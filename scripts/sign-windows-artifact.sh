#!/usr/bin/env bash
# Authenticode-sign Windows release artifacts (RFC-0156 R9), resolving
# RFC-0059's Open Question 1.
#
# Usage:
#   bash scripts/sign-windows-artifact.sh <file> [<file> ...]
#
# Backend: SignPath.io. Its free open-source tier is the primary
# recommendation (Section 11.3) specifically because of how the key is held —
# the CA/Browser Forum Code Signing Baseline Requirements have banned
# software-held OV keys since June 2023, so a plaintext PFX in a GitHub Actions
# secret is not an option any public CA will honor. SignPath keeps the key in
# its HSM and the runner only ever holds a short-lived, scoped API token, which
# means no credential capable of signing offline ever exists in this pipeline
# (Section 6.3).
#
# Required to actually sign (all as repository secrets/variables):
#   SIGNPATH_API_TOKEN                     secret
#   SIGNPATH_ORGANIZATION_ID               secret
#   SIGNPATH_PROJECT_SLUG                  variable
#   SIGNPATH_SIGNING_POLICY_SLUG           variable
#   SIGNPATH_ARTIFACT_CONFIGURATION_SLUG   variable  (optional)
#
# Certificate metadata, recorded once when the certificate is provisioned
# rather than reverse-engineered out of every build:
#   KITE_CODESIGN_FINGERPRINT_SHA256, KITE_CODESIGN_SUBJECT_CN,
#   KITE_CODESIGN_ISSUER_CN, KITE_CODESIGN_NOT_BEFORE, KITE_CODESIGN_NOT_AFTER,
#   KITE_CODESIGN_KEY_CUSTODY   (cloud_hsm | hardware_token)
#
# GRACEFUL DEGRADATION IS THE POINT. With no token configured this script
# writes dist/signing-state.json with state=unsigned_released and exits 0.
# RFC-0156 Section 8.1 is explicit that a security fix must never be blocked
# behind a third-party signing outage — an unsigned release that says so, in a
# queryable field, beats no release at all. Section 10 Phase 3 ships exactly
# this way on purpose, and Phase 4 flips the same pipeline to signed by adding
# the secrets.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <file> [<file> ...]" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/dist"
STATE_FILE="$OUT_DIR/signing-state.json"
mkdir -p "$OUT_DIR"

SIGNPATH_API_TOKEN="${SIGNPATH_API_TOKEN:-}"
SIGNPATH_ORGANIZATION_ID="${SIGNPATH_ORGANIZATION_ID:-}"
SIGNPATH_PROJECT_SLUG="${SIGNPATH_PROJECT_SLUG:-}"
SIGNPATH_SIGNING_POLICY_SLUG="${SIGNPATH_SIGNING_POLICY_SLUG:-}"
SIGNPATH_ARTIFACT_CONFIGURATION_SLUG="${SIGNPATH_ARTIFACT_CONFIGURATION_SLUG:-}"
SIGNPATH_API_BASE="${SIGNPATH_API_BASE:-https://app.signpath.io/API/v1}"

# How long to wait for the signing service. Bounded so a hung request degrades
# to unsigned_released instead of holding the release job to its 20-minute cap.
SIGN_POLL_INTERVAL_S="${SIGN_POLL_INTERVAL_S:-15}"
SIGN_POLL_MAX_ATTEMPTS="${SIGN_POLL_MAX_ATTEMPTS:-40}"

write_state() {
  local state="$1" detail="$2"
  cat > "$STATE_FILE" <<EOF
{
  "state": "${state}",
  "detail": "${detail}",
  "fingerprint_sha256": "${KITE_CODESIGN_FINGERPRINT_SHA256:-}",
  "subject_cn": "${KITE_CODESIGN_SUBJECT_CN:-}",
  "issuer_cn": "${KITE_CODESIGN_ISSUER_CN:-}",
  "not_before": "${KITE_CODESIGN_NOT_BEFORE:-}",
  "not_after": "${KITE_CODESIGN_NOT_AFTER:-}",
  "key_custody": "${KITE_CODESIGN_KEY_CUSTODY:-cloud_hsm}"
}
EOF
  echo "  signing state: ${state} (${detail})"
  echo "  wrote $STATE_FILE"
}

if [[ -z "$SIGNPATH_API_TOKEN" || -z "$SIGNPATH_ORGANIZATION_ID" ||
      -z "$SIGNPATH_PROJECT_SLUG" || -z "$SIGNPATH_SIGNING_POLICY_SLUG" ]]; then
  write_state "unsigned_released" \
    "no signing credentials configured; release proceeds unsigned and labelled"
  exit 0
fi

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    write_state "unsigned_released" "$tool not on PATH"
    exit 0
  fi
done

sign_one() {
  local artifact="$1"
  local name
  name="$(basename "$artifact")"
  echo "  submitting $name to SignPath"

  local submit_args=(
    -sS -f -X POST
    -H "Authorization: Bearer ${SIGNPATH_API_TOKEN}"
    -F "ProjectSlug=${SIGNPATH_PROJECT_SLUG}"
    -F "SigningPolicySlug=${SIGNPATH_SIGNING_POLICY_SLUG}"
    -F "Artifact=@${artifact}"
    -F "Description=kite-collector release ${GITHUB_REF_NAME:-local} (${name})"
  )
  if [[ -n "$SIGNPATH_ARTIFACT_CONFIGURATION_SLUG" ]]; then
    submit_args+=(-F "ArtifactConfigurationSlug=${SIGNPATH_ARTIFACT_CONFIGURATION_SLUG}")
  fi

  local request_url
  request_url="$(curl "${submit_args[@]}" -D - -o /dev/null \
    "${SIGNPATH_API_BASE}/${SIGNPATH_ORGANIZATION_ID}/SigningRequests" \
    | tr -d '\r' | awk 'tolower($1) == "location:" { print $2 }' | tail -n1)"
  if [[ -z "$request_url" ]]; then
    echo "  error: SignPath did not return a signing-request location" >&2
    return 1
  fi

  local attempt status signed_link
  for ((attempt = 1; attempt <= SIGN_POLL_MAX_ATTEMPTS; attempt++)); do
    local body
    body="$(curl -sS -f -H "Authorization: Bearer ${SIGNPATH_API_TOKEN}" "$request_url")"
    status="$(jq -r '.status // empty' <<< "$body")"
    case "$status" in
      Completed)
        signed_link="$(jq -r '.signedArtifactLink // empty' <<< "$body")"
        if [[ -z "$signed_link" ]]; then
          echo "  error: SignPath reported Completed with no signed artifact" >&2
          return 1
        fi
        # Download beside the original and swap only on success, so a failed
        # download can never leave a truncated "signed" artifact in dist/.
        curl -sS -f -H "Authorization: Bearer ${SIGNPATH_API_TOKEN}" \
          -o "${artifact}.signed" "$signed_link"
        mv "${artifact}.signed" "$artifact"
        echo "  signed: $name"
        return 0
        ;;
      Failed|Denied|Canceled)
        echo "  error: SignPath signing request ended as ${status}" >&2
        return 1
        ;;
      *)
        sleep "$SIGN_POLL_INTERVAL_S"
        ;;
    esac
  done
  echo "  error: SignPath signing request timed out (last status: ${status:-unknown})" >&2
  return 1
}

signed_count=0
for artifact in "$@"; do
  if [[ ! -f "$artifact" ]]; then
    echo "  skipping missing artifact: $artifact"
    continue
  fi
  if ! sign_one "$artifact"; then
    write_state "unsigned_released" "signing failed for $(basename "$artifact")"
    exit 0
  fi
  signed_count=$((signed_count + 1))
done

if [[ "$signed_count" -eq 0 ]]; then
  write_state "unsigned_released" "no artifacts were present to sign"
  exit 0
fi

# Best-effort independent verification that a signature actually landed. Not
# fail-closed on absence of the tool: osslsigncode is not installed on the
# runner by default and its absence must not downgrade a genuinely signed
# release to unsigned.
if command -v osslsigncode >/dev/null 2>&1; then
  for artifact in "$@"; do
    [[ -f "$artifact" ]] || continue
    if ! osslsigncode verify -in "$artifact" >/dev/null 2>&1; then
      write_state "signature_invalid" \
        "osslsigncode could not verify $(basename "$artifact")"
      exit 1
    fi
  done
fi

write_state "signed" "${signed_count} artifact(s) signed via SignPath"
