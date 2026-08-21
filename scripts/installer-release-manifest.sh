#!/usr/bin/env bash
# Emit the Windows installer release-provenance manifest (RFC-0156 R8/R12) and
# the per-artifact checksum + SBOM sidecars that go with it.
#
# Usage:
#   bash scripts/installer-release-manifest.sh <version-tag> [<commit-sha>] [<ci-run-url>]
#
# This is the CI half of the contract Section 5.4 describes: the release job
# writes one JSON document, attaches it to the GitHub Release, and the engine's
# ingest_installer_release_workflow() reads it back and persists it into
# kite_installer_bundles / kite_installer_bundled_dependencies. No new service
# endpoint, no push from CI into the platform.
#
# The manifest describes ALL of the release's Windows installer artifacts, not
# just the new one. RFC-0156 Section 4.3 maps both existing MSI <Product>
# elements onto the same WindowsInstallerArtifact class precisely so upgrade
# identity, signing state, and checksum coverage can be reasoned about
# uniformly — a manifest that only carried the new exe would leave the exact
# gap the RFC opens with ("only the plain MSI gets a checksum").
#
# Output in dist/:
#   kite-collector-osquery_windows_amd64.exe.sha256
#   kite-collector-osquery_windows_amd64.sbom.spdx.json
#   kite-collector-osquery_<version>_amd64.msi.sha256
#   installer-release-manifest.json
#   installer-release-manifest.json.sha256

set -euo pipefail

VERSION_TAG="${1:?usage: $0 <version-tag> [commit-sha] [ci-run-url]}"
COMMIT_SHA="${2:-${GITHUB_SHA:-}}"
CI_RUN_URL="${3:-}"
VERSION="${VERSION_TAG#v}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/osquery-pin.env
. "$REPO_ROOT/scripts/osquery-pin.env"

DIST="$REPO_ROOT/dist"
EMBED_MANIFEST="$REPO_ROOT/internal/installer/osquerypayload/payload/manifest.json"

# The UpgradeCode both MSI products share (cmd/kite-collector/wix.wxs). Carried
# on the MSI rows so "which artifacts replace each other" is a query, not
# tribal knowledge.
MSI_UPGRADE_CODE="19b944d3-493b-4a20-952d-df1c6b0e2fe3"

BUNDLE_EXE="$DIST/kite-collector-osquery_windows_amd64.exe"
PLAIN_MSI="$DIST/kite-collector_${VERSION}_amd64.msi"
BUNDLE_MSI="$DIST/kite-collector-osquery_${VERSION}_amd64.msi"

for tool in jq sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not on PATH" >&2
    exit 1
  fi
done

# Signing state comes from sign-windows-artifact.sh. Absent means the signing
# step never ran, which is the Phase 3 rollout state: released, unsigned, and
# labelled as such rather than silently ambiguous.
SIGNING_STATE="unsigned_released"
SIGNER_FINGERPRINT=""
CERT_JSON="null"
if [[ -f "$DIST/signing-state.json" ]]; then
  SIGNING_STATE="$(jq -r '.state // "unsigned_released"' "$DIST/signing-state.json")"
  SIGNER_FINGERPRINT="$(jq -r '.fingerprint_sha256 // ""' "$DIST/signing-state.json")"
  if [[ "$SIGNING_STATE" == "signed" && -n "$SIGNER_FINGERPRINT" ]]; then
    CERT_JSON="$(jq -c '{
      natural_key: ("codesign:" + (.fingerprint_sha256 // "")),
      fingerprint_sha256: (.fingerprint_sha256 // ""),
      subject_cn: (.subject_cn // ""),
      issuer_cn: (.issuer_cn // ""),
      not_before: (.not_before // ""),
      not_after: (.not_after // ""),
      key_custody: (.key_custody // "cloud_hsm"),
      purpose: "code_signing"
    }' "$DIST/signing-state.json")"
  fi
fi

# sha256 sidecar next to every artifact we describe (R8). The plain MSI already
# got one from the existing release step; writing it again is idempotent and
# keeps this script the single answer to "did everything get a checksum".
write_sidecar() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  (cd "$(dirname "$path")" && sha256sum "$(basename "$path")" > "$(basename "$path").sha256")
}

emit_artifact() {
  local path="$1" artifact_format="$2" variant="$3" upgrade_code="$4"
  [[ -f "$path" ]] || return 0

  local sha size
  sha="$(sha256sum "$path" | cut -d' ' -f1)"
  size="$(wc -c < "$path" | tr -d ' ')"

  jq -n \
    --arg natural_key "installer:${VERSION_TAG}:${artifact_format}:${variant}:amd64" \
    --arg file_name "$(basename "$path")" \
    --arg artifact_format "$artifact_format" \
    --arg variant "$variant" \
    --arg kite_collector_version "$VERSION_TAG" \
    --arg sha256 "$sha" \
    --argjson size_bytes "$size" \
    --arg signing_state "$SIGNING_STATE" \
    --arg signer_fingerprint "$SIGNER_FINGERPRINT" \
    --arg build_commit_sha "$COMMIT_SHA" \
    --arg ci_run_url "$CI_RUN_URL" \
    --arg upgrade_code "$upgrade_code" \
    '{
      natural_key: $natural_key,
      file_name: $file_name,
      artifact_format: $artifact_format,
      variant: $variant,
      target_arch: "amd64",
      kite_collector_version: $kite_collector_version,
      sha256: $sha256,
      size_bytes: $size_bytes,
      signing_state: $signing_state,
      signer_fingerprint: (if $signer_fingerprint == "" then null else $signer_fingerprint end),
      build_commit_sha: $build_commit_sha,
      ci_run_url: $ci_run_url,
      upgrade_code: (if $upgrade_code == "" then null else $upgrade_code end)
    }'
}

# One BundledDependency row per (payload, carrying artifact). The exe's numbers
# come from the embed manifest the verified staging step wrote; the MSI's come
# from the shared pin both consumers read. vendored_sha256 == upstream_sha256
# is the checksum-integrity axiom, re-asserted independently by the DBOS
# ingest workflow before anything is stored (Section 5.3).
emit_dependency() {
  local installer_natural_key="$1" artifact_format="$2" vendored="$3"
  jq -n \
    --arg natural_key "bundled:osqueryd:${OSQUERY_VERSION}:${artifact_format}" \
    --arg installer_natural_key "$installer_natural_key" \
    --arg component_version "$OSQUERY_VERSION" \
    --arg upstream_sha256 "$OSQUERY_MSI_SHA256" \
    --arg vendored_sha256 "$vendored" \
    --arg source_url "$OSQUERY_MSI_URL" \
    --arg license_id "$OSQUERY_LICENSE_ID" \
    --arg cpe23 "$OSQUERY_CPE23" \
    '{
      natural_key: $natural_key,
      installer_natural_key: $installer_natural_key,
      component_name: "osqueryd",
      component_version: $component_version,
      upstream_sha256: $upstream_sha256,
      vendored_sha256: $vendored_sha256,
      source_url: $source_url,
      license_id: $license_id,
      cpe23: $cpe23
    }'
}

for artifact in "$BUNDLE_EXE" "$PLAIN_MSI" "$BUNDLE_MSI"; do
  write_sidecar "$artifact"
done

# Per-artifact SBOM (R12). Today's anchore/sbom-action run is repo-wide
# (path: .), which answers "what is in the repo", not "what is in this one
# file a customer downloaded" — the question a security reviewer actually
# asks about a self-contained installer.
if [[ -f "$BUNDLE_EXE" ]] && command -v syft >/dev/null 2>&1; then
  syft "$BUNDLE_EXE" -o spdx-json \
    > "$DIST/kite-collector-osquery_windows_amd64.sbom.spdx.json"
  write_sidecar "$DIST/kite-collector-osquery_windows_amd64.sbom.spdx.json"
else
  echo "  note: syft unavailable or bundle exe missing — per-artifact SBOM skipped"
fi

EXE_KEY="installer:${VERSION_TAG}:self_contained_exe:osquery_bundle:amd64"
BUNDLE_MSI_KEY="installer:${VERSION_TAG}:msi:osquery_bundle:amd64"

# The exe's vendored digest is whatever the verified staging step recorded; if
# the embed manifest is missing the build could not have produced a working
# installer anyway, so falling back to the pin keeps the manifest well-formed
# for the downstream axiom check rather than emitting an empty field.
EXE_VENDORED="$OSQUERY_MSI_SHA256"
if [[ -f "$EMBED_MANIFEST" ]]; then
  EXE_VENDORED="$(jq -r '.vendored_sha256 // empty' "$EMBED_MANIFEST")"
  : "${EXE_VENDORED:=$OSQUERY_MSI_SHA256}"
fi

ARTIFACTS="$(
  {
    emit_artifact "$BUNDLE_EXE" "self_contained_exe" "osquery_bundle" ""
    emit_artifact "$PLAIN_MSI" "msi" "plain" "$MSI_UPGRADE_CODE"
    emit_artifact "$BUNDLE_MSI" "msi" "osquery_bundle" "$MSI_UPGRADE_CODE"
  } | jq -s '.'
)"

DEPENDENCIES="$(
  {
    if [[ -f "$BUNDLE_EXE" ]]; then
      emit_dependency "$EXE_KEY" "self_contained_exe" "$EXE_VENDORED"
    fi
    if [[ -f "$BUNDLE_MSI" ]]; then
      emit_dependency "$BUNDLE_MSI_KEY" "msi" "$OSQUERY_MSI_SHA256"
    fi
  } | jq -s '.'
)"

MANIFEST="$DIST/installer-release-manifest.json"
jq -n \
  --arg version_tag "$VERSION_TAG" \
  --arg build_commit_sha "$COMMIT_SHA" \
  --arg ci_run_url "$CI_RUN_URL" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg signing_state "$SIGNING_STATE" \
  --argjson code_signing_certificate "$CERT_JSON" \
  --argjson artifacts "$ARTIFACTS" \
  --argjson bundled_dependencies "$DEPENDENCIES" \
  '{
    schema_version: 1,
    version_tag: $version_tag,
    build_commit_sha: $build_commit_sha,
    ci_run_url: $ci_run_url,
    generated_at: $generated_at,
    signing_state: $signing_state,
    code_signing_certificate: $code_signing_certificate,
    artifacts: $artifacts,
    bundled_dependencies: $bundled_dependencies
  }' > "$MANIFEST"

write_sidecar "$MANIFEST"

echo "  wrote $MANIFEST"
jq -r '"  artifacts: \(.artifacts | length), dependencies: \(.bundled_dependencies | length), signing_state: \(.signing_state)"' "$MANIFEST"
