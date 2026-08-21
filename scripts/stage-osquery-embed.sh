#!/usr/bin/env bash
# Stage the checksum-verified osqueryd payload into the go:embed tree the
# self-contained Windows installer compiles into itself (RFC-0156 R1/R4).
#
# This is the third consumer of the shared scripts/osquery-pin.env, alongside
# build-msi.sh and build-deb-osquery.sh. It reuses their proven
# download-once/verify-every-run/fail-closed pattern rather than inventing a
# second one: a poisoned cache deletes itself and exits non-zero, so no
# unverified byte ever reaches `go build`.
#
# Used by:
#   - .goreleaser.yaml   builds.kite-collector-osquery.hooks.pre
#   - Local developers:  bash scripts/stage-osquery-embed.sh
#                        go build -tags osquery_bundle ...
#
# Output (all gitignored — ~55 MB of build product, never committed):
#   internal/installer/osquerypayload/payload/manifest.json
#   internal/installer/osquerypayload/payload/osquery/osqueryd/osqueryd.exe
#   internal/installer/osquerypayload/payload/osquery/certs/certs.pem
#   internal/installer/osquerypayload/payload/osquery/osquery.{conf,flags}
#   internal/installer/osquerypayload/payload/osquery/packs/*.conf
#
# The on-disk layout deliberately mirrors what the MSI lays down under
# "<install dir>\osquery\", so the installed tree is byte-identical between the
# MSI channel and this one and upstream osquery docs still map (RFC-0156 R7's
# in-place-upgrade story depends on the two channels agreeing on layout).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/osquery-pin.env
. "$REPO_ROOT/scripts/osquery-pin.env"

read -r -a OSQUERY_PACKS <<< "$OSQUERY_WINDOWS_PACKS"

EMBED_ROOT="$REPO_ROOT/internal/installer/osquerypayload/payload"
STAGE_DIR="$EMBED_ROOT/osquery"
CACHE_DIR="$REPO_ROOT/dist/cache"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

for tool in msiextract sha256sum curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not on PATH (msiextract ships in msitools)" >&2
    exit 1
  fi
done

# Download the official osquery MSI once into dist/cache/ — shared with
# build-msi.sh, which uses the identical filename, so a release job that builds
# both the MSI and the exe downloads the payload exactly once. Verify the
# pinned SHA256 on EVERY run: a poisoned cache must fail the build, not ship.
mkdir -p "$CACHE_DIR"
OSQUERY_MSI="$CACHE_DIR/osquery-${OSQUERY_VERSION}.msi"
if [[ ! -f "$OSQUERY_MSI" ]]; then
  echo "  downloading osquery ${OSQUERY_VERSION} MSI"
  curl -fsSL --retry 3 -o "$OSQUERY_MSI.part" "$OSQUERY_MSI_URL"
  mv "$OSQUERY_MSI.part" "$OSQUERY_MSI"
fi

# vendored_sha256 is recomputed here, at embed time, and compared to the pinned
# upstream_sha256. Equality is the checksum-integrity axiom of RFC-0156 Section
# 4.2 and is re-asserted downstream by the DBOS ingest workflow — this is the
# build-time half of that defense in depth.
VENDORED_SHA256="$(sha256sum "$OSQUERY_MSI" | cut -d' ' -f1)"
if [[ "$VENDORED_SHA256" != "$OSQUERY_MSI_SHA256" ]]; then
  echo "error: osquery MSI failed SHA256 verification — deleting cached copy" >&2
  echo "  expected ${OSQUERY_MSI_SHA256}" >&2
  echo "  actual   ${VENDORED_SHA256}" >&2
  rm -f "$OSQUERY_MSI"
  exit 1
fi
echo "  osquery MSI verified: $OSQUERY_MSI"

# Harvest the payload. msiextract reproduces the official install layout
# (osquery/osqueryd/osqueryd.exe, osquery/certs/certs.pem, osquery/packs/*).
EXTRACT_DIR="$WORK_DIR/osquery-extract"
mkdir -p "$EXTRACT_DIR"
msiextract -C "$EXTRACT_DIR" "$OSQUERY_MSI" >/dev/null
SRC="$EXTRACT_DIR/osquery"
if [[ ! -f "$SRC/osqueryd/osqueryd.exe" ]]; then
  echo "error: osqueryd.exe not at expected path in the osquery MSI payload" >&2
  echo "  (upstream layout changed? inspect $EXTRACT_DIR)" >&2
  exit 1
fi

# Restage from scratch so a pin bump can never leave a stale binary behind for
# go:embed to pick up alongside the new manifest.
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/osqueryd" "$STAGE_DIR/certs" "$STAGE_DIR/packs"
cp "$SRC/osqueryd/osqueryd.exe" "$STAGE_DIR/osqueryd/osqueryd.exe"
cp "$SRC/certs/certs.pem" "$STAGE_DIR/certs/certs.pem"
for pack in "${OSQUERY_PACKS[@]}"; do
  cp "$SRC/packs/${pack}.conf" "$STAGE_DIR/packs/${pack}.conf"
done
cp "$REPO_ROOT/configs/osquery/osquery.conf" "$STAGE_DIR/osquery.conf"
cp "$REPO_ROOT/configs/osquery/osquery.flags" "$STAGE_DIR/osquery.flags"

# Per-file digests. The installer re-verifies every extracted file against
# these before it registers or starts anything, which is the
# extracting -> services_registering transition of RFC-0156 Section 4.2's
# InstallationRun state machine: an AV-mangled or truncated write is caught
# before osqueryd.exe can run as LocalSystem.
manifest_files() {
  (cd "$EMBED_ROOT" && find osquery -type f | LC_ALL=C sort) | while IFS= read -r rel
  do
    sha="$(sha256sum "$EMBED_ROOT/$rel" | cut -d' ' -f1)"
    size="$(wc -c < "$EMBED_ROOT/$rel" | tr -d ' ')"
    printf '    {"path": "%s", "sha256": "%s", "size": %s}\n' "$rel" "$sha" "$size"
  done | sed '$!s/$/,/'
}

cat > "$EMBED_ROOT/manifest.json" <<EOF
{
  "schema_version": 1,
  "natural_key": "bundled:osqueryd:${OSQUERY_VERSION}:self_contained_exe",
  "component_name": "osqueryd",
  "component_version": "${OSQUERY_VERSION}",
  "upstream_sha256": "${OSQUERY_MSI_SHA256}",
  "vendored_sha256": "${VENDORED_SHA256}",
  "source_url": "${OSQUERY_MSI_URL}",
  "license_id": "${OSQUERY_LICENSE_ID}",
  "cpe23": "${OSQUERY_CPE23}",
  "artifact_format": "self_contained_exe",
  "files": [
$(manifest_files)
  ]
}
EOF

echo "  osquery payload staged for go:embed: $EMBED_ROOT"
du -sh "$STAGE_DIR" | sed 's/^/  /'

# The Go side refuses to install unless this same digest was baked in at link
# time (RFC-0156 Section 4.2, defense in depth): a refactor that quietly drops
# the staging step cannot produce an installer that silently ships whatever
# happens to be on disk. Print the exact flag so a local bundle build is a
# copy-paste away.
LDFLAGS_PIN="-X github.com/vulnertrack/kite-collector/internal/installer.vendoredOsquerySHA256=${VENDORED_SHA256}"
mkdir -p "$REPO_ROOT/dist"
printf '%s\n' "$LDFLAGS_PIN" > "$REPO_ROOT/dist/osquery-embed-ldflags.txt"
echo "  link with: go build -tags osquery_bundle -ldflags \"${LDFLAGS_PIN}\" ./cmd/kite-collector"
