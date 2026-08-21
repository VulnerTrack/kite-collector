#!/usr/bin/env bash
# Build the kite-collector-osquery Debian package — the Linux analogue of
# `scripts/build-msi.sh --with-osquery`: collector + a namespaced osqueryd
# (kite-osqueryd.service) in one artifact, payload harvested from the
# official osquery deb (pinned version + SHA256 below).
#
# Used by:
#   - .github/workflows/kite-collector.yml (release job, after goreleaser;
#     the deb lands in dist/ so the dynamic APT repo step sweeps it up)
#   - tests/e2e/deb-osquery/run.sh (container install/run battery)
#   - Local developers: ./scripts/build-deb-osquery.sh 0.0.0-dev
#
# Inputs:
#   $1  version  e.g. "1.2.3" (defaults to "0.0.0-dev")
#
# Expects:
#   - go on PATH (nfpm is `go run` with a pinned version unless already
#     installed), curl, and dpkg-deb OR bsdtar for payload extraction
#   - a linux/amd64 collector binary at one of:
#       dist/kite-collector_linux_amd64_v1/kite-collector   (goreleaser)
#       bin/kite-collector_linux_amd64                      (make build)
#
# Output:
#   dist/kite-collector-osquery_<version>_amd64.deb

set -euo pipefail

VERSION="${1:-0.0.0-dev}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# osquery payload pin. OSQUERY_VERSION, OSQUERY_DEB_SHA256, OSQUERY_DEB_URL
# and OSQUERY_LINUX_PACKS live in the shared scripts/osquery-pin.env, which
# build-msi.sh and stage-osquery-embed.sh source too, so the Windows and Linux
# bundles can never drift onto different upstream releases (RFC-0156 Phase 1).
# Bump the pin file, never a copy here.
# shellcheck source=scripts/osquery-pin.env
. "$REPO_ROOT/scripts/osquery-pin.env"

# Space-separated in the pin file (it has to stay POSIX-sh sourceable and
# $GITHUB_ENV-exportable); split back into the array the staging loop wants.
read -r -a OSQUERY_PACKS <<< "$OSQUERY_LINUX_PACKS"

# nfpm pin — bump deliberately, it's the packager, not a runtime dep. Stays
# here rather than in osquery-pin.env: it is a build tool, not part of the
# redistributed osquery payload whose checksum the pin file governs.
NFPM_VERSION="v2.47.0"

OUT_DIR="$REPO_ROOT/dist"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

run_nfpm() {
  # type -P looks up binaries only — `command -v` would find this function.
  if type -P nfpm >/dev/null 2>&1; then
    nfpm "$@"
  else
    go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" "$@"
  fi
}

# Locate the linux binary. Two layouts, mirroring build-msi.sh:
BIN_CANDIDATES=(
  "$REPO_ROOT/dist/kite-collector_linux_amd64_v1/kite-collector"
  "$REPO_ROOT/dist/kite-collector_linux_amd64/kite-collector"
  "$REPO_ROOT/bin/kite-collector_linux_amd64"
)
BIN=""
for candidate in "${BIN_CANDIDATES[@]}"; do
  if [[ -f "$candidate" ]]; then
    BIN="$candidate"
    break
  fi
done
if [[ -z "$BIN" ]]; then
  echo "error: could not find a linux/amd64 kite-collector binary in any of:" >&2
  printf '  %s\n' "${BIN_CANDIDATES[@]}" >&2
  echo "  Run goreleaser or 'make build' first." >&2
  exit 1
fi
echo "  using binary: $BIN"

# Download the official osquery deb once into dist/cache/, but verify the
# pinned SHA256 on EVERY run — a poisoned cache must fail the build, not
# ship. Download to a temp name so an interrupted curl never poisons the
# cache with a truncated file.
CACHE_DIR="$OUT_DIR/cache"
mkdir -p "$CACHE_DIR"
OSQUERY_DEB="$CACHE_DIR/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"
if [[ ! -f "$OSQUERY_DEB" ]]; then
  echo "  downloading osquery ${OSQUERY_VERSION} deb"
  curl -fsSL --retry 3 -o "$OSQUERY_DEB.part" "$OSQUERY_DEB_URL"
  mv "$OSQUERY_DEB.part" "$OSQUERY_DEB"
fi
echo "${OSQUERY_DEB_SHA256}  ${OSQUERY_DEB}" | sha256sum -c - >/dev/null || {
  echo "error: osquery deb failed SHA256 verification — deleting cached copy" >&2
  rm -f "$OSQUERY_DEB"
  exit 1
}
echo "  osquery deb verified: $OSQUERY_DEB"

# Harvest the payload. dpkg-deb where available (Debian-family CI), bsdtar
# otherwise (libarchive reads the ar container and the inner tarball).
EXTRACT_DIR="$WORK_DIR/osquery-extract"
mkdir -p "$EXTRACT_DIR"
if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb -x "$OSQUERY_DEB" "$EXTRACT_DIR"
elif command -v bsdtar >/dev/null 2>&1; then
  bsdtar -xf "$OSQUERY_DEB" -C "$WORK_DIR" 'data.tar.*'
  bsdtar -xf "$WORK_DIR"/data.tar.* -C "$EXTRACT_DIR"
else
  echo "error: need dpkg-deb or bsdtar to extract the osquery deb payload" >&2
  exit 1
fi
SRC="$EXTRACT_DIR/opt/osquery"
if [[ ! -f "$SRC/bin/osqueryd" ]]; then
  echo "error: osqueryd not at expected path in the osquery deb payload" >&2
  echo "  (upstream layout changed? inspect $EXTRACT_DIR)" >&2
  exit 1
fi

# Stage what packaging/deb/nfpm-osquery.yaml references.
STAGING="$WORK_DIR/staging"
mkdir -p "$STAGING/osquery/certs" "$STAGING/osquery/packs" "$STAGING/osquery/lenses"
cp "$BIN" "$STAGING/kite-collector"
cp "$SRC/bin/osqueryd" "$STAGING/osquery/osqueryd"
cp "$SRC/share/osquery/certs/certs.pem" "$STAGING/osquery/certs/certs.pem"
for pack in "${OSQUERY_PACKS[@]}"; do
  cp "$SRC/share/osquery/packs/${pack}.conf" "$STAGING/osquery/packs/${pack}.conf"
done
cp "$SRC"/share/osquery/lenses/*.aug "$STAGING/osquery/lenses/"
echo "  osquery payload staged"

mkdir -p "$OUT_DIR"
OUT_DEB="$OUT_DIR/kite-collector-osquery_${VERSION}_amd64.deb"

# Render the nfpm config with the same sed templating build-msi.sh applies
# to wix.wxs — nfpm does not expand variables in content paths itself.
sed \
  -e "s|{{ \.Version }}|${VERSION}|g" \
  -e "s|{{ \.Arch }}|amd64|g" \
  -e "s|{{ \.Staging }}|${STAGING}|g" \
  "$REPO_ROOT/packaging/deb/nfpm-osquery.yaml" > "$WORK_DIR/nfpm-osquery.yaml"

echo "  building: $OUT_DEB"
( cd "$REPO_ROOT" && run_nfpm package -f "$WORK_DIR/nfpm-osquery.yaml" -p deb -t "$OUT_DEB" )

ls -lh "$OUT_DEB"
echo "  done."
