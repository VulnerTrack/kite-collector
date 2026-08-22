#!/usr/bin/env bash
# Build the PLAIN kite-collector Debian package for local testing and the
# container e2e battery (tests/e2e/deb-collector). The release deb is
# goreleaser-owned (.goreleaser.yaml nfpms block); this renders the
# mirrored packaging/deb/nfpm-collector.yaml — run.sh guards the two
# against drift before calling this.
#
#   ./scripts/build-deb-collector.sh            # version 0.0.0-dev
#   ./scripts/build-deb-collector.sh 1.2.3
#
# Expects go on PATH (nfpm is `go run` with a pinned version unless already
# installed). Reuses a prebuilt linux/amd64 binary from dist/ or bin/ when
# present, else builds one.
#
# Output: dist/kite-collector_<version>_amd64.deb
set -euo pipefail

VERSION="${1:-0.0.0-dev}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Same pin as build-deb-osquery.sh — bump both together.
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

# ── collector binary ─────────────────────────────────────────────────────
STAGING="$WORK_DIR/staging"
mkdir -p "$STAGING" "$OUT_DIR"

BIN=""
for candidate in \
  "$REPO_ROOT/dist/kite-collector_linux_amd64_v1/kite-collector" \
  "$REPO_ROOT/bin/kite-collector_linux_amd64"; do
  [[ -x "$candidate" ]] && BIN="$candidate" && break
done
if [[ -z "$BIN" ]]; then
  echo "  no prebuilt linux/amd64 binary — building"
  (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o "$STAGING/kite-collector" ./cmd/kite-collector)
else
  cp "$BIN" "$STAGING/kite-collector"
fi

# ── render nfpm config (same sed templating as build-deb-osquery.sh) ─────
sed -e "s|{{ .Version }}|$VERSION|g" \
    -e "s|{{ .Arch }}|amd64|g" \
    -e "s|{{ .Staging }}|$STAGING|g" \
  "$REPO_ROOT/packaging/deb/nfpm-collector.yaml" > "$WORK_DIR/nfpm.yaml"

(cd "$REPO_ROOT" && run_nfpm package -f "$WORK_DIR/nfpm.yaml" -p deb -t "$OUT_DIR")

DEB="$OUT_DIR/kite-collector_${VERSION}_amd64.deb"
[[ -f "$DEB" ]] || DEB=$(ls -t "$OUT_DIR"/kite-collector_*_amd64.deb | head -1)
echo "  built: $DEB"
