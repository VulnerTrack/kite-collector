#!/usr/bin/env bash
# Install/upgrade-bridge battery for the PLAIN kite-collector deb inside a
# stock debian container — proves the package installs its unit, the
# binary lands at /usr/bin, and the /usr/local/bin→/usr/bin upgrade bridge
# behaves, all without systemd as PID 1.
#
#   ./tests/e2e/deb-collector/run.sh            # builds the deb if missing
#   DEB=dist/kite-collector_1.2.3_amd64.deb ./tests/e2e/deb-collector/run.sh
#
# `make test-deb-collector` wraps this. Requires docker.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${IMAGE:-debian:12}"

# ── drift guard ──────────────────────────────────────────────────────────
# The release deb is goreleaser-owned; the battery builds from the mirrored
# packaging/deb/nfpm-collector.yaml. Assert the load-bearing lines exist in
# BOTH configs so the battery can't silently test a different layout than
# the one that ships.
GR="$REPO_ROOT/.goreleaser.yaml"
NF="$REPO_ROOT/packaging/deb/nfpm-collector.yaml"
for needle in \
  "bindir: /usr/bin" \
  "/usr/lib/systemd/system/kite-collector.service" \
  "packaging/systemd/kite-collector.service" \
  "packaging/deb/collector-postinstall.sh" \
  "packaging/deb/collector-postremove.sh"; do
  grep -qF "$needle" "$GR" || { echo "DRIFT: '$needle' missing from .goreleaser.yaml"; exit 1; }
done
for needle in \
  "dst: /usr/bin/kite-collector" \
  "dst: /usr/lib/systemd/system/kite-collector.service" \
  "src: packaging/systemd/kite-collector.service" \
  "postinstall: packaging/deb/collector-postinstall.sh" \
  "postremove: packaging/deb/collector-postremove.sh"; do
  grep -qF "$needle" "$NF" || { echo "DRIFT: '$needle' missing from nfpm-collector.yaml"; exit 1; }
done
echo "  drift guard: goreleaser and nfpm-collector configs agree"

DEB="${DEB:-}"
if [[ -z "$DEB" ]]; then
  DEB=$(ls "$REPO_ROOT"/dist/kite-collector_*_amd64.deb 2>/dev/null | grep -v osquery | head -1 || true)
fi
if [[ -z "$DEB" ]]; then
  echo "  no collector deb in dist/ — building one"
  "$REPO_ROOT/scripts/build-deb-collector.sh"
  DEB=$(ls "$REPO_ROOT"/dist/kite-collector_*_amd64.deb | grep -v osquery | head -1)
fi
echo "  testing: $DEB (in $IMAGE)"

docker run --rm \
  -v "$(dirname "$(readlink -f "$DEB")"):/pkg:ro" \
  -v "$REPO_ROOT/tests/e2e/deb-collector/battery.sh:/battery.sh:ro" \
  "$IMAGE" bash /battery.sh
