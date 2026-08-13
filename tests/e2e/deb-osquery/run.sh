#!/usr/bin/env bash
# Install/run battery for the kite-collector-osquery deb inside a stock
# debian container — proves the package installs, the bundled kite-osqueryd
# actually serves queries, and the plain<->bundle cross-grade works, all
# without systemd as PID 1 (the maintainer scripts must tolerate that).
#
#   ./tests/e2e/deb-osquery/run.sh            # builds the deb if missing
#   DEB=dist/kite-collector-osquery_1.2.3_amd64.deb ./tests/e2e/deb-osquery/run.sh
#
# `make test-deb-osquery` wraps this. Requires docker.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${IMAGE:-debian:12}"

DEB="${DEB:-}"
if [[ -z "$DEB" ]]; then
  DEB=$(ls "$REPO_ROOT"/dist/kite-collector-osquery_*_amd64.deb 2>/dev/null | head -1 || true)
fi
if [[ -z "$DEB" ]]; then
  echo "  no bundle deb in dist/ — building one"
  "$REPO_ROOT/scripts/build-deb-osquery.sh"
  DEB=$(ls "$REPO_ROOT"/dist/kite-collector-osquery_*_amd64.deb | head -1)
fi
echo "  testing: $DEB (in $IMAGE)"

docker run --rm \
  -v "$(dirname "$(readlink -f "$DEB")"):/pkg:ro" \
  -v "$REPO_ROOT/tests/e2e/deb-osquery/battery.sh:/battery.sh:ro" \
  "$IMAGE" bash /battery.sh
