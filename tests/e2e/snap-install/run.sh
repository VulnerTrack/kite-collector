#!/usr/bin/env bash
# Orchestrates the snap-installation e2e test:
#   1. boot the ubuntu machine (systemd PID 1) with kite-collector staged as a
#      snap install leaves it,
#   2. wait for systemd, run the install scenario on the machine,
#   3. run the test-runner container's assertions over the shared evidence,
#   4. propagate the runner's exit code, then tear everything down.
#
# Usage: ./run.sh    (resolves its own dir). Requires docker + compose plugin.
set -euo pipefail

cd "$(dirname "$0")"

# Classic build backend — the bake backend mis-joins context-relative
# dockerfile paths when the context is a parent directory (repo root).
export COMPOSE_BAKE=false

COMPOSE=(docker compose -f docker-compose.snap.yml -p kite-snap-install-e2e)

cleanup() {
  echo "==> tearing down"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> booting ubuntu machine (systemd)"
"${COMPOSE[@]}" up -d --build ubuntu

echo "==> waiting for systemd to settle"
"${COMPOSE[@]}" exec ubuntu bash -c '
  for _ in $(seq 1 60); do
    state=$(systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) exit 0 ;; esac
    sleep 1
  done
  echo "systemd never settled (last state: ${state:-none})" >&2
  exit 1
'

echo "==> running snap install scenario on the machine"
"${COMPOSE[@]}" exec ubuntu /usr/local/bin/scenario.sh

echo "==> running test-runner assertions"
"${COMPOSE[@]}" run --rm --build test-runner
