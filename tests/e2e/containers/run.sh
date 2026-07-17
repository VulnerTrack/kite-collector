#!/usr/bin/env bash
# Orchestrates the container-discovery smoke test:
#   1. start the fixture containers (known, deterministic properties),
#   2. run the collector-under-test in the runner container,
#   3. propagate the runner's exit code, then tear everything down.
#
# Usage: ./run.sh            (from anywhere; resolves its own dir)
# Requires: docker + the compose plugin (`docker compose`).
set -euo pipefail

cd "$(dirname "$0")"

PROJECT="kite-containers-smoke"
COMPOSE=(docker compose -f docker-compose.smoke.yml -p "$PROJECT")

FIXTURES=(smoke-web smoke-privileged smoke-hostnet smoke-nonroot smoke-exited)

cleanup() {
  echo "==> tearing down smoke fixtures"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting fixture containers"
"${COMPOSE[@]}" up -d "${FIXTURES[@]}"

echo "==> running collector smoke test"
# `run --rm` returns the runner's exit code directly, so a failed assertion
# fails this script (and CI) with a non-zero status.
"${COMPOSE[@]}" run --rm runner
