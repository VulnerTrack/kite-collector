#!/usr/bin/env bash
# Orchestrates the end-to-end kite container + settings smoke test:
#   1. start the fixture containers,
#   2. build + run the kite binary against them (smoke.sh),
#   3. propagate the runner's exit code, then tear everything down.
#
# Usage: ./run.sh    (resolves its own dir). Requires docker + the compose plugin.
set -euo pipefail

cd "$(dirname "$0")"

# Use the classic build backend. Compose's bake backend mis-joins a
# context-relative dockerfile path when the context is a parent directory
# (our context is the repo root, three levels up), producing a bogus
# "tests/tests" path. The classic builder resolves it correctly.
export COMPOSE_BAKE=false

COMPOSE=(docker compose -f docker-compose.kite.yml -p kite-containers-e2e)
FIXTURES=(smoke-web smoke-privileged)

cleanup() {
  echo "==> tearing down"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting fixture containers"
"${COMPOSE[@]}" up -d "${FIXTURES[@]}"

echo "==> building + running kite smoke test"
"${COMPOSE[@]}" run --rm --build kite
