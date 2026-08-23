#!/usr/bin/env bash
# Build the collector, boot a throwaway dashboard on loopback, and run the
# offline browser render check against it. Everything is torn down on exit.
#
# The render check itself makes NO internet requests (it aborts every
# non-loopback request and drives the system browser). The only step that can
# need the network is the one-time `npm install` of playwright-core below, and
# only if node_modules is missing — a normal run is fully offline.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"        # apps/kite-collector
cd "$here"

port="${KITE_PORT:-9096}"
tmp="$(mktemp -d)"
bin="$tmp/kite-collector"
log="$tmp/dashboard.log"

cleanup() {
  [ -n "${dash_pid:-}" ] && kill "$dash_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# One-time JS deps. playwright-core does NOT download a browser on install, so
# this stays small; we use the host's own chromium/chrome at run time.
if [ ! -d node_modules ]; then
  echo "==> installing playwright-core (one-time; needs network)…"
  npm install --no-audit --no-fund --loglevel=error
fi

echo "==> building kite-collector…"
( cd "$root" && go build -o "$bin" ./cmd/kite-collector )

echo "==> starting dashboard on 127.0.0.1:$port (inspector, no agent/install)…"
"$bin" dashboard \
  --addr "127.0.0.1:$port" \
  --db "$tmp/kite.db" \
  --certs-dir "$tmp/certs" \
  --with-agent=false \
  --enable-install=false >"$log" 2>&1 &
dash_pid=$!

echo "==> waiting for the port to open…"
for _ in $(seq 1 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; break; fi
  kill -0 "$dash_pid" 2>/dev/null || { echo "dashboard exited early:"; cat "$log"; exit 1; }
  sleep 0.2
done

echo "==> running offline render check…"
node machines-render.test.mjs "http://127.0.0.1:$port"
