#!/usr/bin/env bash
# Proves the simulated osquery is live and queryable over its extensions
# socket — the same Thrift UDS a Go osquery-go client (a future kite
# osquery-backed collector) would bind to. Attaches as a client with
# `osqueryi --connect` rather than running a standalone shell, so a green
# run means the *daemon + socket* work, not just the osquery binary.
set -euo pipefail

SOCK="${OSQUERY_SOCKET:-/var/osquery/osquery.em}"

q() {
  # `osqueryi --connect <socket>` attaches to the running osqueryd over its
  # extensions socket (the path is the argument to --connect, not a separate
  # --extensions_socket flag). It prints a "Connected to extension socket ...
  # for debugging" banner to stdout ahead of the JSON — strip it so the output
  # is valid JSON that jq can parse.
  osqueryi --connect "$SOCK" --json "$1" 2>/dev/null \
    | grep -v '^Connected to extension socket'
}

echo "==> waiting for osquery extensions socket at $SOCK"
for _ in $(seq 1 30); do
  [ -S "$SOCK" ] && break
  sleep 1
done
if [ ! -S "$SOCK" ]; then
  echo "FAIL: extensions socket never appeared at $SOCK" >&2
  exit 1
fi

echo "==> osquery_info (identity of the running daemon)"
q "SELECT version, pid, build_platform FROM osquery_info;"

echo "==> processes (proves a real table is served over the socket)"
q "SELECT pid, name FROM processes ORDER BY pid LIMIT 5;"

echo "==> os_version"
q "SELECT name, version, platform FROM os_version;"

# Assert osquery_info returns exactly one row with a non-empty version — a
# minimal data-quality gate so the probe fails loudly if the socket answers
# but returns garbage.
VER="$(q 'SELECT version FROM osquery_info;' | jq -r '.[0].version // empty')"
if [ -z "$VER" ]; then
  echo "FAIL: osquery_info returned no version over the socket" >&2
  exit 1
fi

echo "==> OK: simulated osquery is live and queryable (version $VER)"
