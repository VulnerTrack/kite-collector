#!/usr/bin/env bash
# Daily osquery diagnostic battery.
#
# Each check corresponds to a distinct way the osquery integration could break
# over time. The point is not a single green/red — it's to name *which* failure
# mode hit, so a red daily run is immediately actionable:
#
#   - binary/version .... the apt repo, GPG key, or package name changed
#   - socket ............ osqueryd failed to start or moved the socket
#   - --connect ......... the client attach behavior changed (it has before)
#   - table exists ...... a table kite would consume was removed/renamed
#   - columns ........... a column kite reads was removed/renamed
#
# Run against a pinned version AND "latest" (see the daily workflow) so drift
# surfaces before it reaches a released collector.
#
# Exit status: 0 iff every check passed. Runs ALL checks regardless of failures
# (no `set -e`) so one run reports the full picture.
set -uo pipefail

SOCK="${OSQUERY_SOCKET:-/var/osquery/osquery.em}"
FAILS=0
PASSES=0

pass() { PASSES=$((PASSES + 1)); printf '  \033[32mPASS\033[0m  %-40s %s\n' "$1" "${2:-}"; }
fail() { FAILS=$((FAILS + 1));   printf '  \033[31mFAIL\033[0m  %-40s %s\n' "$1" "${2:-}"; }

# osq runs a query over the daemon's extensions socket and emits clean JSON
# (the "Connected to extension socket ..." banner osqueryi prints to stdout is
# stripped). Returns non-zero / empty on any osquery error.
osq() {
  osqueryi --connect "$SOCK" --json "$1" 2>/dev/null \
    | grep -v '^Connected to extension socket'
}

echo "== osquery daily smoke =="

# 1. Binary present and reports a version.
if VER=$(osqueryi --version 2>/dev/null | awk '{print $NF}') && [ -n "$VER" ]; then
  pass "osqueryi binary + version" "$VER"
else
  VER="unknown"
  fail "osqueryi binary + version" "osqueryi --version failed"
fi

# 2. Daemon is up and the extensions socket exists.
if [ -S "$SOCK" ]; then
  pass "extensions socket present" "$SOCK"
else
  fail "extensions socket present" "missing: $SOCK"
fi

# 3. Client can attach over the socket (--connect behavior drift).
if [ "$(osq 'SELECT 1 AS ok;' | jq -r '.[0].ok // empty')" = "1" ]; then
  pass "osqueryi --connect over socket" "SELECT 1 -> 1 row"
else
  fail "osqueryi --connect over socket" "SELECT 1 returned no row"
fi

# 4. osquery_info is queryable and returns a version.
if [ -n "$(osq 'SELECT version FROM osquery_info;' | jq -r '.[0].version // empty')" ]; then
  pass "osquery_info queryable"
else
  fail "osquery_info queryable" "no version row over socket"
fi

# 5. Every table a kite osquery-backed collector would consume still exists.
#    0 rows is fine (e.g. docker_* with no docker inside the sim) — we assert the
#    query *plans*, which fails loudly if the table was removed or renamed.
echo "  -- tables (schema drift) --"
for t in processes listening_ports users logged_in_users os_version system_info \
         deb_packages kernel_modules interface_addresses mounts block_devices \
         crontab certificates docker_containers docker_images; do
  if out=$(osq "SELECT count(*) AS n FROM ${t};") \
     && n=$(printf '%s' "$out" | jq -r '.[0].n // empty') && [ -n "$n" ]; then
    pass "table: ${t}" "${n} rows"
  else
    fail "table: ${t}" "SELECT errored (removed/renamed?)"
  fi
done

# 6. Every column a collector reads still exists (column drift). osquery plans
#    the query even with 0 rows, so a renamed/removed column fails here.
echo "  -- columns (column drift) --"
col_check() {
  local name=$1 tbl=$2 cols=$3
  if osq "SELECT ${cols} FROM ${tbl} LIMIT 1;" | jq -e . >/dev/null 2>&1; then
    pass "columns: ${name}"
  else
    fail "columns: ${name}" "one of [${cols}] missing from ${tbl}"
  fi
}
col_check "processes"         processes         "pid,name,path,cmdline,state,uid,gid,parent"
col_check "listening_ports"   listening_ports   "pid,port,protocol,family,address"
col_check "users"             users             "uid,gid,username,directory,shell"
col_check "os_version"        os_version        "name,version,major,minor,platform"
col_check "deb_packages"      deb_packages      "name,version,arch"
col_check "docker_containers" docker_containers "id,name,image,image_id,state,status"

echo
echo "== result: ${PASSES} passed, ${FAILS} failed (osquery ${VER}) =="
[ "$FAILS" -eq 0 ]
