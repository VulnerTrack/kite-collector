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
#   - events subsystem .. inotify publisher / event subscribers stopped running
#   - YARA on-demand .... the yara table lost YARA support, or rules stopped
#                         compiling / matching (positive AND negative canary)
#   - hash .............. the hash table disagrees with sha256sum (data quality)
#   - FIM ............... file_events no longer sees changes under file_paths
#   - YARA events ....... yara_events no longer scans files on change
#
# Run against a pinned version AND "latest" (see the daily workflow) so drift
# surfaces before it reaches a released collector.
#
# Exit status: 0 iff every check passed. Runs ALL checks regardless of failures
# (no `set -e`) so one run reports the full picture.
set -uo pipefail

SOCK="${OSQUERY_SOCKET:-/var/osquery/osquery.em}"
WATCH_DIR="${OSQUERY_WATCH_DIR:-/var/kite/watch}"
SIGFILE="/etc/osquery/yara/kite.yar"
MARKER="KITE-OSQUERY-SIM-YARA-CANARY"
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

# retry_osq <sql> <jq filter> <attempts> — polls until the filter yields
# non-empty output, 1s apart. Event-driven tables (file_events, yara_events)
# are asynchronous: inotify delivery + the event loop take a moment, so a
# single-shot query would be flaky by design. Prints the value on success.
retry_osq() {
  local sql=$1 filter=$2 attempts=${3:-30} out
  for _ in $(seq 1 "$attempts"); do
    out=$(osq "$sql" | jq -r "$filter" 2>/dev/null)
    if [ -n "$out" ]; then
      printf '%s' "$out"
      return 0
    fi
    sleep 1
  done
  return 1
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

# Plant the FIM/YARA canaries NOW, before the static checks run, so inotify
# events have maximum dwell time to reach file_events / yara_events by the
# time the event-driven checks poll for them (sections 10-12). The watch
# volume is shared with the daemon: writes here hit the same inodes its
# inotify subscription watches. Unique names per run — the volume may outlive
# a run.
#
# FIM and YARA deliberately watch DISJOINT subtrees (fim/ vs yara/): osquery's
# inotify publisher owns each kernel watch descriptor by exactly ONE
# subscription (shouldFire: `sc.get() != ec->isub_ctx.get()`), and
# inotify_add_watch dedups by path — so when file_events and yara_events watch
# the same directory, the last subscriber to register (yara_events) steals the
# watch and file_events goes silently deaf. Section 12 pins that behavior.
FIM_DIR="${WATCH_DIR}/fim"
YARA_DIR="${WATCH_DIR}/yara"
RUN_ID="$$-$(date +%s)"
CANARY="${YARA_DIR}/canary-${RUN_ID}.txt"
CLEAN="${YARA_DIR}/clean-${RUN_ID}.txt"
FIM_CANARY="${FIM_DIR}/fim-canary-${RUN_ID}.txt"
# A file matching BOTH baked rules (marker string + the "KITEHEX" bytes the
# hex rule keys on), used to pin that yara.count counts distinct RULES.
BOTH="${YARA_DIR}/both-${RUN_ID}.txt"
if mkdir -p "$FIM_DIR" "$YARA_DIR" 2>/dev/null \
   && printf 'kite sim yara canary: %s\n' "$MARKER" > "$CANARY" \
   && printf 'kite sim clean file: no marker here\n' > "$CLEAN" \
   && printf 'kite sim fim canary: %s\n' "$MARKER" > "$FIM_CANARY" \
   && printf '%s and KITEHEX\n' "$MARKER" > "$BOTH"; then
  pass "watch dirs writable (canaries planted)" "$FIM_DIR + $YARA_DIR"
else
  fail "watch dirs writable (canaries planted)" "cannot write under $WATCH_DIR"
fi

# 5. Every table a kite osquery-backed collector would consume still exists.
#    0 rows is fine (e.g. docker_* with no docker inside the sim) — we assert the
#    query *plans*, which fails loudly if the table was removed or renamed.
echo "  -- tables (schema drift) --"
for t in processes listening_ports users logged_in_users os_version system_info \
         deb_packages kernel_modules interface_addresses mounts block_devices \
         crontab certificates docker_containers docker_images \
         process_open_sockets suid_bin etc_hosts apt_sources \
         file_events yara_events osquery_events; do
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
col_check "process_open_sockets" process_open_sockets \
          "pid,fd,family,protocol,local_address,local_port,remote_address,remote_port"
col_check "file_events"       file_events       "target_path,category,action,sha256,time"
col_check "yara_events"       yara_events       "target_path,category,action,matches,count"

# yara and hash are constraint-required virtual tables: a bare SELECT errors
# with "constraint required", which would read as a false table-removed FAIL.
# Their plan/column checks carry the constraints a real collector would pass.
if osq "SELECT path, matches, count, sig_group, sigfile
        FROM yara WHERE path='/etc/hostname' AND sigfile='${SIGFILE}';" \
     | jq -e . >/dev/null 2>&1; then
  pass "columns: yara (constrained)"
else
  fail "columns: yara (constrained)" "yara table missing, or YARA support not compiled in"
fi
if osq "SELECT path, md5, sha1, sha256 FROM hash WHERE path='/etc/hostname';" \
     | jq -e . >/dev/null 2>&1; then
  pass "columns: hash (constrained)"
else
  fail "columns: hash (constrained)" "hash table missing or constraint behavior changed"
fi

# 7. Events subsystem is actually running (not just tables existing). If the
#    inotify publisher or the file_events/yara_events subscribers show
#    active=0, FIM is silently dead even though every schema check passes.
echo "  -- events subsystem --"
for ev in inotify file_events yara_events; do
  ACTIVE=$(osq "SELECT active FROM osquery_events WHERE name='${ev}';" \
             | jq -r '.[0].active // empty')
  if [ "$ACTIVE" = "1" ]; then
    pass "events: ${ev} active"
  else
    fail "events: ${ev} active" "active='${ACTIVE:-missing}' (events disabled or subscriber gone)"
  fi
done

# 8. YARA on-demand scanning (the `yara` table): the canary file must match
#    the kite_sim_canary rule, and the clean file must NOT match anything —
#    the negative leg catches a sigfile that fails to compile or a scanner
#    that starts matching everything.
echo "  -- YARA on-demand (yara table) --"
Y_COUNT=$(osq "SELECT count AS c, matches FROM yara
               WHERE path='${CANARY}' AND sigfile='${SIGFILE}';" \
            | jq -r '.[0].c // empty')
Y_MATCHES=$(osq "SELECT matches FROM yara
                 WHERE path='${CANARY}' AND sigfile='${SIGFILE}';" \
              | jq -r '.[0].matches // empty')
if [ -n "$Y_COUNT" ] && [ "$Y_COUNT" -ge 1 ] 2>/dev/null \
   && printf '%s' "$Y_MATCHES" | grep -q 'kite_sim_canary'; then
  pass "yara: canary matches" "matches=${Y_MATCHES}"
else
  fail "yara: canary matches" "count='${Y_COUNT:-}' matches='${Y_MATCHES:-}'"
fi
N_COUNT=$(osq "SELECT count AS c FROM yara
               WHERE path='${CLEAN}' AND sigfile='${SIGFILE}';" \
            | jq -r '.[0].c // empty')
if [ "$N_COUNT" = "0" ]; then
  pass "yara: clean file does not match"
else
  fail "yara: clean file does not match" "count='${N_COUNT:-no row}' (expected 0)"
fi
# yara.count counts distinct matching RULES, not string hits (osquery
# YARACallback increments once per CALLBACK_MSG_RULE_MATCHING). A file
# matching BOTH baked rules must report count=2 with both rule names. Kite
# reads this as yara_match_count, so a drift to "count = string matches"
# would silently change that number's meaning — pin it here.
B_COUNT=$(osq "SELECT count AS c FROM yara
               WHERE path='${BOTH}' AND sigfile='${SIGFILE}';" \
            | jq -r '.[0].c // empty')
B_MATCHES=$(osq "SELECT matches FROM yara
                 WHERE path='${BOTH}' AND sigfile='${SIGFILE}';" \
              | jq -r '.[0].matches // empty')
if [ "$B_COUNT" = "2" ] \
   && printf '%s' "$B_MATCHES" | grep -q 'kite_sim_canary' \
   && printf '%s' "$B_MATCHES" | grep -q 'kite_sim_hex_canary'; then
  pass "yara: count = distinct rules (2)" "matches=${B_MATCHES}"
else
  fail "yara: count = distinct rules (2)" "count='${B_COUNT:-}' matches='${B_MATCHES:-}'"
fi

# 9. hash table agrees with coreutils on the same bytes (data quality — the
#    daemon reads the file through the shared volume, we read it locally).
WANT_SHA=$(sha256sum "$CANARY" | awk '{print $1}')
GOT_SHA=$(osq "SELECT sha256 FROM hash WHERE path='${CANARY}';" \
            | jq -r '.[0].sha256 // empty')
if [ -n "$GOT_SHA" ] && [ "$GOT_SHA" = "$WANT_SHA" ]; then
  pass "hash: sha256 matches sha256sum"
else
  fail "hash: sha256 matches sha256sum" "hash='${GOT_SHA:-}' sha256sum='${WANT_SHA}'"
fi

# 10. FIM: the fim/ canary write must surface in file_events. Event delivery
#     is asynchronous (inotify -> event loop -> RocksDB), so poll with a
#     budget instead of a single shot.
echo "  -- FIM + YARA events (event-driven) --"
if ACTION=$(retry_osq "SELECT action FROM file_events
                       WHERE target_path='${FIM_CANARY}' LIMIT 1;" \
                      '.[0].action // empty' 45); then
  pass "file_events: fim canary captured" "action=${ACTION}"
else
  fail "file_events: fim canary captured" "no event for ${FIM_CANARY} after 45s"
fi

# 11. yara_events: the yara/ canary write must trigger an event-driven YARA
#     scan that reports the canary rule match.
if EV_MATCHES=$(retry_osq "SELECT matches FROM yara_events
                           WHERE target_path='${CANARY}' AND count > 0 LIMIT 1;" \
                          '.[0].matches // empty' 45) \
   && printf '%s' "$EV_MATCHES" | grep -q 'kite_sim_canary'; then
  pass "yara_events: event-driven match" "matches=${EV_MATCHES}"
else
  fail "yara_events: event-driven match" "no matching yara_events row for ${CANARY} after 45s"
fi

# 12. Known-pitfall pin: file_events must NOT see writes under the yara/
#     category — yara_events' later registration owns that subtree's inotify
#     watch descriptor (see the comment above the canary plant). A kite
#     collector must therefore never rely on file_events for paths that
#     yara_events also watches. If this check ever FAILS on `latest`,
#     upstream fixed the collision — good news, but re-plan the config
#     guidance before adopting.
FE_YARA=$(osq "SELECT count(*) AS n FROM file_events
               WHERE target_path='${CANARY}';" | jq -r '.[0].n // empty')
if [ "$FE_YARA" = "0" ]; then
  pass "file_events blind to yara-watched paths (known collision)"
else
  fail "file_events blind to yara-watched paths (known collision)" \
       "got ${FE_YARA:-no} rows — upstream inotify ownership behavior changed"
fi

echo
echo "== result: ${PASSES} passed, ${FAILS} failed (osquery ${VER}) =="
[ "$FAILS" -eq 0 ]
