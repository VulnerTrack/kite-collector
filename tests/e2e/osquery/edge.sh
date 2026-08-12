#!/usr/bin/env bash
# Edge-case / error-state battery for the simulated osquery.
#
# checks.sh answers "does the happy path still work?"; this script answers
# "does osquery still FAIL the way a collector was designed around?" Every
# check pins an observed 5.15.0 behavior — especially the traps:
#
#   - loud errors ..... bad SQL / missing tables / unconstrained virtual
#                       tables exit non-zero with a parseable message
#   - SILENT zeroes ... a missing or UNCOMPILABLE yara sigfile, or a missing
#                       scan target, returns rc=0 with zero rows — a collector
#                       that reads "0 rows" as "scanned clean" is wrong
#   - data quality .... empty-file hashes, unicode paths, deep recursion,
#                       delete actions, event bursts
#   - async states .... event tables are eventually-consistent (poll, never
#                       single-shot); unwatched paths must stay absent
#
# If an upstream release changes any of these, the corresponding check names
# the drift before a collector ships against it.
set -uo pipefail

SOCK="${OSQUERY_SOCKET:-/var/osquery/osquery.em}"
WATCH_DIR="${OSQUERY_WATCH_DIR:-/var/kite/watch}"
FIM_DIR="${WATCH_DIR}/fim"
YARA_DIR="${WATCH_DIR}/yara"
SIGFILE="/etc/osquery/yara/kite.yar"
MARKER="KITE-OSQUERY-SIM-YARA-CANARY"
RUN_ID="$$-$(date +%s)"
FAILS=0
PASSES=0

pass() { PASSES=$((PASSES + 1)); printf '  \033[32mPASS\033[0m  %-52s %s\n' "$1" "${2:-}"; }
fail() { FAILS=$((FAILS + 1));   printf '  \033[31mFAIL\033[0m  %-52s %s\n' "$1" "${2:-}"; }

# osq_raw returns osqueryi's real exit code and emits cleaned stdout; error
# text goes to stderr (osqueryi prints "Error: ..." on stdout, keep it).
osq_raw() {
  osqueryi --connect "$SOCK" --json "$1" 2>&1 \
    | grep -v '^Connected to extension socket'
  return "${PIPESTATUS[0]}"
}

osq() {
  osqueryi --connect "$SOCK" --json "$1" 2>/dev/null \
    | grep -v '^Connected to extension socket'
}

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

echo "== osquery edge-case / error-state battery =="

mkdir -p "$FIM_DIR" "$YARA_DIR"

# ---------------------------------------------------------------------------
echo "  -- loud error states (a collector must see these fail) --"

# 1. Nonexistent table: non-zero exit + "no such table".
OUT=$(osq_raw "SELECT * FROM kite_no_such_table;"); RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "no such table"; then
  pass "nonexistent table errors loudly" "rc=$RC"
else
  fail "nonexistent table errors loudly" "rc=$RC out=$(printf '%s' "$OUT" | head -1)"
fi

# 2. Syntax error: non-zero exit + "syntax error".
OUT=$(osq_raw "SELEC 1;"); RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qi "syntax error"; then
  pass "SQL syntax error errors loudly" "rc=$RC"
else
  fail "SQL syntax error errors loudly" "rc=$RC"
fi

# 3+4. Constraint-required virtual tables queried without their required
# WHERE column: yara and hash must refuse, not fabricate rows.
for t in yara hash; do
  OUT=$(osq_raw "SELECT count(*) FROM ${t};"); RC=$?
  if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "required column"; then
    pass "unconstrained ${t} refuses (required column)" "rc=$RC"
  else
    fail "unconstrained ${t} refuses (required column)" "rc=$RC"
  fi
done

# 5. Dead socket: connecting to a nonexistent socket fails non-zero, fast
#    (budget 15s — a collector's liveness probe hangs forever if this stalls).
START=$(date +%s)
osqueryi --connect /tmp/kite-no-such.sock "SELECT 1;" >/dev/null 2>&1; RC=$?
ELAPSED=$(( $(date +%s) - START ))
if [ "$RC" -ne 0 ] && [ "$ELAPSED" -le 15 ]; then
  pass "dead socket fails fast" "rc=$RC in ${ELAPSED}s"
else
  fail "dead socket fails fast" "rc=$RC in ${ELAPSED}s"
fi

# ---------------------------------------------------------------------------
echo "  -- SILENT zero-row traps (rc=0, no rows — collector must not read as 'clean') --"

# 6. Missing sigfile: rc=0 and zero rows. THE trap: a typo'd rules path looks
#    exactly like "no matches".
OUT=$(osq "SELECT count FROM yara WHERE path='/etc/hostname' AND sigfile='/kite-nope.yar';"); RC=$?
N=$(printf '%s' "$OUT" | jq -r 'length' 2>/dev/null)
if [ "$RC" -eq 0 ] && [ "$N" = "0" ]; then
  pass "missing sigfile is SILENT (rc=0, 0 rows)"
else
  fail "missing sigfile is SILENT (rc=0, 0 rows)" "rc=$RC rows=$N"
fi

# 7. Uncompilable sigfile: same silent shape. Plant a syntactically broken
#    rules file where the daemon can read it.
BADSIG="${WATCH_DIR}/bad-${RUN_ID}.yar"
printf 'rule { this does not compile' > "$BADSIG"
OUT=$(osq "SELECT count FROM yara WHERE path='/etc/hostname' AND sigfile='${BADSIG}';"); RC=$?
N=$(printf '%s' "$OUT" | jq -r 'length' 2>/dev/null)
if [ "$RC" -eq 0 ] && [ "$N" = "0" ]; then
  pass "uncompilable sigfile is SILENT (rc=0, 0 rows)"
else
  fail "uncompilable sigfile is SILENT (rc=0, 0 rows)" "rc=$RC rows=$N"
fi

# 8. Nonexistent scan target: silent empty set, not an error.
N=$(osq "SELECT count FROM yara WHERE path='/kite/no/file' AND sigfile='${SIGFILE}';" | jq -r 'length')
if [ "$N" = "0" ]; then
  pass "yara on missing target: silent empty set"
else
  fail "yara on missing target: silent empty set" "rows=$N"
fi

# 9. hash of a nonexistent path: silent empty set.
N=$(osq "SELECT sha256 FROM hash WHERE path='/kite/no/file';" | jq -r 'length')
if [ "$N" = "0" ]; then
  pass "hash on missing path: silent empty set"
else
  fail "hash on missing path: silent empty set" "rows=$N"
fi

# ---------------------------------------------------------------------------
echo "  -- data edge cases --"

# 10. Empty file: hash must be the canonical sha256 of zero bytes.
EMPTY="${FIM_DIR}/empty-${RUN_ID}.bin"
: > "$EMPTY"
GOT=$(osq "SELECT sha256 FROM hash WHERE path='${EMPTY}';" | jq -r '.[0].sha256 // empty')
if [ "$GOT" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
  pass "empty file hashes to canonical empty sha256"
else
  fail "empty file hashes to canonical empty sha256" "got=${GOT:-none}"
fi

# 11. Empty file yara scan: succeeds with zero matches (not an error, not a
#     false positive).
C=$(osq "SELECT count FROM yara WHERE path='${EMPTY}' AND sigfile='${SIGFILE}';" | jq -r '.[0].count // "0"')
if [ "$C" = "0" ]; then
  pass "empty file yara scan: zero matches"
else
  fail "empty file yara scan: zero matches" "count=$C"
fi

# 12. Unicode + spaces in filename: on-demand scan and hash still address it.
WEIRD="${YARA_DIR}/päth with späces ${RUN_ID}.txt"
printf '%s\n' "$MARKER" > "$WEIRD"
C=$(osq "SELECT count FROM yara WHERE path='${WEIRD}' AND sigfile='${SIGFILE}';" | jq -r '.[0].count // empty')
if [ -n "$C" ] && [ "$C" -ge 1 ] 2>/dev/null; then
  pass "unicode/space path scans on demand" "count=$C"
else
  fail "unicode/space path scans on demand" "count=${C:-none}"
fi

# 13. Large file (8 MiB): hash agrees with coreutils (streaming, not a
#     truncated read).
BIG="${FIM_DIR}/big-${RUN_ID}.bin"
head -c 8388608 /dev/urandom > "$BIG"
WANT=$(sha256sum "$BIG" | awk '{print $1}')
GOT=$(osq "SELECT sha256 FROM hash WHERE path='${BIG}';" | jq -r '.[0].sha256 // empty')
if [ "$GOT" = "$WANT" ]; then
  pass "8MiB file hash matches sha256sum"
else
  fail "8MiB file hash matches sha256sum" "got=${GOT:-none}"
fi

# 14. Big result set: 10k generated rows arrive intact through the socket.
N=$(osq "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 10000) SELECT count(*) AS c FROM seq;" | jq -r '.[0].c // empty')
if [ "$N" = "10000" ]; then
  pass "10k-row result set over the socket"
else
  fail "10k-row result set over the socket" "got=${N:-none}"
fi

# 15. Concurrent clients: five parallel connections all answer. The Thrift
#     socket must multiplex a fleet of collector queries, not serialize into
#     failures.
CONC_FAILS=0
for i in 1 2 3 4 5; do
  osqueryi --connect "$SOCK" "SELECT ${i};" >/dev/null 2>&1 &
done
for job in $(jobs -p); do
  wait "$job" || CONC_FAILS=$((CONC_FAILS + 1))
done
if [ "$CONC_FAILS" -eq 0 ]; then
  pass "5 concurrent clients all answered"
else
  fail "5 concurrent clients all answered" "${CONC_FAILS} failed"
fi

# ---------------------------------------------------------------------------
echo "  -- async / eventually-consistent states --"

# 16. Pending -> delivered: a fresh write is NOT required to be visible
#     immediately (that's the pending state), but must arrive within the
#     poll budget. Single-shot consumers are wrong by design.
ASYNC="${FIM_DIR}/async-${RUN_ID}.txt"
printf 'async state\n' > "$ASYNC"
if ACTION=$(retry_osq "SELECT action FROM file_events WHERE target_path='${ASYNC}' LIMIT 1;" \
                      '.[0].action // empty' 45); then
  pass "fresh write becomes visible within poll budget" "action=${ACTION}"
else
  fail "fresh write becomes visible within poll budget" "never arrived in 45s"
fi

# 17. Delete action: removing a watched file emits DELETED (a tamper-evidence
#     path collectors alert on).
DELME="${FIM_DIR}/delete-me-${RUN_ID}.txt"
printf 'to be removed\n' > "$DELME"
rm -f "$DELME"
if retry_osq "SELECT action FROM file_events WHERE target_path='${DELME}' AND action='DELETED' LIMIT 1;" \
             '.[0].action // empty' 45 >/dev/null; then
  pass "DELETED action captured for removed file"
else
  fail "DELETED action captured for removed file" "no DELETED event in 45s"
fi

# 18. Recursive depth: %% must cover nested directories created after boot.
DEEP_DIR="${FIM_DIR}/a/b/c"
mkdir -p "$DEEP_DIR"
DEEP="${DEEP_DIR}/deep-${RUN_ID}.txt"
sleep 2 # give inotify a beat to pick up the new subdirs before writing
printf 'deep\n' > "$DEEP"
if retry_osq "SELECT action FROM file_events WHERE target_path='${DEEP}' LIMIT 1;" \
             '.[0].action // empty' 45 >/dev/null; then
  pass "event captured 3 directories deep"
else
  fail "event captured 3 directories deep" "no event for ${DEEP} in 45s"
fi

# 19. Burst: 25 rapid writes all surface (mild-burst loss check).
BURST_DIR="${FIM_DIR}/burst-${RUN_ID}"
mkdir -p "$BURST_DIR"
sleep 2
for i in $(seq 1 25); do printf 'b%s\n' "$i" > "${BURST_DIR}/f${i}.txt"; done
if N=$(retry_osq "SELECT count(*) AS n FROM file_events
                  WHERE target_path LIKE '${BURST_DIR}/%' AND action='CREATED'
                  HAVING count(*) >= 25;" '.[0].n // empty' 60); then
  pass "burst of 25 writes all captured" "events=${N}"
else
  LAST=$(osq "SELECT count(*) AS n FROM file_events WHERE target_path LIKE '${BURST_DIR}/%' AND action='CREATED';" | jq -r '.[0].n // "0"')
  fail "burst of 25 writes all captured" "only ${LAST}/25 after 60s"
fi

# 20. Unwatched path stays absent: the watch-root itself is outside both
#     fim/ and yara/ subtrees — a write there must never appear (scope
#     containment; also guards against an accidental watch-everything config).
STRAY="${WATCH_DIR}/stray-${RUN_ID}.txt"
printf 'stray\n' > "$STRAY"
sleep 5
N=$(osq "SELECT count(*) AS n FROM file_events WHERE target_path='${STRAY}';" | jq -r '.[0].n // "0"')
if [ "$N" = "0" ]; then
  pass "unwatched path emits no events"
else
  fail "unwatched path emits no events" "got ${N} events"
fi

echo
echo "== result: ${PASSES} passed, ${FAILS} failed =="
[ "$FAILS" -eq 0 ]
