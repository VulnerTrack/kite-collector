#!/usr/bin/env bash
# Container-side battery for the kite-collector-osquery deb. Runs inside a
# stock debian container (no systemd as PID 1) with the built package
# mounted at /pkg. Driven by run.sh — do not run on a host you care about:
# it installs/removes packages and starts daemons.
#
# Covers, in order:
#   1. apt install of the bundle (deps + maintainer scripts sans systemd)
#   2. package metadata: conflicts/replaces/provides, conffiles
#   3. installed layout: binaries, symlink, unit, drop-in, state dirs
#   4. unit passes systemd-analyze verify (offline)
#   5. the bundled daemon actually runs: socket up, queries answer,
#      augeas lenses wired, version pinned
#   6. plain kite-collector <-> bundle cross-grade via apt (the deb
#      analogue of the MSIs' shared-UpgradeCode swap)
#   7. remove keeps runtime state, purge deletes it
set -uo pipefail

FAILS=0
PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "  PASS: $1${2:+ — $2}"; }
fail() { FAILS=$((FAILS + 1)); echo "  FAIL: $1${2:+ — $2}"; }

# dpkg -s exits 0 for removed-but-config-remains ("rc") packages, so status
# must be compared explicitly.
is_installed() { [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = "installed" ]; }

DEB=$(ls /pkg/kite-collector-osquery_*_amd64.deb | head -1)
OSQ=/opt/kite-collector/osquery/bin/osqueryd
OSQI=/opt/kite-collector/osquery/bin/osqueryi
SOCK=/run/kite-osquery/kite-osquery.em

echo "== kite-collector-osquery deb battery =="
echo "  package: $DEB"

# ── 1. install ────────────────────────────────────────────────────────────
apt-get update -qq >/dev/null 2>&1
if apt-get install -y -qq "$DEB" >/dev/null 2>&1; then
  pass "apt install (no systemd running)"
else
  fail "apt install (no systemd running)" "maintainer scripts or deps failed"
  echo "== battery aborted =="; exit 1
fi

# ── 2. package metadata ─────────────────────────────────────────────────
for field in Conflicts Replaces Provides; do
  if dpkg -s kite-collector-osquery 2>/dev/null | grep -q "^${field}: kite-collector$"; then
    pass "control: ${field}: kite-collector"
  else
    fail "control: ${field}: kite-collector"
  fi
done
CONFF=$(dpkg-query -W -f='${Conffiles}\n' kite-collector-osquery 2>/dev/null)
for f in /etc/kite-collector/osquery/osquery.conf /etc/kite-collector/osquery/osquery.flags; do
  if printf '%s' "$CONFF" | grep -q "$f"; then
    pass "conffile registered: $f"
  else
    fail "conffile registered: $f"
  fi
done

# ── 3. layout ────────────────────────────────────────────────────────────
[ -x /usr/bin/kite-collector ] && pass "collector binary installed" || fail "collector binary installed"
[ -x "$OSQ" ] && pass "osqueryd installed" || fail "osqueryd installed"
[ "$(readlink -f "$OSQI")" = "$OSQ" ] && pass "osqueryi symlink -> osqueryd" || fail "osqueryi symlink -> osqueryd"
[ -f /usr/lib/systemd/system/kite-osqueryd.service ] && pass "systemd unit installed" || fail "systemd unit installed"
if grep -q "KITE_OSQUERY_SOCKET=$SOCK" /usr/lib/systemd/system/kite-collector.service.d/10-kite-osquery-socket.conf 2>/dev/null; then
  pass "collector drop-in exports KITE_OSQUERY_SOCKET"
else
  fail "collector drop-in exports KITE_OSQUERY_SOCKET"
fi
[ -d /var/lib/kite-collector/osquery ] && pass "state dir created" || fail "state dir created"
[ -d /var/log/kite-collector/osquery ] && pass "log dir created" || fail "log dir created"
if OUT=$(/usr/bin/kite-collector version 2>&1); then
  pass "kite-collector version runs" "$(printf '%s' "$OUT" | head -1)"
else
  fail "kite-collector version runs" "$OUT"
fi

# ── 4. unit verifies offline ─────────────────────────────────────────────
apt-get install -y -qq systemd >/dev/null 2>&1
if systemd-analyze verify /usr/lib/systemd/system/kite-osqueryd.service >/tmp/verify.out 2>&1; then
  pass "systemd-analyze verify kite-osqueryd.service"
else
  fail "systemd-analyze verify kite-osqueryd.service" "$(head -3 /tmp/verify.out | tr '\n' ' ')"
fi

# ── 5. the daemon runs (ExecStart replicated; RuntimeDirectory by hand) ──
mkdir -p /run/kite-osquery
$OSQ \
  --flagfile /etc/kite-collector/osquery/osquery.flags \
  --config_path /etc/kite-collector/osquery/osquery.conf \
  --database_path /var/lib/kite-collector/osquery/osquery.db \
  --logger_path /var/log/kite-collector/osquery \
  --extensions_socket "$SOCK" &
OSQ_PID=$!
for _ in $(seq 1 30); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] && pass "extensions socket up" "$SOCK" || fail "extensions socket up" "daemon did not create $SOCK"

osq() { "$OSQI" --connect "$SOCK" --json "$1" 2>/dev/null | grep -v '^Connected to extension socket'; }

VER=$(osq "SELECT version FROM osquery_info;" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
[ "$VER" = "5.15.0" ] && pass "osquery_info version pinned" "$VER" || fail "osquery_info version pinned" "got '$VER', want 5.15.0"

OSNAME=$(osq "SELECT name FROM os_version;" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
case "$OSNAME" in Debian*) pass "os_version answers" "$OSNAME";; *) fail "os_version answers" "got '$OSNAME'";; esac

NPKG=$(osq "SELECT count(*) AS n FROM deb_packages;" | sed -n 's/.*"n":"\{0,1\}\([0-9]*\)"\{0,1\}.*/\1/p')
[ -n "$NPKG" ] && [ "$NPKG" -gt 0 ] && pass "deb_packages queryable" "$NPKG packages" || fail "deb_packages queryable" "got '$NPKG'"

# augeas needs the relocated lenses (--augeas_lenses in osquery.flags);
# a broken lens path answers with zero rows, so >0 proves the wiring.
NAUG=$(osq "SELECT count(*) AS n FROM augeas WHERE path='/etc/hosts';" | sed -n 's/.*"n":"\{0,1\}\([0-9]*\)"\{0,1\}.*/\1/p')
[ -n "$NAUG" ] && [ "$NAUG" -gt 0 ] && pass "augeas lenses wired" "$NAUG rows for /etc/hosts" || fail "augeas lenses wired" "got '$NAUG' rows"

kill -0 "$OSQ_PID" 2>/dev/null && pass "daemon still alive" || fail "daemon still alive" "exited during queries"
kill "$OSQ_PID" 2>/dev/null; wait "$OSQ_PID" 2>/dev/null

# ── 6. cross-grade with a plain kite-collector deb ───────────────────────
# Build a stub plain package in-container (content irrelevant — the swap
# semantics live in the control fields).
mkdir -p /tmp/stub/DEBIAN
cat > /tmp/stub/DEBIAN/control <<'EOF'
Package: kite-collector
Version: 0.0.0-dev
Architecture: amd64
Maintainer: VulnerTrack <hello@vulnertrack.dev>
Description: stub plain collector for cross-grade testing
EOF
dpkg-deb -b /tmp/stub /tmp/kite-collector_0.0.0-dev_amd64.deb >/dev/null 2>&1

if apt-get install -y -qq /tmp/kite-collector_0.0.0-dev_amd64.deb >/dev/null 2>&1 \
   && is_installed kite-collector \
   && ! is_installed kite-collector-osquery; then
  pass "cross-grade bundle -> plain (apt removed the bundle)"
else
  fail "cross-grade bundle -> plain (apt removed the bundle)"
fi
if apt-get install -y -qq "$DEB" >/dev/null 2>&1 \
   && is_installed kite-collector-osquery \
   && ! is_installed kite-collector; then
  pass "cross-grade plain -> bundle (apt removed the stub)"
else
  fail "cross-grade plain -> bundle (apt removed the stub)"
fi

# ── 7. remove keeps state, purge deletes it ──────────────────────────────
touch /var/lib/kite-collector/osquery/runtime-canary
apt-get remove -y -qq kite-collector-osquery >/dev/null 2>&1
if [ -f /var/lib/kite-collector/osquery/runtime-canary ]; then
  pass "remove keeps runtime state"
else
  fail "remove keeps runtime state"
fi
apt-get purge -y -qq kite-collector-osquery >/dev/null 2>&1
if [ ! -d /var/lib/kite-collector/osquery ] && [ ! -d /var/log/kite-collector/osquery ]; then
  pass "purge deletes runtime state"
else
  fail "purge deletes runtime state"
fi
[ ! -f /etc/kite-collector/osquery/osquery.conf ] && pass "purge removes conffiles" || fail "purge removes conffiles"

echo "== battery done: ${PASSES} passed, ${FAILS} failed =="
[ "$FAILS" -eq 0 ]
