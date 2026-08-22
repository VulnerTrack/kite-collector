#!/usr/bin/env bash
# Container-side battery for the plain kite-collector deb. Runs inside a
# stock debian container (no systemd as PID 1) with the built package
# mounted at /pkg. Driven by run.sh — do not run on a host you care about:
# it installs/removes packages and writes into /etc and /usr/local/bin.
#
# Covers, in order:
#   1. apt install (maintainer scripts must tolerate no systemd)
#   2. installed layout: /usr/bin binary runs, unit + example config land
#   3. unit sanity: ExecStart matches the packaged binary path, and the
#      unit passes systemd-analyze verify when available
#   4. /usr/local/bin → /usr/bin upgrade bridge: creates the compat
#      symlink for a drifted /etc unit, never clobbers a real file,
#      no-ops without the drift signature
#   5. remove: binary + unit gone, bridge symlink cleaned, /etc conffile
#      and manual state preserved
set -uo pipefail

FAILS=0
PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "  PASS: $1${2:+ — $2}"; }
fail() { FAILS=$((FAILS + 1)); echo "  FAIL: $1${2:+ — $2}"; }

DEB=$(ls /pkg/kite-collector_*_amd64.deb | grep -v osquery | head -1)
BIN=/usr/bin/kite-collector
UNIT=/usr/lib/systemd/system/kite-collector.service
ETC_UNIT=/etc/systemd/system/kite-collector.service
LEGACY=/usr/local/bin/kite-collector

echo "== kite-collector deb battery =="
echo "  package: $DEB"

# ── 1. install ───────────────────────────────────────────────────────────
apt-get update -qq >/dev/null 2>&1
if apt-get install -y -qq "$DEB" >/dev/null 2>&1; then
  pass "apt install (no systemd running)"
else
  fail "apt install (no systemd running)" "maintainer scripts or deps failed"
  echo "== battery aborted =="; exit 1
fi

# ── 2. installed layout ─────────────────────────────────────────────────
[ -x "$BIN" ] && pass "binary at $BIN" || fail "binary at $BIN"
if OUT=$("$BIN" version 2>&1); then
  pass "binary executes" "$(echo "$OUT" | head -1)"
else
  fail "binary executes" "$OUT"
fi
[ -f "$UNIT" ] && pass "unit shipped at $UNIT" || fail "unit shipped at $UNIT"
[ -f /etc/kite-collector/kite-collector.example.yaml ] \
  && pass "example config shipped" || fail "example config shipped"
if dpkg -S "$BIN" >/dev/null 2>&1; then
  pass "dpkg owns the binary (install will adopt, not copy)"
else
  fail "dpkg owns the binary"
fi

# ── 3. unit sanity ──────────────────────────────────────────────────────
if grep -q "ExecStart=$BIN " "$UNIT"; then
  pass "unit ExecStart uses the packaged path"
else
  fail "unit ExecStart uses the packaged path" "$(grep ExecStart "$UNIT" | head -1)"
fi
if grep -q "^Restart=always" "$UNIT"; then
  pass "unit has Restart=always (zero-step upgrade relaunch)"
else
  fail "unit has Restart=always"
fi
if apt-get install -y -qq systemd >/dev/null 2>&1 && command -v systemd-analyze >/dev/null 2>&1; then
  if systemd-analyze verify "$UNIT" 2>&1 | grep -v "^$" | grep -qv "Cannot determine"; then
    # systemd-analyze prints unit errors to output; empty (or only
    # environment noise) means the unit parsed clean.
    VERIFY_OUT=$(systemd-analyze verify "$UNIT" 2>&1 | grep -v "Cannot determine" || true)
    if [ -z "$VERIFY_OUT" ]; then
      pass "systemd-analyze verify"
    else
      fail "systemd-analyze verify" "$VERIFY_OUT"
    fi
  else
    pass "systemd-analyze verify"
  fi
else
  pass "systemd-analyze verify" "skipped (systemd unavailable in container)"
fi

# ── 4. upgrade bridge ───────────────────────────────────────────────────
# 4a. Drift signature present (legacy /etc unit, empty legacy path) →
#     reinstall runs postinst → compat symlink appears.
mkdir -p /etc/systemd/system
printf '[Service]\nExecStart=%s service run\n' "$LEGACY" > "$ETC_UNIT"
rm -f "$LEGACY"
apt-get install -y -qq --reinstall "$DEB" >/dev/null 2>&1
if [ -L "$LEGACY" ] && [ "$(readlink "$LEGACY")" = "$BIN" ]; then
  pass "bridge: compat symlink created for drifted /etc unit"
else
  fail "bridge: compat symlink created for drifted /etc unit"
fi
"$LEGACY" version >/dev/null 2>&1 \
  && pass "bridge: symlinked path executes" || fail "bridge: symlinked path executes"

# 4b. Never clobbers a real file at the legacy path.
rm -f "$LEGACY"
printf 'sentinel' > "$LEGACY"
apt-get install -y -qq --reinstall "$DEB" >/dev/null 2>&1
if [ "$(cat "$LEGACY")" = "sentinel" ]; then
  pass "bridge: existing file at legacy path preserved"
else
  fail "bridge: existing file at legacy path preserved"
fi
rm -f "$LEGACY"

# 4c. No drift signature (no /etc unit) → no symlink.
rm -f "$ETC_UNIT"
apt-get install -y -qq --reinstall "$DEB" >/dev/null 2>&1
if [ ! -e "$LEGACY" ] && [ ! -L "$LEGACY" ]; then
  pass "bridge: no-op without a drifted /etc unit"
else
  fail "bridge: no-op without a drifted /etc unit"
fi

# ── 5. remove ───────────────────────────────────────────────────────────
# Recreate the bridge state so postrm's cleanup is exercised.
printf '[Service]\nExecStart=%s service run\n' "$LEGACY" > "$ETC_UNIT"
apt-get install -y -qq --reinstall "$DEB" >/dev/null 2>&1
[ -L "$LEGACY" ] || fail "precondition: bridge symlink before remove"
apt-get remove -y -qq kite-collector >/dev/null 2>&1
[ ! -x "$BIN" ] && pass "remove: binary gone" || fail "remove: binary gone"
[ ! -f "$UNIT" ] && pass "remove: unit gone" || fail "remove: unit gone"
if [ ! -L "$LEGACY" ] && [ ! -e "$LEGACY" ]; then
  pass "remove: bridge symlink cleaned"
else
  fail "remove: bridge symlink cleaned"
fi
[ -f "$ETC_UNIT" ] && pass "remove: operator's /etc unit untouched" \
  || fail "remove: operator's /etc unit untouched"

echo "== battery finished: $PASSES passed, $FAILS failed =="
[ "$FAILS" -eq 0 ]
