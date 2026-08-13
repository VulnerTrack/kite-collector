#!/usr/bin/env bash
# Runs on the ubuntu "machine" (systemd PID 1) and produces evidence files in
# /results for the test-runner container to assert on. Deliberately does NOT
# assert anything itself — the machine produces facts, the runner produces
# verdicts — and deliberately does NOT use `set -e`: non-zero exit codes from
# the binary under test are evidence, not scenario failures.
set -uo pipefail

R=/results
mkdir -p "$R"
: >"$R/facts.env"

fact() { printf '%s=%s\n' "$1" "$2" >>"$R/facts.env"; }

exists() { if [ -e "$1" ]; then echo yes; else echo no; fi; }

# Stamp taken before any kite-collector invocation: nothing under the
# (squashfs-like) snap tree may be newer than this afterwards.
STAMP=/run/snap-stamp
touch "$STAMP"

# --- S1: dry-run must plan the right actions and write nothing -------------
kite-collector install --dry-run >"$R/dryrun.out" 2>&1
fact DRYRUN_EXIT $?
fact DRYRUN_WROTE_BINARY "$(exists /usr/local/bin/kite-collector)"
fact DRYRUN_WROTE_CERTS_DIR "$(exists /var/lib/kite-collector)"
fact DRYRUN_WROTE_UNIT "$(exists /etc/systemd/system/kite-collector.service)"

# --- S2: real install ------------------------------------------------------
kite-collector install >"$R/install.out" 2>&1
fact INSTALL_EXIT $?

fact SNAP_BINARY_SHA "$(sha256sum /snap/kite-collector/x1/kite-collector 2>/dev/null | cut -d' ' -f1)"
fact INSTALLED_BINARY_SHA "$(sha256sum /usr/local/bin/kite-collector 2>/dev/null | cut -d' ' -f1)"
fact CERTS_DIR_EXISTS "$(exists /var/lib/kite-collector)"
fact ENROLLMENT_PEMS "$(ls /var/lib/kite-collector 2>/dev/null | grep -c '\.pem$')"

fact UNIT_PRESENT "$(exists /etc/systemd/system/kite-collector.service)"
cp /etc/systemd/system/kite-collector.service "$R/unit.service" 2>/dev/null \
    || : >"$R/unit.service"
# is-enabled/is-active print their state AND exit non-zero for disabled/
# inactive — capture stdout only, fall back when there was no output at all.
enabled=$(systemctl is-enabled kite-collector 2>/dev/null) || true
active=$(systemctl is-active kite-collector 2>/dev/null) || true
fact SERVICE_ENABLED "${enabled:-query-failed}"
fact SERVICE_ACTIVE "${active:-query-failed}"

# --- S3: re-running install (snap refresh hooks do this) must be safe ------
kite-collector install >"$R/reinstall.out" 2>&1
fact REINSTALL_EXIT $?

# --- Snap tree integrity ---------------------------------------------------
find /snap -newer "$STAMP" >"$R/snap-writes.txt" 2>/dev/null
find /snap -name '*.tmp' >>"$R/snap-writes.txt" 2>/dev/null
if [ -s "$R/snap-writes.txt" ]; then
    fact SNAP_TREE_MODIFIED yes
else
    fact SNAP_TREE_MODIFIED no
fi

echo "scenario complete:"
cat "$R/facts.env"
