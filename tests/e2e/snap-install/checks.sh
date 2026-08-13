#!/usr/bin/env bash
# Test-runner assertions over the evidence the ubuntu machine wrote to
# /results. Exits non-zero if any check fails; prints every check either way.
set -uo pipefail

R=/results
fail=0

if [ ! -s "$R/facts.env" ]; then
    echo "FATAL: $R/facts.env missing or empty — the ubuntu scenario never ran"
    exit 2
fi
# shellcheck disable=SC1091
set -a && . "$R/facts.env" && set +a

check() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  ok    $desc"
    else
        echo "  FAIL  $desc"
        fail=1
    fi
}

echo "== dry-run behaves under snap =="
check "dry-run exits 0" test "$DRYRUN_EXIT" = 0
check "dry-run plans the copy out of the snap tree" \
    grep -F '/snap/kite-collector/x1/kite-collector → /usr/local/bin/kite-collector' "$R/dryrun.out"
check "dry-run wrote no binary" test "$DRYRUN_WROTE_BINARY" = no
check "dry-run wrote no certs dir" test "$DRYRUN_WROTE_CERTS_DIR" = no
check "dry-run wrote no systemd unit" test "$DRYRUN_WROTE_UNIT" = no

echo "== install from a snap-installed binary =="
check "install exits 0" test "$INSTALL_EXIT" = 0
check "binary copied out of the snap (sha256 match)" \
    test -n "$SNAP_BINARY_SHA" -a "$SNAP_BINARY_SHA" = "$INSTALLED_BINARY_SHA"
check "certs dir created" test "$CERTS_DIR_EXISTS" = yes
check "systemd unit registered" test "$UNIT_PRESENT" = yes
check "unit ExecStart uses the installed binary" \
    grep -F '/usr/local/bin/kite-collector' "$R/unit.service"
check "unit does not reference the snap tree" \
    bash -c "! grep -F '/snap/' $R/unit.service"
check "boot persistence enabled" test "$SERVICE_ENABLED" = enabled
check "unenrolled agent: service registered but NOT started" \
    test "$SERVICE_ACTIVE" != active
check "no enrollment PEMs yet" test "$ENROLLMENT_PEMS" = 0
check "install output reports service registration" \
    grep -F 'service "kite-collector" registered' "$R/install.out"
check "post-install report tells the operator to enroll" \
    grep -F 'enroll' "$R/install.out"

echo "== snap tree left intact =="
check "no writes into /snap (squashfs is read-only on real hosts)" \
    test "$SNAP_TREE_MODIFIED" = no

echo "== re-running install (snap refresh) is safe =="
check "re-install exits 0" test "$REINSTALL_EXIT" = 0

echo
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL — see outputs under /results (docker compose cp)"
    exit 1
fi
echo "RESULT: PASS"
