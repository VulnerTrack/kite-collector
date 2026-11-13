#!/bin/sh
# Run only in a disposable Linux container, with the repository mounted read-only.
# All systemctl operations are mocked; no services or network are used.
# docker run --rm --network none -v "$PWD:/work:ro" -w /work debian:12 \
#   sh scripts/test-service-packaging.sh
set -eu
[ -f /.dockerenv ] || { echo "Run this check inside a disposable Docker container." >&2; exit 1; }
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p /run/systemd/system "$test_dir/bin"
export KITE_TEST_LOG="$test_dir/systemctl.log"
export PATH="$test_dir/bin:$PATH"
cat > "$test_dir/bin/systemctl" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$KITE_TEST_LOG"
if [ "$*" = "${KITE_TEST_FAIL:-}" ]; then exit 9; fi
if [ "$1" = is-active ]; then exit "${KITE_TEST_INACTIVE:-1}"; fi
exit 0
STUB
chmod +x "$test_dir/bin/systemctl"

run_hook() {
    : > "$KITE_TEST_LOG"
    sh "$@"
}
plain=packaging/deb/collector-postinstall.sh
bundle=packaging/deb/postinstall.sh

run_hook "$plain" configure
grep -qx 'start kite-collector.service' "$KITE_TEST_LOG"
echo 'PASS fresh Debian install starts collector'
run_hook "$plain" 1
grep -qx 'start kite-collector.service' "$KITE_TEST_LOG"
echo 'PASS fresh RPM install starts collector'
KITE_TEST_INACTIVE=0 run_hook "$plain" configure 1.0.0
grep -qx 'restart kite-collector.service' "$KITE_TEST_LOG"
echo 'PASS running collector restarts on upgrade'
KITE_TEST_INACTIVE=1 run_hook "$plain" configure 1.0.0
if grep -Eq '^(start|restart) kite-collector.service$' "$KITE_TEST_LOG"; then exit 1; fi
echo 'PASS upgrade respects stopped collector'
if KITE_TEST_FAIL='enable kite-collector.service' run_hook "$plain" configure; then exit 1; fi
echo 'PASS boot enable failure propagates'
if KITE_TEST_FAIL='start kite-collector.service' run_hook "$plain" configure; then exit 1; fi
echo 'PASS startup failure propagates'
run_hook "$bundle" configure
grep -qx 'start kite-collector.service' "$KITE_TEST_LOG"
echo 'PASS fresh bundle starts collector'
if KITE_TEST_FAIL='restart kite-osqueryd.service' run_hook "$bundle" configure; then exit 1; fi
grep -qx 'start kite-collector.service' "$KITE_TEST_LOG"
echo 'PASS optional osquery failure still starts collector and propagates error'
