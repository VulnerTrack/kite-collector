#!/bin/sh
# postinst for the main kite-collector deb/rpm. The package ships the
# systemd unit, so this hook makes systemd see it, bridges upgrades from
# the old /usr/local/bin layout, and picks up new binaries. Enabling is
# deliberately left to the operator (or to `kite-collector install`, which
# detects the packaged binary and only enrolls + enables): an unenrolled
# agent has nothing useful to do at boot.
#
# Every systemd interaction is guarded on /run/systemd/system so installs
# inside containers (no systemd as PID 1) and chroots succeed cleanly.
set -e

# Upgrade bridge: packages before the /usr/bin move installed the binary
# at /usr/local/bin. An already-running shell may keep that old absolute
# path in its command hash even after dpkg removes the file; a postinst
# cannot clear the parent shell's hash table. Keep the cached path valid
# by linking it to /usr/bin on Debian upgrades (the old version is $2).
# A self-registered unit that still names the legacy path also needs the
# bridge. Never clobber an existing file. On rpm the old file is still
# present at %post time; collector-posttrans.sh handles that ordering.
bridge_legacy_path() {
    unit=/etc/systemd/system/kite-collector.service
    legacy=/usr/local/bin/kite-collector
    newbin=/usr/bin/kite-collector
    needs_bridge=false
    if [ -n "${2:-}" ]; then
        needs_bridge=true
    elif [ -f "$unit" ] && grep -q "$legacy" "$unit"; then
        needs_bridge=true
    fi
    if [ "$needs_bridge" = true ] && [ -x "$newbin" ] \
        && [ ! -e "$legacy" ] && [ ! -L "$legacy" ]; then
        mkdir -p /usr/local/bin
        ln -s "$newbin" "$legacy" || true
    fi
}

bridge_legacy_path "$@"

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Upgrade over a running service: restart onto the new binary now
    # rather than waiting for the agent's own binary-change watcher.
    if systemctl is-active --quiet kite-collector.service; then
        systemctl restart kite-collector.service || true
    fi
fi

exit 0
