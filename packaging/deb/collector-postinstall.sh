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
# at /usr/local/bin, and a self-registered kardianos unit under
# /etc/systemd/system points there. dpkg removes the old path during
# unpack, which would leave that unit's ExecStart dangling — a compat
# symlink keeps it working until the operator re-runs install (or removes
# the /etc unit in favor of the packaged one). Never clobbers: only an
# empty path gets the link. On rpm the old file is still present at
# %post time; the posttrans script (collector-posttrans.sh) runs the same
# bridge after removal.
bridge_legacy_path() {
    unit=/etc/systemd/system/kite-collector.service
    legacy=/usr/local/bin/kite-collector
    newbin=/usr/bin/kite-collector
    if [ -f "$unit" ] && [ -x "$newbin" ] && grep -q "$legacy" "$unit" \
        && [ ! -e "$legacy" ] && [ ! -L "$legacy" ]; then
        mkdir -p /usr/local/bin
        ln -s "$newbin" "$legacy" || true
    fi
}

bridge_legacy_path

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Upgrade over a running service: restart onto the new binary now
    # rather than waiting for the agent's own binary-change watcher.
    if systemctl is-active --quiet kite-collector.service; then
        systemctl restart kite-collector.service || true
    fi
fi

exit 0
