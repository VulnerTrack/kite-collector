#!/bin/sh
# postinst for kite-collector-osquery. Mirrors the Windows MSI's
# ServiceInstall/ServiceControl behavior: register + start kite-osqueryd.
#
# Every systemd interaction is guarded on /run/systemd/system so installs
# inside containers (no systemd as PID 1) and chroots succeed cleanly —
# the container e2e test (tests/e2e/deb-osquery/run.sh) relies on this.
set -e

# Upgrade bridge for the /usr/local/bin → /usr/bin move — same logic as the
# plain deb's collector-postinstall.sh (keep in sync): a self-registered
# /etc unit pointing at the old collector path keeps working via a compat
# symlink. Never clobbers an existing file.
unit=/etc/systemd/system/kite-collector.service
legacy=/usr/local/bin/kite-collector
newbin=/usr/bin/kite-collector
if [ -f "$unit" ] && [ -x "$newbin" ] && grep -q "$legacy" "$unit" \
    && [ ! -e "$legacy" ] && [ ! -L "$legacy" ]; then
    mkdir -p /usr/local/bin
    ln -s "$newbin" "$legacy" || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable kite-osqueryd.service || true
    # restart (not start) so upgrades pick up the new daemon binary.
    systemctl restart kite-osqueryd.service || true
    # If the collector service exists, restart it so the
    # KITE_OSQUERY_SOCKET drop-in takes effect.
    if systemctl list-unit-files kite-collector.service >/dev/null 2>&1 \
        && systemctl is-active --quiet kite-collector.service; then
        systemctl restart kite-collector.service || true
    fi
fi

exit 0
