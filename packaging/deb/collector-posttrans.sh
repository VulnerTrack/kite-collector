#!/bin/sh
# rpm %posttrans for the main kite-collector package. rpm's upgrade order
# runs %post BEFORE the old package's files are removed, so the
# /usr/local/bin → /usr/bin bridge in collector-postinstall.sh sees the
# legacy binary still present and stays quiet. %posttrans runs after the
# removal — the point where a self-registered /etc unit's ExecStart is
# actually dangling — so the same bridge runs again here. Keep the bridge
# logic in sync with collector-postinstall.sh.
set -e

unit=/etc/systemd/system/kite-collector.service
legacy=/usr/local/bin/kite-collector
newbin=/usr/bin/kite-collector
if [ -f "$unit" ] && [ -x "$newbin" ] && grep -q "$legacy" "$unit" \
    && [ ! -e "$legacy" ] && [ ! -L "$legacy" ]; then
    mkdir -p /usr/local/bin
    ln -s "$newbin" "$legacy" || true
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        if systemctl is-active --quiet kite-collector.service; then
            systemctl restart kite-collector.service || true
        fi
    fi
fi

exit 0
