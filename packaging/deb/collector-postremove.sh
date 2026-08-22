#!/bin/sh
# postrm for the main kite-collector deb/rpm: clean the /usr/local/bin
# compat symlink the postinst bridge may have created. On real removal
# only — during an upgrade the OLD package's postrm runs with
# $1 = "upgrade" (deb) or 1 (rpm), and the link must survive for a
# still-registered /etc unit.
set -e

case "$1" in
remove | purge | 0)
    legacy=/usr/local/bin/kite-collector
    if [ -L "$legacy" ] && [ "$(readlink "$legacy")" = "/usr/bin/kite-collector" ]; then
        rm -f "$legacy"
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
    ;;
esac

exit 0
