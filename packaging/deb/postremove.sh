#!/bin/sh
# postrm for kite-collector-osquery.
#
# Runtime state (/var/lib RocksDB, /var/log results) survives a plain
# remove — same policy as the Windows MSI and the collector's own
# certificate store — and is deleted only on purge.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/kite-collector/osquery /var/log/kite-collector/osquery
fi

# Clean the /usr/local/bin compat symlink the postinst bridge may have
# created — on real removal only ($1 = remove/purge); during an upgrade
# the old package's postrm runs with $1 = "upgrade" and the link must
# survive for the still-registered /etc unit.
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    legacy=/usr/local/bin/kite-collector
    if [ -L "$legacy" ] && [ "$(readlink "$legacy")" = "/usr/bin/kite-collector" ]; then
        rm -f "$legacy"
    fi
fi

exit 0
