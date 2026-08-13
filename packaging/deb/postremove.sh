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

exit 0
