#!/bin/sh
# prerm for kite-collector-osquery. Stop + disable the bundled daemon on
# removal only — on upgrade ($1 = "upgrade") the new postinst restarts it,
# so stopping here would just add downtime.
set -e

if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl stop kite-osqueryd.service || true
    systemctl disable kite-osqueryd.service || true
fi

exit 0
