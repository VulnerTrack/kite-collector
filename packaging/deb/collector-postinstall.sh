#!/bin/sh
# postinst for the main kite-collector deb/rpm. The package ships the
# systemd unit, so this hook makes systemd see it, enables it at boot,
# bridges upgrades from the old /usr/local/bin layout, and picks up new
# binaries. Fresh installs start immediately so onboarding and collection
# do not need a separate service-start command. Upgrades preserve an
# explicitly stopped service; running services restart onto the new binary.
#
# Every systemd interaction is guarded on /run/systemd/system so installs
# inside containers (no systemd as PID 1) and chroots succeed cleanly.
set -e

# Legacy-path bridge: packages before the /usr/bin move, and the one-line
# installer's binary method, put the binary at /usr/local/bin. An
# already-running shell keeps that absolute path in its command hash even
# after the file is gone, and a postinst cannot clear another shell's hash
# table — the user would see "No such file or directory" until `hash -r`.
# Keep the cached path valid by linking it to /usr/bin whenever nothing is
# there, on every install (not just upgrades: the old file may have been
# removed by an earlier package removal or by hand). A self-registered
# /etc unit that still names the legacy path relies on it too. Never
# clobber an existing file. On rpm the old file is still present at %post
# time; collector-posttrans.sh handles that ordering.
bridge_legacy_path() {
    legacy=/usr/local/bin/kite-collector
    newbin=/usr/bin/kite-collector
    if [ -x "$newbin" ] && [ ! -e "$legacy" ] && [ ! -L "$legacy" ]; then
        mkdir -p /usr/local/bin
        ln -s "$newbin" "$legacy" || true
    fi
}

bridge_legacy_path

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable kite-collector.service
    # Debian: configure with no previous version. RPM: first install = 1.
    if { [ "${1:-}" = configure ] && [ -z "${2:-}" ]; } || [ "${1:-}" = 1 ]; then
        systemctl start kite-collector.service
    # Upgrade over a running service: restart onto the new binary now
    # rather than waiting for the agent's own binary-change watcher.
    elif systemctl is-active --quiet kite-collector.service; then
        systemctl restart kite-collector.service
    fi
fi

exit 0
