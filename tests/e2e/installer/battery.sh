#!/bin/sh
# Container side of the installer battery. run.sh starts one stock distro
# container per leg and runs this with plain `sh` (dash, busybox ash or bash,
# whatever the image has). It installs the one-liner's only precondition, a
# downloader, then pipes the served installer into sh exactly as a user
# would and asserts on the result.
#
#   LEG            debian | ubuntu | fedora | almalinux | opensuse | alpine | arch
#   MODE           local (fixture release) | live (real latest release)
#   FIXTURE_URL    where run.sh serves install.sh and the fixture release
#   OLD_VERSION, NEW_VERSION   the two fixture versions (local)
#   LIVE_VERSION   the latest real release (live)
set -u
: "${LEG:?}" "${MODE:?}" "${FIXTURE_URL:?}"

PASSES=0
FAILS=0
LOG=/tmp/installer.log
INSTALLER_URL="$FIXTURE_URL/install.sh"
RUN_AS=""

pass() {
    PASSES=$((PASSES + 1))
    echo "  PASS: $1"
}
fail() {
    FAILS=$((FAILS + 1))
    echo "  FAIL: $1"
    [ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/        | /'
}

# oneliner VAR=value... runs `curl -fsSL $INSTALLER_URL | sh` (wget -qO- when
# the image has no curl) with that environment, as $RUN_AS when set.
oneliner() {
    if [ "$MODE" = local ]; then
        set -- KITE_RELEASES_URL="$FIXTURE_URL/releases" KITE_APT_URL="$FIXTURE_URL/apt" "$@"
    fi
    # shellcheck disable=SC2016 # expanded by the inner sh
    script='if command -v curl >/dev/null 2>&1; then curl -fsSL "$0" | sh; else wget -qO- "$0" | sh; fi'
    if [ -n "$RUN_AS" ]; then
        # shellcheck disable=SC2024 # the log belongs to root; only the installer runs as $RUN_AS
        sudo -u "$RUN_AS" -H env "$@" sh -c "$script" "$INSTALLER_URL" >"$LOG" 2>&1
    else
        env "$@" sh -c "$script" "$INSTALLER_URL" >"$LOG" 2>&1
    fi
}

# expect_ok DESC VAR=value... : the one-liner must exit 0.
expect_ok() {
    eo_desc=$1
    shift
    if oneliner "$@"; then
        pass "$eo_desc"
    else
        fail "$eo_desc" "$(tail -n 25 "$LOG")"
    fi
}

# expect_refusal DESC PATTERN VAR=value... : the one-liner must exit non-zero
# and say why.
expect_refusal() {
    er_desc=$1
    er_pattern=$2
    shift 2
    if oneliner "$@"; then
        fail "$er_desc" "installer exited 0: $(tail -n 10 "$LOG")"
    elif grep -q -- "$er_pattern" "$LOG"; then
        pass "$er_desc"
    else
        fail "$er_desc" "exited non-zero without '$er_pattern': $(tail -n 10 "$LOG")"
    fi
}

expect_log() { # expect_log DESC PATTERN
    if grep -q -- "$2" "$LOG"; then pass "$1"; else fail "$1" "$(tail -n 10 "$LOG")"; fi
}

expect_version() { # expect_version BIN VERSION DESC
    ev_got=$("$1" version 2>/dev/null | head -n 1)
    if [ "$ev_got" = "kite-collector $2" ]; then
        pass "$3 ($ev_got)"
    else
        fail "$3" "expected 'kite-collector $2', got '$ev_got'"
    fi
}

# ── preconditions ────────────────────────────────────────────────────────
# The one-liner needs a downloader and nothing else; install only that, so
# anything else the installer relies on has to come from the base image.
echo "  preparing $LEG"
case "$LEG" in
    debian | ubuntu)
        apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl >/dev/null
        ;;
    fedora | almalinux)
        command -v curl >/dev/null 2>&1 || dnf install -y -q curl >/dev/null
        ;;
    opensuse)
        command -v curl >/dev/null 2>&1 || zypper --non-interactive --quiet install curl >/dev/null
        ;;
    alpine | arch) ;;
esac
if [ "$LEG" = ubuntu ]; then
    # Non-root through sudo: every privileged step has to go through $SUDO,
    # including the files the installer writes under /etc and /usr/share.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null
    useradd -m kite
    echo 'kite ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/kite
    RUN_AS=kite
fi
if [ "$LEG" = alpine ] && command -v curl >/dev/null 2>&1; then
    fail "alpine leg has no curl" "the image gained curl, so busybox wget is no longer what gets tested"
fi

case "$LEG" in
    debian | ubuntu) METHOD=apt BIN=/usr/bin/kite-collector ;;
    fedora | almalinux | opensuse) METHOD=rpm BIN=/usr/bin/kite-collector ;;
    *) METHOD=binary BIN=/usr/local/bin/kite-collector ;;
esac

# The default flavor (KITE_OSQUERY=auto) is the osquery bundle wherever it is
# published, Debian/Ubuntu amd64. The ubuntu leg starts from a deliberately
# plain install instead, to prove default re-runs do not swap it.
EXPECT_PKG=kite-collector
if [ "$METHOD" = apt ] && [ "$LEG" != ubuntu ] && [ "$(dpkg --print-architecture)" = amd64 ]; then
    EXPECT_PKG=kite-collector-osquery
fi

expect_owner() { # expect_owner PKG : the package manager says PKG owns $BIN
    case "$METHOD" in
        apt)
            eo_owner=$(dpkg -S "$BIN" 2>/dev/null)
            eo_owner=${eo_owner%%:*}
            ;;
        rpm) eo_owner=$(rpm -qf --qf '%{NAME}' "$BIN" 2>/dev/null) ;;
    esac
    if [ "$eo_owner" = "$1" ]; then pass "$1 owns $BIN"; else fail "$1 owns $BIN" "owner: $eo_owner"; fi
}

# ── live: the real latest release ────────────────────────────────────────
if [ "$MODE" = live ]; then
    expect_ok "one-liner installs the latest release"
    expect_log "picked the $METHOD method" "using $METHOD"
    expect_log "picked $EXPECT_PKG" "Installing $EXPECT_PKG "
    expect_version "$BIN" "$LIVE_VERSION" "installed binary is the latest release"
    [ "$METHOD" = binary ] || expect_owner "$EXPECT_PKG"
    expect_ok "re-running the one-liner is a no-op success"
    expect_version "$BIN" "$LIVE_VERSION" "still the latest release after re-run"
    echo "== $LEG: $PASSES passed, $FAILS failed =="
    [ "$FAILS" -eq 0 ]
    exit
fi

# ── install, upgrade, re-run ─────────────────────────────────────────────
if [ "$LEG" = ubuntu ]; then
    expect_ok "pinned plain install (KITE_VERSION=$OLD_VERSION KITE_OSQUERY=no)" \
        KITE_VERSION="$OLD_VERSION" KITE_OSQUERY=no
else
    expect_ok "pinned install, default flavor (KITE_VERSION=$OLD_VERSION)" KITE_VERSION="$OLD_VERSION"
fi
expect_log "picked the $METHOD method" "using $METHOD"
expect_log "picked $EXPECT_PKG" "Installing $EXPECT_PKG "
expect_version "$BIN" "$OLD_VERSION" "binary reports the pinned version"
expect_log "prints the next step" "kite-collector install"
if [ -n "$RUN_AS" ]; then
    expect_log "privileged commands went through sudo" "^+ sudo "
fi
case "$LEG" in
    debian) [ "$EXPECT_PKG" = kite-collector ] || expect_log "names the kite-osqueryd service" "kite-osqueryd" ;;
    fedora | almalinux | opensuse) expect_log "points at osquery where no bundle is published" "osquery.io/downloads" ;;
    arch) expect_log "points at Arch's osquery package" "pacman -S osquery" ;;
    alpine)
        # osquery has no musl build, so there is nothing to point at.
        if grep -q osquery "$LOG"; then fail "no osquery hint on musl" "$(grep osquery "$LOG")"; else pass "no osquery hint on musl"; fi
        ;;
esac

expect_ok "unpinned re-run upgrades"
expect_version "$BIN" "$NEW_VERSION" "binary reports the latest version"
[ "$METHOD" = binary ] || expect_owner "$EXPECT_PKG"

expect_ok "second unpinned re-run succeeds"
expect_version "$BIN" "$NEW_VERSION" "version unchanged by the re-run"
[ "$LEG" != ubuntu ] || expect_log "default re-run keeps the plain install" "keeping the installed plain kite-collector"

if [ -n "$(find /tmp -maxdepth 1 -type d -name 'tmp.*' 2>/dev/null)" ]; then
    fail "installer cleans up its temp directory" "$(find /tmp -maxdepth 1 -type d -name 'tmp.*')"
else
    pass "installer cleans up its temp directory"
fi

case "$METHOD" in
    apt)
        want="deb [signed-by=/usr/share/keyrings/kite-collector-keyring.asc] $FIXTURE_URL/apt/ stable main"
        got=$(cat /etc/apt/sources.list.d/kite-collector.list 2>/dev/null)
        if [ "$got" = "$want" ]; then pass "source list matches the README line"; else fail "source list matches the README line" "$got"; fi
        # shellcheck disable=SC2012
        key_mode=$(ls -l /usr/share/keyrings/kite-collector-keyring.asc 2>/dev/null | cut -c1-10)
        if [ "$key_mode" = "-rw-r--r--" ]; then pass "keyring is world-readable (apt's _apt sandbox)"; else fail "keyring mode" "$key_mode"; fi
        n=$(grep -rhs "$FIXTURE_URL/apt" /etc/apt/sources.list /etc/apt/sources.list.d | wc -l)
        if [ "$n" -eq 1 ]; then pass "re-runs leave exactly one source entry"; else fail "re-runs leave exactly one source entry" "found $n"; fi
        expect_refusal "a version the archive does not serve is refused with a hint" \
            "three newest releases" KITE_VERSION=9.9.9
        ;;
    rpm)
        expect_log "same-version re-run skips the package manager" "is already installed"
        ;;
    binary)
        if [ ! -e /usr/local/bin/.kite-collector.new ]; then pass "no staging file left behind"; else fail "no staging file left behind"; fi
        ;;
esac

# ── explicit flavor swaps (apt, amd64) ───────────────────────────────────
if [ "$LEG" = ubuntu ] && [ "$(dpkg --print-architecture)" = amd64 ]; then
    expect_ok "KITE_OSQUERY=yes swaps in the bundle" KITE_OSQUERY=yes
    expect_owner kite-collector-osquery
    expect_ok "default re-run keeps the bundle"
    expect_owner kite-collector-osquery
    expect_ok "KITE_OSQUERY=no swaps back to the plain collector" KITE_OSQUERY=no
    expect_owner kite-collector
    expect_version "$BIN" "$NEW_VERSION" "binary still runs after both swaps"
fi

# ── refusals (alpine: cheapest image, and the busybox wget + ash path) ───
if [ "$LEG" = alpine ]; then
    # Compared by hash: the tampered binary still runs and reports the same
    # version, so a version check cannot tell the two apart.
    before=$(sha256sum "$BIN")
    expect_refusal "tampered binary is refused" "checksum mismatch" \
        KITE_RELEASES_URL="$FIXTURE_URL/tampered"
    if [ "$(sha256sum "$BIN")" = "$before" ]; then
        pass "tampered download left the installed binary untouched"
    else
        fail "tampered download left the installed binary untouched" "$BIN was replaced"
    fi

    expect_refusal "unknown release is refused" "release v9.9.9 exists" KITE_VERSION=9.9.9
    expect_refusal "unreachable release server is refused" "could not download" \
        KITE_RELEASES_URL=http://127.0.0.1:9/releases
    expect_refusal "shell metacharacters in KITE_VERSION are refused" "KITE_VERSION must look like" \
        "KITE_VERSION=1.0;id"
    expect_refusal "unknown KITE_INSTALL_METHOD is refused" "KITE_INSTALL_METHOD must be" \
        KITE_INSTALL_METHOD=snap
    expect_refusal "KITE_OSQUERY=yes is refused where no bundle is published" \
        "only published for Debian/Ubuntu amd64" KITE_OSQUERY=yes
    expect_refusal "unknown KITE_OSQUERY value is refused" "KITE_OSQUERY must be" KITE_OSQUERY=maybe

    mkdir -p /tmp/fakeuname
    # shellcheck disable=SC2016 # a script body, expanded when it runs
    printf '#!/bin/sh\n[ "${1:-}" = -m ] && { echo riscv64; exit 0; }\nexec /bin/uname "$@"\n' >/tmp/fakeuname/uname
    chmod +x /tmp/fakeuname/uname
    expect_refusal "unsupported architecture is refused with diagnostics" "architecture riscv64" \
        PATH="/tmp/fakeuname:$PATH"

    # A download cut off anywhere must install nothing: every statement
    # before the final `main "$@"` only defines functions.
    wget -qO /tmp/install.sh "$INSTALLER_URL"
    size=$(wc -c </tmp/install.sh)
    for cut in $((size / 4)) $((size / 2)) $((size * 3 / 4)) $((size - 12)); do
        head -c "$cut" /tmp/install.sh | env KITE_RELEASES_URL="$FIXTURE_URL/releases" \
            KITE_INSTALL_DIR=/opt/truncated sh >"$LOG" 2>&1
        if [ -e /opt/truncated ]; then
            fail "script truncated at byte $cut/$size installs nothing" "$(tail -n 5 "$LOG")"
            rm -rf /opt/truncated
        else
            pass "script truncated at byte $cut/$size installs nothing"
        fi
    done

    # Without root, sudo or doas the default target is refused ...
    if su -s /bin/sh nobody -c "wget -qO- $INSTALLER_URL | env KITE_RELEASES_URL=$FIXTURE_URL/releases sh" >"$LOG" 2>&1; then
        fail "non-root without sudo/doas is refused" "installer exited 0"
    else
        expect_log "non-root without sudo/doas is refused" "needs root"
    fi
    # ... but a directory that user can write needs no root at all.
    if su -s /bin/sh nobody -c "wget -qO- $INSTALLER_URL | env KITE_RELEASES_URL=$FIXTURE_URL/releases KITE_INSTALL_DIR=/tmp/nobody-bin sh" >"$LOG" 2>&1; then
        pass "rootless install into a writable KITE_INSTALL_DIR"
    else
        fail "rootless install into a writable KITE_INSTALL_DIR" "$(tail -n 10 "$LOG")"
    fi
    expect_version /tmp/nobody-bin/kite-collector "$NEW_VERSION" "rootless binary runs"
fi

echo "== $LEG: $PASSES passed, $FAILS failed =="
[ "$FAILS" -eq 0 ]
