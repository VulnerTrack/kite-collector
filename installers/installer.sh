#!/bin/sh
# kite-collector installer.
#
# Detects the operating system and installs kite-collector the way that
# system expects it:
#
#   Debian, Ubuntu and derivatives    the signed APT repository, so apt owns
#                                     upgrades from then on (amd64 gets the
#                                     osquery bundle, see KITE_OSQUERY)
#   Fedora, RHEL, SUSE and relatives  the release .rpm, SHA256-verified
#   everything else (Alpine, Arch,    the static release binary,
#   macOS, FreeBSD, OpenBSD, ...)     SHA256-verified, into /usr/local/bin
#
# Environment variables:
#   KITE_VERSION         pin a release, e.g. "0.60.5" (default: latest)
#   KITE_OSQUERY         "auto" (default) installs kite-collector-osquery, the
#                        collector plus a bundled osqueryd running as the
#                        kite-osqueryd service, where it is published
#                        (Debian/Ubuntu amd64) and the plain collector
#                        elsewhere. A re-run keeps whichever of the two is
#                        already installed. "yes" requires the bundle, "no"
#                        installs the plain collector.
#   KITE_INSTALL_METHOD  "auto" (default), "apt", "rpm" or "binary"
#   KITE_INSTALL_DIR     binary method target (default: /usr/local/bin). A
#                        directory you can already write needs no root.
#   KITE_RELEASES_URL    release download base (default: GitHub Releases)
#   KITE_APT_URL         APT repository base (default: GitHub Pages)
#
# Examples:
#   curl -fsSL https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | KITE_VERSION=0.60.5 sh
#   wget -qO- https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | sh
#
# The detect -> privilege -> install shape follows Tailscale's install.sh
# (BSD-3-Clause). tests/e2e/installer pipes this file into `sh` inside real
# distro containers; `make test-installer` runs it.

set -eu

REPO_URL="https://github.com/VulnerTrack/kite-collector"
# Same paths the README's manual APT steps use, so following either one
# after the other rewrites these files instead of adding a duplicate source.
KEYRING=/usr/share/keyrings/kite-collector-keyring.asc
APT_LIST=/etc/apt/sources.list.d/kite-collector.list

say() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# as_root echoes each privileged command before running it, so whoever
# piped this into sh can see exactly what ran as root.
as_root() {
    printf '+ %s%s\n' "${SUDO:+$SUDO }" "$*" >&2
    if [ -n "$SUDO" ]; then
        "$SUDO" "$@"
    else
        "$@"
    fi
}

deb_installed() {
    # shellcheck disable=SC2016 # ${Status} is a dpkg-query format field.
    [ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]
}

# fetch URL [FILE] writes to FILE, or to stdout when FILE is omitted.
fetch() {
    if [ "$DOWNLOADER" = curl ]; then
        if [ $# -gt 1 ]; then
            curl -fsSL --retry 3 -o "$2" "$1"
        else
            curl -fsSL --retry 3 "$1"
        fi
    else
        wget -q -O "${2:--}" "$1"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{ print $NF }'
    else
        die "no SHA256 tool found (sha256sum, shasum, sha256 or openssl)"
    fi
}

# download_verified ASSET fetches ASSET from $RELEASE_BASE into $TMP_DIR and
# fails closed unless it matches the release's checksums.txt. The checksums
# come from the same origin, so this catches truncated and corrupted
# downloads, not a compromised release.
download_verified() {
    dv_expected=$(printf '%s\n' "$CHECKSUMS" | awk -v f="$1" '$2 == f { print $1; exit }')
    [ -n "$dv_expected" ] || die "$1 is not listed in $RELEASE_BASE/checksums.txt"
    say "Downloading $RELEASE_BASE/$1"
    fetch "$RELEASE_BASE/$1" "$TMP_DIR/$1" || die "download failed: $RELEASE_BASE/$1"
    dv_actual=$(sha256_of "$TMP_DIR/$1")
    if [ "$dv_actual" != "$dv_expected" ]; then
        rm -f "$TMP_DIR/$1"
        die "checksum mismatch for $1: expected $dv_expected, got $dv_actual. Refusing to install."
    fi
    say "Verified SHA256 $dv_actual"
}

unsupported() {
    {
        say "kite-collector has no build for this system: $1."
        say "Release builds cover linux, darwin, freebsd and openbsd on amd64 and arm64."
        say ""
        say "If it should work here, open an issue at $REPO_URL/issues"
        say "and include what this installer detected:"
        say ""
        say "KERNEL=$KERNEL"
        say "MACHINE=$MACHINE"
        say "OS_ID=$OS_ID"
        say "OS_LIKE=$OS_LIKE"
        say "UNAME=$(uname -a 2>/dev/null || true)"
        if [ -f /etc/os-release ]; then
            cat /etc/os-release
        fi
    } >&2
    exit 1
}

install_apt() {
    apt_key=$(fetch "$KITE_APT_URL/repository.key") ||
        die "could not download $KITE_APT_URL/repository.key. Check this machine's internet access."
    case "$apt_key" in
        *"BEGIN PGP PUBLIC KEY BLOCK"*) ;;
        *) die "$KITE_APT_URL/repository.key is not an armored OpenPGP key" ;;
    esac

    # apt verifies https peers against this bundle, and minimal images ship
    # without it.
    case "$KITE_APT_URL" in
        https://*)
            if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
                as_root env DEBIAN_FRONTEND=noninteractive apt-get update
                as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates
            fi
            ;;
    esac

    # Staged in TMP_DIR and installed with a mode, instead of `| sudo tee`,
    # so the keyring and list are never world-unreadable or half-written.
    printf '%s\n' "$apt_key" >"$TMP_DIR/repository.key"
    printf 'deb [signed-by=%s] %s/ stable main\n' "$KEYRING" "$KITE_APT_URL" >"$TMP_DIR/kite-collector.list"
    as_root mkdir -p "$(dirname "$KEYRING")" "$(dirname "$APT_LIST")"
    as_root install -m 0644 "$TMP_DIR/repository.key" "$KEYRING"
    as_root install -m 0644 "$TMP_DIR/kite-collector.list" "$APT_LIST"

    # Refresh only this source. A broken or expired third-party repository
    # elsewhere on the host must not fail this install, and neither package
    # depends on anything a Debian-family system lacks.
    as_root env DEBIAN_FRONTEND=noninteractive apt-get update \
        -o Dir::Etc::sourcelist="$APT_LIST" \
        -o Dir::Etc::sourceparts=- \
        -o APT::Get::List-Cleanup=0

    apt_target="$PACKAGE"
    [ -z "$KITE_VERSION" ] || apt_target="$PACKAGE=$KITE_VERSION"
    if ! as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$apt_target"; then
        if [ -n "$KITE_VERSION" ]; then
            die "apt could not install $apt_target. The repository serves the three newest releases; older ones are on $REPO_URL/releases (KITE_INSTALL_METHOD=binary)."
        fi
        die "apt could not install $apt_target"
    fi
    INSTALLED_BIN=/usr/bin/kite-collector
}

install_rpm() {
    rpm_version="$KITE_VERSION"
    if [ -z "$rpm_version" ]; then
        # The rpm file name carries the version, so "latest" has to be read
        # back from the release's own checksums.txt. That avoids the
        # rate-limited GitHub API and works against any static mirror.
        rpm_version=$(printf '%s\n' "$CHECKSUMS" |
            sed -n "s/^[0-9a-f]*  kite-collector_\([^_]*\)_linux_${ARCH}\.rpm\$/\1/p" | head -n 1)
        [ -n "$rpm_version" ] || die "no linux/$ARCH rpm is listed in $RELEASE_BASE/checksums.txt"
    fi

    # rpm -U refuses a same-version reinstall, and dnf/zypper would still
    # download it, so settle the no-op case before any package manager runs.
    if rpm -q kite-collector >/dev/null 2>&1 &&
        [ "$(rpm -q --qf '%{VERSION}' kite-collector)" = "$rpm_version" ]; then
        say "kite-collector $rpm_version is already installed."
    else
        rpm_asset="kite-collector_${rpm_version}_linux_${ARCH}.rpm"
        download_verified "$rpm_asset"
        rpm_file="$TMP_DIR/$rpm_asset"
        if command -v dnf >/dev/null 2>&1; then
            as_root dnf install -y "$rpm_file"
        elif command -v yum >/dev/null 2>&1; then
            as_root yum install -y "$rpm_file"
        elif command -v zypper >/dev/null 2>&1; then
            # The release rpm is unsigned; its SHA256 was checked above.
            as_root zypper --non-interactive install --allow-unsigned-rpm "$rpm_file"
        else
            as_root rpm -U "$rpm_file"
        fi
    fi
    INSTALLED_BIN=/usr/bin/kite-collector
}

install_binary() {
    bin_asset="kite-collector_${GOOS}_${ARCH}_bin"
    download_verified "$bin_asset"

    # Copy beside the target and rename over it. The rename is atomic and
    # works while the old binary is running as a service, where writing into
    # the existing file fails with "Text file busy".
    as_root mkdir -p "$KITE_INSTALL_DIR"
    as_root cp "$TMP_DIR/$bin_asset" "$KITE_INSTALL_DIR/.kite-collector.new"
    as_root chmod 0755 "$KITE_INSTALL_DIR/.kite-collector.new"
    as_root mv -f "$KITE_INSTALL_DIR/.kite-collector.new" "$KITE_INSTALL_DIR/kite-collector"
    INSTALLED_BIN="$KITE_INSTALL_DIR/kite-collector"

    if [ "$KITE_INSTALL_DIR" != /usr/bin ] && [ -x /usr/bin/kite-collector ]; then
        warn "/usr/bin/kite-collector also exists (package-managed?). $INSTALLED_BIN may shadow it on PATH."
    fi
}

# Everything runs from main, called on the last line, so a download cut off
# mid-script is a syntax error instead of half an install.
main() {
    KITE_VERSION="${KITE_VERSION:-}"
    KITE_VERSION="${KITE_VERSION#v}"
    KITE_OSQUERY="${KITE_OSQUERY:-auto}"
    KITE_INSTALL_METHOD="${KITE_INSTALL_METHOD:-auto}"
    KITE_INSTALL_DIR="${KITE_INSTALL_DIR:-/usr/local/bin}"
    KITE_RELEASES_URL="${KITE_RELEASES_URL:-$REPO_URL/releases}"
    KITE_RELEASES_URL="${KITE_RELEASES_URL%/}"
    KITE_APT_URL="${KITE_APT_URL:-https://vulnertrack.github.io/kite-collector}"
    KITE_APT_URL="${KITE_APT_URL%/}"
    SUDO=""

    # The version lands in URLs and in root-run package manager arguments,
    # so anything that is not plainly a version is rejected up front.
    case "$KITE_VERSION" in
        "" | latest) KITE_VERSION="" ;;
        [!0-9]* | *[!0-9A-Za-z.+~-]*)
            die "KITE_VERSION must look like 1.2.3 (got '$KITE_VERSION')"
            ;;
    esac
    case "$KITE_OSQUERY" in
        auto) ;;
        yes | 1 | true) KITE_OSQUERY=yes ;;
        no | 0 | false) KITE_OSQUERY=no ;;
        *) die "KITE_OSQUERY must be auto, yes or no (got '$KITE_OSQUERY')" ;;
    esac
    case "$KITE_INSTALL_METHOD" in
        auto | apt | rpm | binary) ;;
        *) die "KITE_INSTALL_METHOD must be auto, apt, rpm or binary (got '$KITE_INSTALL_METHOD')" ;;
    esac

    # Step 1: detect the platform and pick an install method.
    KERNEL=$(uname -s 2>/dev/null || echo unknown)
    MACHINE=$(uname -m 2>/dev/null || echo unknown)
    OS_ID=""
    OS_LIKE=""
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        OS_ID=$(. /etc/os-release && printf '%s' "${ID:-}")
        # shellcheck source=/dev/null
        OS_LIKE=$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")
    fi

    case "$KERNEL" in
        Linux) GOOS=linux ;;
        Darwin) GOOS=darwin ;;
        FreeBSD) GOOS=freebsd ;;
        OpenBSD) GOOS=openbsd ;;
        *) unsupported "kernel $KERNEL" ;;
    esac
    case "$MACHINE" in
        x86_64 | amd64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) unsupported "architecture $MACHINE" ;;
    esac

    # The family is all that matters: the APT repository is one "stable"
    # suite for every Debian-family release and the rpm is not built per
    # distro, so ID_LIKE covers derivatives without a table mapping each
    # one to an upstream codename.
    FAMILY=binary
    if [ "$GOOS" = linux ]; then
        for os_word in $OS_ID $OS_LIKE; do
            case "$os_word" in
                debian | ubuntu | raspbian) FAMILY=apt ;;
                fedora | rhel | centos | rocky | almalinux | ol | amzn | suse | opensuse | opensuse-* | sles | sle-micro) FAMILY=rpm ;;
                *) continue ;;
            esac
            break
        done
        # /usr is read-only on rpm-ostree systems (Silverblue, CoreOS);
        # /usr/local is not.
        if [ "$FAMILY" = rpm ] && [ -e /run/ostree-booted ]; then
            FAMILY=binary
        fi
    fi

    METHOD="$KITE_INSTALL_METHOD"
    [ "$METHOD" != auto ] || METHOD="$FAMILY"
    dpkg_arch=""

    if [ "$METHOD" = apt ]; then
        command -v apt-get >/dev/null 2>&1 || die "the apt method needs apt-get, which is not installed"
        # shellcheck disable=SC2016 # ${Version} is a dpkg-query format field.
        apt_version=$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)
        dpkg_arch=$(dpkg --print-architecture 2>/dev/null || true)
        apt_blocker=""
        if [ -n "$apt_version" ] && dpkg --compare-versions "$apt_version" lt 1.4; then
            apt_blocker="apt $apt_version cannot read armored signed-by keyrings (needs 1.4+)"
        fi
        case "$dpkg_arch" in
            amd64 | arm64) ;;
            # e.g. a 32-bit Raspberry Pi OS userland on a 64-bit kernel: the
            # repository has no armhf package, but the static arm64 binary runs.
            *) apt_blocker="the repository has no $dpkg_arch packages" ;;
        esac
        if [ -n "$apt_blocker" ]; then
            [ "$KITE_INSTALL_METHOD" = auto ] || die "$apt_blocker"
            say "Note: $apt_blocker; installing the static binary instead."
            METHOD=binary
        fi
    elif [ "$METHOD" = rpm ]; then
        [ "$GOOS" = linux ] || die "the rpm method is only available on Linux"
        command -v rpm >/dev/null 2>&1 || die "the rpm method needs rpm, which is not installed"
    fi

    # Step 2: pick the flavor. kite-collector-osquery is the same collector
    # plus a bundled osqueryd, published only as an amd64 deb. Without it the
    # plain collector still uses any osqueryd listening on a stock socket
    # path, which is what the hint printed at the end sets up.
    PACKAGE=kite-collector
    BUNDLE_PUBLISHED=false
    if [ "$METHOD" = apt ] && [ "$dpkg_arch" = amd64 ]; then
        BUNDLE_PUBLISHED=true
    fi
    case "$KITE_OSQUERY" in
        yes)
            [ "$BUNDLE_PUBLISHED" = true ] ||
                die "KITE_OSQUERY=yes, but kite-collector-osquery is only published for Debian/Ubuntu amd64 and this system installs via $METHOD on $ARCH. Use KITE_OSQUERY=auto for the plain collector, then add osquery separately."
            PACKAGE=kite-collector-osquery
            ;;
        auto)
            if [ "$BUNDLE_PUBLISHED" = true ]; then
                # Upgrade whichever flavor is installed, instead of swapping
                # a deliberately plain install for the bundle on a re-run.
                if deb_installed kite-collector && ! deb_installed kite-collector-osquery; then
                    say "Note: keeping the installed plain kite-collector; set KITE_OSQUERY=yes to switch to the osquery bundle."
                else
                    PACKAGE=kite-collector-osquery
                fi
            fi
            ;;
    esac

    if command -v curl >/dev/null 2>&1; then
        DOWNLOADER=curl
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOADER=wget
    else
        die "this installer needs curl or wget to download files"
    fi

    # Step 3: work out how to run privileged commands. The binary method
    # needs none when the target directory is already writable.
    if [ "$(id -u)" != 0 ]; then
        if [ "$METHOD" = binary ] && mkdir -p "$KITE_INSTALL_DIR" 2>/dev/null && [ -w "$KITE_INSTALL_DIR" ]; then
            :
        elif command -v sudo >/dev/null 2>&1; then
            SUDO=sudo
        elif command -v doas >/dev/null 2>&1; then
            SUDO=doas
        else
            die "this install needs root, and neither sudo nor doas is available. Re-run as root, or set KITE_INSTALL_DIR to a directory you can write."
        fi
    fi

    TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t kite-collector)
    trap 'rm -rf "$TMP_DIR"' EXIT
    trap 'rm -rf "$TMP_DIR"; exit 130' INT TERM

    if [ -n "$KITE_VERSION" ]; then
        RELEASE_BASE="$KITE_RELEASES_URL/download/v$KITE_VERSION"
    else
        RELEASE_BASE="$KITE_RELEASES_URL/latest/download"
    fi

    # Step 4: install.
    say "Installing $PACKAGE ${KITE_VERSION:-(latest)} for ${OS_ID:-$GOOS}/$ARCH using $METHOD"
    case "$METHOD" in
        apt) install_apt ;;
        rpm | binary)
            if ! CHECKSUMS=$(fetch "$RELEASE_BASE/checksums.txt"); then
                if [ -n "$KITE_VERSION" ]; then
                    die "could not download $RELEASE_BASE/checksums.txt. Check this machine's internet access and that release v$KITE_VERSION exists."
                fi
                die "could not download $RELEASE_BASE/checksums.txt. Check this machine's internet access."
            fi
            "install_$METHOD"
            ;;
    esac

    # Step 5: prove the result runs, and is the version that was asked for.
    version_line=$("$INSTALLED_BIN" version 2>/dev/null | head -n 1) || true
    [ -n "$version_line" ] || die "$INSTALLED_BIN was installed but does not run"
    if [ -n "$KITE_VERSION" ] && [ "$version_line" != "kite-collector $KITE_VERSION" ]; then
        die "asked for $KITE_VERSION, but $INSTALLED_BIN reports '$version_line'"
    fi

    say ""
    say "Installed $PACKAGE ($version_line) at $INSTALLED_BIN via $METHOD."
    if [ "$PACKAGE" = kite-collector-osquery ]; then
        if [ -d /run/systemd/system ]; then
            say "The bundled osqueryd runs as the kite-osqueryd systemd service."
        else
            say "The bundled osqueryd ships as the kite-osqueryd systemd unit (not started: systemd is not running)."
        fi
    fi
    bin_dir=$(dirname "$INSTALLED_BIN")
    case ":$PATH:" in
        *":$bin_dir:"*) ;;
        *) warn "$bin_dir is not on PATH; add it, or call $INSTALLED_BIN directly." ;;
    esac
    root_prefix=""
    [ "$(id -u)" = 0 ] || root_prefix="${SUDO:-sudo} "
    say ""
    say "Next, enroll this host and register the background service:"
    say ""
    say "  ${root_prefix}kite-collector install"

    if [ "$KITE_OSQUERY" = auto ] && [ "$PACKAGE" = kite-collector ] && [ "$BUNDLE_PUBLISHED" = false ]; then
        osquery_hint=""
        if [ "$GOOS" = darwin ]; then
            osquery_hint="brew install --cask osquery && sudo kite-collector install --with-osquery"
        elif command -v pacman >/dev/null 2>&1; then
            osquery_hint="${root_prefix}pacman -S osquery && ${root_prefix}systemctl enable --now osqueryd"
        elif [ "$GOOS" = linux ] && ! command -v apk >/dev/null 2>&1; then
            # osquery publishes glibc builds only, so nothing to suggest on musl.
            osquery_hint="install osquery from https://osquery.io/downloads and start osqueryd"
        fi
        if [ -n "$osquery_hint" ]; then
            say ""
            say "No osquery bundle is published for this system. For osquery-backed"
            say "discovery (FIM, YARA, richer inventory), add osquery; kite-collector"
            say "finds a running osqueryd on its own:"
            say ""
            say "  $osquery_hint"
        fi
    fi
}

main "$@"
