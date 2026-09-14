#!/usr/bin/env bash
# One-liner installer battery. Pipes installers/installer.sh into `sh` inside
# stock distro containers, the same way a user runs
# `curl -fsSL <url> | sh`, and checks what it left behind.
#
#   ./tests/e2e/installer/run.sh                    # every leg, local fixture release
#   LEGS="debian alpine" ./tests/e2e/installer/run.sh
#   MODE=live ./tests/e2e/installer/run.sh          # the real latest release
#
# Local mode (the default) never touches the published release. It builds the
# collector twice (OLD_VERSION and NEW_VERSION) and lays both out the way the
# release pipeline does: goreleaser asset names, checksums.txt, and a signed
# APT archive from scripts/publish-apt-repo.sh. Everything is served over
# HTTP on a private docker network, and the installer is pointed at it with
# KITE_RELEASES_URL and KITE_APT_URL. Base images and distro package indexes
# still come from the internet.
#
# Live mode serves only the installer and lets it install the latest real
# release from GitHub, as a post-release smoke test.
#
# `make test-installer` and `make test-installer-live` wrap this. Requires
# docker, plus go in local mode.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$REPO_ROOT/tests/e2e/installer"
INSTALLER="$REPO_ROOT/installers/installer.sh"
MODE="${MODE:-local}"
OLD_VERSION="${OLD_VERSION:-1.0.0}"
NEW_VERSION="${NEW_VERSION:-1.1.0}"

declare -A LEG_IMAGE=(
  [debian]="${IMAGE_DEBIAN:-debian:12}"
  [ubuntu]="${IMAGE_UBUNTU:-ubuntu:24.04}"
  [fedora]="${IMAGE_FEDORA:-fedora:44}"
  [almalinux]="${IMAGE_ALMALINUX:-almalinux:9}"
  [opensuse]="${IMAGE_OPENSUSE:-opensuse/leap:15.6}"
  [alpine]="${IMAGE_ALPINE:-alpine:3.22}"
  [arch]="${IMAGE_ARCH:-archlinux:latest}"
)
case "$MODE" in
  local) LEGS="${LEGS:-debian ubuntu fedora almalinux opensuse alpine arch}" ;;
  live)  LEGS="${LEGS:-debian fedora alpine}" ;;
  *)     echo "MODE must be local or live (got '$MODE')"; exit 2 ;;
esac
for leg in $LEGS; do
  [[ -n "${LEG_IMAGE[$leg]:-}" ]] || { echo "unknown leg '$leg' (have: ${!LEG_IMAGE[*]})"; exit 2; }
done

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported docker host architecture $(uname -m)"; exit 2 ;;
esac

# ── guards ───────────────────────────────────────────────────────────────
# The installer hard-codes names that other files own. A green battery
# against the fixture proves nothing if the real release is named
# differently, so assert each coupling at its source.
[[ -s "$INSTALLER" ]] || { echo "DRIFT: $INSTALLER is missing or empty"; exit 1; }
sh -n "$INSTALLER" || { echo "installer does not parse as sh"; exit 1; }

GR="$REPO_ROOT/.goreleaser.yaml"
for needle in \
  'name_template: "kite-collector_{{ .Os }}_{{ .Arch }}_bin"' \
  'name_template: "checksums.txt"' \
  'package_name: kite-collector' \
  'bindir: /usr/bin' \
  '- rpm'; do
  grep -qF -- "$needle" "$GR" || { echo "DRIFT: '$needle' missing from .goreleaser.yaml"; exit 1; }
done
# rpm assets are found as kite-collector_<version>_linux_<arch>.rpm, which is
# goreleaser's default nfpm file name. A custom template breaks that.
if grep -qE '^\s*file_name_template:' "$GR"; then
  echo "DRIFT: .goreleaser.yaml sets an nfpm file_name_template; update install_rpm in installers/installer.sh"
  exit 1
fi
# shellcheck disable=SC2016 # literal source lines, not expansions
for needle in \
  'bin_asset="kite-collector_${GOOS}_${ARCH}_bin"' \
  'rpm_asset="kite-collector_${rpm_version}_linux_${ARCH}.rpm"' \
  'checksums.txt' \
  'KEYRING=/usr/share/keyrings/kite-collector-keyring.asc' \
  'APT_LIST=/etc/apt/sources.list.d/kite-collector.list' \
  '/ stable main'; do
  grep -qF -- "$needle" "$INSTALLER" || { echo "DRIFT: '$needle' missing from installers/installer.sh"; exit 1; }
done
# The README's manual APT steps write the same two files the installer does.
for needle in \
  '/usr/share/keyrings/kite-collector-keyring.asc' \
  '/etc/apt/sources.list.d/kite-collector.list' \
  'https://vulnertrack.github.io/kite-collector/ stable main'; do
  grep -qF -- "$needle" "$REPO_ROOT/README.md" || { echo "DRIFT: '$needle' missing from README.md"; exit 1; }
done
# The fixture's stand-in bundle mirrors how the real one swaps with the plain
# package; the installer's flavor logic depends on exactly that.
for needle in 'name: kite-collector-osquery' 'conflicts:' 'replaces:' 'provides:'; do
  grep -qF -- "$needle" "$REPO_ROOT/packaging/deb/nfpm-osquery.yaml" \
    || { echo "DRIFT: '$needle' missing from packaging/deb/nfpm-osquery.yaml"; exit 1; }
done
grep -qF 'Suite "stable"' "$REPO_ROOT/packaging/apt/apt-ftparchive.conf" \
  || { echo "DRIFT: the APT archive no longer publishes a 'stable' suite"; exit 1; }
echo "  drift guard: installer asset names, APT paths and suite agree with goreleaser, README and the archive config"

# Linting as POSIX sh also catches bashisms that dash and busybox ash would
# only trip over at runtime.
if type -P shellcheck >/dev/null 2>&1; then
  shellcheck -s sh "$INSTALLER" "$HERE/battery.sh"
else
  docker run --rm -v "$INSTALLER:/installer.sh:ro" -v "$HERE/battery.sh:/battery.sh:ro" \
    koalaman/shellcheck:v0.11.0 -s sh /installer.sh /battery.sh
fi
echo "  shellcheck -s sh: clean"

# ── fixture ──────────────────────────────────────────────────────────────
FIXTURE="$REPO_ROOT/dist/installer-fixture"
RUN_ID="kite-installer-$$"
NET="$RUN_ID"
SERVER="$RUN_ID-fixture"

cleanup() {
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$FIXTURE"
mkdir -p "$FIXTURE"
cp "$INSTALLER" "$FIXTURE/install.sh"

LIVE_VERSION=""
if [[ "$MODE" == local ]]; then
  # Same nfpm pin as the other package builds; bump them together there.
  NFPM_VERSION="$(sed -n 's/^NFPM_VERSION="\(.*\)"$/\1/p' "$REPO_ROOT/scripts/build-deb-collector.sh")"
  [[ -n "$NFPM_VERSION" ]] || { echo "DRIFT: no NFPM_VERSION pin in scripts/build-deb-collector.sh"; exit 1; }
  run_nfpm() {
    if type -P nfpm >/dev/null 2>&1; then
      nfpm "$@"
    else
      go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" "$@"
    fi
  }

  for ver in "$OLD_VERSION" "$NEW_VERSION"; do
    build="$FIXTURE/build/$ver"
    rel="$FIXTURE/releases/download/v$ver"
    mkdir -p "$build" "$rel"
    echo "  building kite-collector $ver (linux/$ARCH)"
    (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
      go build -trimpath -ldflags="-s -w -X main.version=$ver" \
      -o "$build/kite-collector" ./cmd/kite-collector)
    ln "$build/kite-collector" "$rel/kite-collector_linux_${ARCH}_bin"

    # The release deb/rpm come from goreleaser's nfpms block; this renders the
    # mirrored packaging/deb/nfpm-collector.yaml that tests/e2e/deb-collector
    # already guards against drift.
    sed -e "s|{{ .Version }}|$ver|g" \
        -e "s|{{ .Arch }}|$ARCH|g" \
        -e "s|{{ .Staging }}|$build|g" \
      "$REPO_ROOT/packaging/deb/nfpm-collector.yaml" > "$build/nfpm.yaml"
    for fmt in deb rpm; do
      (cd "$REPO_ROOT" && run_nfpm package -f "$build/nfpm.yaml" -p "$fmt" \
        -t "$rel/kite-collector_${ver}_linux_${ARCH}.$fmt" >/dev/null)
    done
  done

  echo "  assembling checksums, latest/, tampered release and signed APT archive"
  docker run --rm \
    -e OLD_VERSION="$OLD_VERSION" -e NEW_VERSION="$NEW_VERSION" -e ARCH="$ARCH" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$FIXTURE:/fixture" \
    -v "$REPO_ROOT:/src:ro" \
    debian:12 bash /src/tests/e2e/installer/fixture.sh
else
  LIVE_VERSION="$(curl -fsSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/checksums.txt \
    | sed -n "s/^[0-9a-f]*  kite-collector_\([^_]*\)_linux_${ARCH}\.deb\$/\1/p" | head -n 1)"
  [[ -n "$LIVE_VERSION" ]] || { echo "could not read the latest release version from checksums.txt"; exit 1; }
  echo "  live: latest release is $LIVE_VERSION"
fi

docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --network "$NET" \
  -v "$FIXTURE:/srv:ro" busybox:1.37 httpd -f -p 8080 -h /srv >/dev/null
FIXTURE_URL="http://$SERVER:8080"
for _ in $(seq 1 30); do
  docker run --rm --network "$NET" busybox:1.37 \
    wget -q -O /dev/null "$FIXTURE_URL/install.sh" 2>/dev/null && break
  sleep 1
done

# ── legs ─────────────────────────────────────────────────────────────────
passed=()
failed=()
for leg in $LEGS; do
  image="${LEG_IMAGE[$leg]}"
  echo
  echo "== leg $leg ($image, $MODE) =="
  if docker run --rm --network "$NET" \
      -e LEG="$leg" -e MODE="$MODE" -e FIXTURE_URL="$FIXTURE_URL" \
      -e OLD_VERSION="$OLD_VERSION" -e NEW_VERSION="$NEW_VERSION" \
      -e LIVE_VERSION="$LIVE_VERSION" \
      -v "$HERE/battery.sh:/battery.sh:ro" \
      "$image" sh /battery.sh; then
    passed+=("$leg")
  else
    failed+=("$leg")
  fi
done

echo
echo "== installer battery ($MODE): ${#passed[@]} leg(s) passed${passed:+: ${passed[*]}}; ${#failed[@]} failed${failed:+: ${failed[*]}} =="
[[ ${#failed[@]} -eq 0 ]]
