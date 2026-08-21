#!/usr/bin/env bash
# Build the kite-collector Windows MSI from cmd/kite-collector/wix.wxs.
#
# Intended for local developers wanting to build or test the MSI without
# attaching it to a GitHub release.
#
# Inputs:
#   $1  version       e.g. "1.2.3"   (defaults to "0.0.0-dev")
#   $2  short commit  e.g. "abc1234" (defaults to "dev")
#   $3  optional "--with-osquery" — build the bundle variant that also
#       installs osqueryd as the kite-osqueryd Windows service. The osquery
#       payload is harvested from the official osquery MSI (pinned version +
#       SHA256 below), downloaded once into dist/cache/ and verified on
#       every run.
#
# Expects:
#   - wixl on PATH (apt install msitools / brew install msitools)
#   - msiextract on PATH for --with-osquery (same msitools package)
#   - dist/kite-collector_windows_amd64_v1/kite-collector.exe present
#     (laid down by goreleaser, or manually for local builds via
#     `make build` which writes to bin/kite-collector_windows_amd64.exe;
#     the script auto-discovers either layout).
#
# Output:
#   dist/kite-collector_<version>_amd64.msi            (default)
#   dist/kite-collector-osquery_<version>_amd64.msi    (--with-osquery)
#
# wixl notes:
#   wixl is the WiX toolset's Linux port via msitools. It accepts a subset
#   of WiX 3.x — all features used by wix.wxs (ServiceInstall, MajorUpgrade,
#   File, Shortcut, RegistryValue, Permission) are supported. If the wxs
#   gains a feature wixl doesn't grok (e.g. Bundle elements, WiX 4 schema),
#   you'll see "Error: unhandled element" and need to either rewrite or
#   switch to the Windows-native candle/light toolchain in CI.

set -euo pipefail

VERSION="${1:-0.0.0-dev}"
SHORT_COMMIT="${2:-dev}"
WITH_OSQUERY=0
if [[ "${3:-}" == "--with-osquery" ]]; then
  WITH_OSQUERY=1
elif [[ -n "${3:-}" ]]; then
  echo "error: unknown argument '${3}' (only --with-osquery is accepted)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# osquery payload pin for the --with-osquery bundle. OSQUERY_VERSION,
# OSQUERY_MSI_SHA256, OSQUERY_MSI_URL and OSQUERY_WINDOWS_PACKS live in the
# shared scripts/osquery-pin.env, which build-deb-osquery.sh and
# stage-osquery-embed.sh source too — one assertion of the pin instead of
# three copies drifting independently (RFC-0156 Phase 1). Bump the pin file,
# never a copy here.
# shellcheck source=scripts/osquery-pin.env
. "$REPO_ROOT/scripts/osquery-pin.env"

# Space-separated in the pin file (it has to stay POSIX-sh sourceable and
# $GITHUB_ENV-exportable); split back into the array the staging loop wants.
read -r -a OSQUERY_PACKS <<< "$OSQUERY_WINDOWS_PACKS"

WXS_SRC="$REPO_ROOT/cmd/kite-collector/wix.wxs"
OUT_DIR="$REPO_ROOT/dist"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! command -v wixl >/dev/null 2>&1; then
  echo "  wixl not on PATH — attempting auto-install" >&2
  case "$(uname -s)" in
    Linux)
      # Noble (24.04) and later ship wixl as a standalone package separate
      # from msitools — install both so the script works on older releases
      # too (msitools used to bundle wixl). Falls back to a clear error if
      # apt-get is missing (non-Debian-family distro).
      if command -v apt-get >/dev/null 2>&1; then
        SUDO=""
        if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
        $SUDO apt-get update
        $SUDO apt-get install -y --no-install-recommends wixl msitools
      else
        echo "error: unsupported Linux distro — install wixl manually" >&2
        exit 1
      fi
      ;;
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        brew install msitools
      else
        echo "error: Homebrew not on PATH — install brew, then 'brew install msitools'" >&2
        exit 1
      fi
      ;;
    *)
      echo "error: wixl auto-install not supported on $(uname -s)" >&2
      echo "  install wixl/msitools manually for your platform." >&2
      exit 1
      ;;
  esac
  if ! command -v wixl >/dev/null 2>&1; then
    echo "error: wixl still not on PATH after install attempt" >&2
    exit 1
  fi
fi

# Locate the Windows binary. Two layouts:
#   - goreleaser CI layout: dist/kite-collector_windows_amd64_v1/kite-collector.exe
#   - Makefile local layout: bin/kite-collector_windows_amd64.exe
EXE_CANDIDATES=(
  "$REPO_ROOT/dist/kite-collector_windows_amd64_v1/kite-collector.exe"
  "$REPO_ROOT/dist/kite-collector_windows_amd64/kite-collector.exe"
  "$REPO_ROOT/bin/kite-collector_windows_amd64.exe"
)
EXE=""
for candidate in "${EXE_CANDIDATES[@]}"; do
  if [[ -f "$candidate" ]]; then
    EXE="$candidate"
    break
  fi
done
if [[ -z "$EXE" ]]; then
  echo "error: could not find kite-collector.exe in any of:" >&2
  printf '  %s\n' "${EXE_CANDIDATES[@]}" >&2
  echo "  Run goreleaser or 'make build' first." >&2
  exit 1
fi
echo "  using exe: $EXE"

# Stage the .exe next to the .wxs so the WiX <File Source="kite-collector.exe">
# resolves correctly. wixl resolves File@Source relative to the .wxs path.
cp "$EXE" "$WORK_DIR/kite-collector.exe"

WIXL_EXTRA_ARGS=()
OUT_BASENAME="kite-collector_${VERSION}_amd64.msi"

if [[ "$WITH_OSQUERY" == "1" ]]; then
  if ! command -v msiextract >/dev/null 2>&1; then
    echo "error: msiextract not on PATH — install msitools (--with-osquery needs it)" >&2
    exit 1
  fi

  # Download the official osquery MSI once into dist/cache/, but verify the
  # pinned SHA256 on EVERY run — a poisoned cache must fail the build, not
  # ship. Download to a temp name so an interrupted curl never poisons the
  # cache with a truncated file.
  CACHE_DIR="$REPO_ROOT/dist/cache"
  mkdir -p "$CACHE_DIR"
  OSQUERY_MSI="$CACHE_DIR/osquery-${OSQUERY_VERSION}.msi"
  if [[ ! -f "$OSQUERY_MSI" ]]; then
    echo "  downloading osquery ${OSQUERY_VERSION} MSI"
    curl -fsSL --retry 3 -o "$OSQUERY_MSI.part" "$OSQUERY_MSI_URL"
    mv "$OSQUERY_MSI.part" "$OSQUERY_MSI"
  fi
  echo "${OSQUERY_MSI_SHA256}  ${OSQUERY_MSI}" | sha256sum -c - >/dev/null || {
    echo "error: osquery MSI failed SHA256 verification — deleting cached copy" >&2
    rm -f "$OSQUERY_MSI"
    exit 1
  }
  echo "  osquery MSI verified: $OSQUERY_MSI"

  # Harvest the payload. msiextract reproduces the official install layout
  # (osquery/osqueryd/osqueryd.exe, osquery/certs/certs.pem, osquery/packs/*)
  # under the extraction root; restage just what the wxs references, plus
  # our own osquery.conf/osquery.flags from configs/osquery/.
  EXTRACT_DIR="$WORK_DIR/osquery-extract"
  mkdir -p "$EXTRACT_DIR"
  msiextract -C "$EXTRACT_DIR" "$OSQUERY_MSI" >/dev/null
  SRC="$EXTRACT_DIR/osquery"
  if [[ ! -f "$SRC/osqueryd/osqueryd.exe" ]]; then
    echo "error: osqueryd.exe not at expected path in the osquery MSI payload" >&2
    echo "  (upstream layout changed? inspect $EXTRACT_DIR)" >&2
    exit 1
  fi

  mkdir -p "$WORK_DIR/osquery/osqueryd" "$WORK_DIR/osquery/certs" "$WORK_DIR/osquery/packs"
  cp "$SRC/osqueryd/osqueryd.exe" "$WORK_DIR/osquery/osqueryd/osqueryd.exe"
  cp "$SRC/certs/certs.pem" "$WORK_DIR/osquery/certs/certs.pem"
  for pack in "${OSQUERY_PACKS[@]}"; do
    cp "$SRC/packs/${pack}.conf" "$WORK_DIR/osquery/packs/${pack}.conf"
  done
  cp "$REPO_ROOT/configs/osquery/osquery.conf" "$WORK_DIR/osquery/osquery.conf"
  cp "$REPO_ROOT/configs/osquery/osquery.flags" "$WORK_DIR/osquery/osquery.flags"

  WIXL_EXTRA_ARGS+=(-D OSQUERY)
  OUT_BASENAME="kite-collector-osquery_${VERSION}_amd64.msi"
  echo "  osquery payload staged (bundle build)"
fi

# Render the wxs with template substitutions. We use simple sed instead of
# pulling in a templating library — wix.wxs only references {{ .Version }}
# and {{ .ShortCommit }} from goreleaser's syntax, and both are scalar.
sed \
  -e "s|{{ \.Version }}|${VERSION}|g" \
  -e "s|{{ \.ShortCommit }}|${SHORT_COMMIT}|g" \
  "$WXS_SRC" > "$WORK_DIR/wix.wxs"

mkdir -p "$OUT_DIR"
OUT_MSI="$OUT_DIR/$OUT_BASENAME"

echo "  building: $OUT_MSI"
wixl --arch x64 ${WIXL_EXTRA_ARGS[@]+"${WIXL_EXTRA_ARGS[@]}"} -o "$OUT_MSI" "$WORK_DIR/wix.wxs"

ls -lh "$OUT_MSI"
echo "  done."
