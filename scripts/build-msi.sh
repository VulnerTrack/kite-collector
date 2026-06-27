#!/usr/bin/env bash
# Build the kite-collector Windows MSI from cmd/kite-collector/wix.wxs.
#
# Used by:
#   - .github/workflows/kite-collector.yml (release job, after goreleaser)
#   - Local developers wanting to test the MSI without cutting a tag
#
# Inputs:
#   $1  version       e.g. "1.2.3"   (defaults to "0.0.0-dev")
#   $2  short commit  e.g. "abc1234" (defaults to "dev")
#
# Expects:
#   - wixl on PATH (apt install msitools / brew install msitools)
#   - dist/kite-collector_windows_amd64_v1/kite-collector.exe present
#     (laid down by goreleaser, or manually for local builds via
#     `make build` which writes to bin/kite-collector_windows_amd64.exe;
#     the script auto-discovers either layout).
#
# Output:
#   dist/kite-collector_<version>_amd64.msi
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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# Render the wxs with template substitutions. We use simple sed instead of
# pulling in a templating library — wix.wxs only references {{ .Version }}
# and {{ .ShortCommit }} from goreleaser's syntax, and both are scalar.
sed \
  -e "s|{{ \.Version }}|${VERSION}|g" \
  -e "s|{{ \.ShortCommit }}|${SHORT_COMMIT}|g" \
  "$WXS_SRC" > "$WORK_DIR/wix.wxs"

mkdir -p "$OUT_DIR"
OUT_MSI="$OUT_DIR/kite-collector_${VERSION}_amd64.msi"

echo "  building: $OUT_MSI"
wixl --arch x64 -o "$OUT_MSI" "$WORK_DIR/wix.wxs"

ls -lh "$OUT_MSI"
echo "  done."
