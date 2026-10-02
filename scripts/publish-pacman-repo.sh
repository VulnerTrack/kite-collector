#!/usr/bin/env bash
# Rebuild and sign the Kite Collector pacman repository — statelessly.
#
# There is no repo-add incremental database kept between runs: THE os/
# TREE IS THE STATE. Every run copies the currently-published packages
# in, adds this release's .pkg.tar.zst files, prunes to the newest N
# versions per (package, arch), then regenerates every database with
# repo-add and re-signs. Nothing but the published tree has to survive
# between runs, which is what makes this work from an ephemeral runner
# publishing to the same gh-pages branch as scripts/publish-apt-repo.sh.
# os/ sits beside APT's pool/ and dists/; this script never touches those.
#
#   # release publish: accumulate built packages onto the published os/
#   ./scripts/publish-pacman-repo.sh --out public \
#       --pkg-dir ../kite-collector-aur --pool-from /tmp/gh-pages \
#       --sign-key 79847F85E3FF6E43
#
#   # build the AUR PKGBUILD, then index (Arch host / container)
#   ./scripts/publish-pacman-repo.sh --out public \
#       --pkgbuild-dir ../kite-collector-aur --sign-key 79847F85E3FF6E43
#
#   # local, unsigned
#   ./scripts/publish-pacman-repo.sh --out /tmp/pacman-repo \
#       --pkg-dir ../kite-collector-aur
#
# Requires: repo-add, vercmp, bsdtar (all from pacman / libarchive), and
# gpg when --sign-key is given. Arch Linux only — run it in an Arch
# container on other hosts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF_SRC="$REPO_ROOT/packaging/pacman/vulnertrack.conf"

OUT_DIR="public"
PKG_DIRS=()
PKGBUILD_DIRS=()
POOL_FROM=""
SIGN_KEY="${PACMAN_SIGN_KEY:-${APT_SIGN_KEY:-}}"
# Versions retained per (package, architecture) — the stateless equivalent
# of the APT script's KEEP_VERSIONS. Same bound, same reason: GitHub Pages
# is a serving window. Every pkg.tar.zst ever released can still live as a
# GitHub Release asset; pruning here only stops pacman from offering it.
KEEP_VERSIONS="${PACMAN_KEEP_VERSIONS:-3}"
REPO_NAME="${PACMAN_REPO_NAME:-vulnertrack}"
SERVER="${PACMAN_SERVER:-https://vulnertrack.github.io/kite-collector/os/\$arch}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)           OUT_DIR="$2"; shift 2 ;;
    --pkg-dir)       PKG_DIRS+=("$2"); shift 2 ;;
    --pkgbuild-dir)  PKGBUILD_DIRS+=("$2"); shift 2 ;;
    --pool-from)     POOL_FROM="$2"; shift 2 ;;
    --sign-key)      SIGN_KEY="$2"; shift 2 ;;
    --keep)          KEEP_VERSIONS="$2"; shift 2 ;;
    --repo)          REPO_NAME="$2"; shift 2 ;;
    --server)        SERVER="$2"; shift 2 ;;
    -h|--help)       sed -n '2,36p' "$0"; exit 0 ;;
    *)               echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in repo-add vercmp bsdtar; do
  type -P "$tool" >/dev/null 2>&1 || {
    echo "FATAL: $tool not on PATH — this script needs an Arch host (pacman)" >&2
    echo "       or run it inside an Arch container." >&2
    exit 1
  }
done
[[ -f "$CONF_SRC" ]] || { echo "FATAL: missing $CONF_SRC" >&2; exit 1; }

if [[ -n "$SIGN_KEY" ]]; then
  type -P gpg >/dev/null 2>&1 || { echo "FATAL: gpg not on PATH" >&2; exit 1; }
  export GPGKEY="$SIGN_KEY"
fi

# ── 0. optional makepkg ──────────────────────────────────────────────────
# The AUR PKGBUILD is the package definition. Building it here keeps the
# publisher in kite-collector (next to publish-apt-repo.sh) without
# requiring a pre-built pkg.tar.zst. --nocheck: the test suite needs live
# services, same as the PKGBUILD's missing check().
for dir in "${PKGBUILD_DIRS[@]:-}"; do
  [[ -n "$dir" && -d "$dir" ]] || {
    echo "FATAL: --pkgbuild-dir $dir is not a directory" >&2
    exit 1
  }
  [[ -f "$dir/PKGBUILD" ]] || {
    echo "FATAL: $dir has no PKGBUILD" >&2
    exit 1
  }
  echo "  makepkg in $dir"
  (
    cd "$dir"
    extra=(--syncdeps --cleanbuild --force --nocheck --noconfirm)
    [[ -n "$SIGN_KEY" ]] && extra+=(--sign)
    makepkg "${extra[@]}"
  )
  PKG_DIRS+=("$dir")
done

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

# ── 1. seed os/ from what is already published ───────────────────────────
# Wipe only os/, never pool/ or dists/: this archive shares --out with the
# APT publisher. Without --pool-from the regenerated databases describe
# only this run's packages and every previously shipped version becomes
# unfetchable.
rm -rf "$OUT_ABS/os"
mkdir -p "$OUT_ABS/os"

seeded=0
if [[ -n "$POOL_FROM" && -d "$POOL_FROM/os" ]]; then
  while IFS= read -r -d '' archdir; do
    arch="$(basename "$archdir")"
    mkdir -p "$OUT_ABS/os/$arch"
    while IFS= read -r -d '' f; do
      cp -a "$f" "$OUT_ABS/os/$arch/"
      case "$f" in
        *.sig) ;;
        *) seeded=$((seeded + 1)) ;;
      esac
    done < <(find "$archdir" -maxdepth 1 -type f \( \
               -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' -o \
               -name '*.pkg.tar.zst.sig' -o -name '*.pkg.tar.xz.sig' \
             \) -print0 | sort -z)
  done < <(find "$POOL_FROM/os" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
  echo "  seeded os/ from $POOL_FROM ($seeded packages)"
elif [[ -n "$POOL_FROM" ]]; then
  echo "  NOTE: $POOL_FROM has no os/ — starting a fresh archive"
else
  echo "  NOTE: no --pool-from given — databases will describe only new packages"
fi

# ── 2. add this run's packages ───────────────────────────────────────────
pkginfo_field() {
  # .PKGINFO is `key = value`; pacman writes a single arch per package.
  awk -F ' = ' -v k="$1" '$1 == k { print $2; exit }'
}

read_pkginfo() {
  bsdtar -xOf "$1" .PKGINFO
}

place_package() {
  local pkg="$1"
  local info arch dest name
  if ! info="$(read_pkginfo "$pkg" 2>/dev/null)"; then
    echo "  WARN: $pkg has no .PKGINFO — skipped" >&2
    return 0
  fi
  arch="$(pkginfo_field arch <<<"$info")"
  name="$(pkginfo_field pkgname <<<"$info")"
  [[ -n "$arch" && -n "$name" ]] || {
    echo "  WARN: $pkg missing pkgname/arch — skipped" >&2
    return 0
  }

  copy_into() {
    local dest_arch="$1"
    mkdir -p "$OUT_ABS/os/$dest_arch"
    cp -f "$pkg" "$OUT_ABS/os/$dest_arch/$(basename "$pkg")"
    if [[ -f "$pkg.sig" ]]; then
      cp -f "$pkg.sig" "$OUT_ABS/os/$dest_arch/$(basename "$pkg").sig"
    fi
  }

  # `any` packages must appear in every architecture pacman will query
  # (`Server = .../os/$arch`). kite-collector itself is x86_64/aarch64;
  # this branch is for a future keyring package.
  if [[ "$arch" == "any" ]]; then
    copy_into x86_64
    copy_into aarch64
  else
    copy_into "$arch"
  fi
}

added=0
for dir in "${PKG_DIRS[@]:-}"; do
  [[ -n "$dir" && -d "$dir" ]] || continue
  while IFS= read -r pkg; do
    place_package "$pkg"
    added=$((added + 1))
  done < <(find "$dir" -maxdepth 1 -type f \( \
             -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' \
           \) | sort)
done
echo "  added $added package(s) from: ${PKG_DIRS[*]:-<none>}"

total=$(find "$OUT_ABS/os" -type f \( -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' \) | wc -l)
total=${total// /}
[[ "$total" -gt 0 ]] || {
  echo "FATAL: os/ is empty — refusing to publish an empty archive" >&2
  exit 1
}

# ── 3. sign any package that arrived without a .sig ──────────────────────
# makepkg --sign writes the detached signature next to the package;
# packages copied from an unsigned local build get signed here so the
# database and the blobs share one key.
if [[ -n "$SIGN_KEY" ]]; then
  signed=0
  while IFS= read -r pkg; do
    [[ -f "$pkg.sig" ]] && continue
    gpg --batch --yes --detach-sign --digest-algo SHA256 \
        -u "$SIGN_KEY" --output "$pkg.sig" "$pkg"
    signed=$((signed + 1))
  done < <(find "$OUT_ABS/os" -type f \( -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' \) | sort)
  [[ "$signed" -eq 0 ]] || echo "  signed $signed previously-unsigned package(s)"
fi

# ── 4. prune to the newest KEEP_VERSIONS per (package, architecture) ─────
# pacman version ordering is not lexicographic (epochs, pkgrel), so
# comparisons go through vercmp. Insertion sort is fine at this archive's
# size.
if [[ "$KEEP_VERSIONS" -gt 0 ]]; then
  declare -A groups=()
  while IFS= read -r pkg; do
    info="$(read_pkginfo "$pkg")" || continue
    name="$(pkginfo_field pkgname <<<"$info")"
    ver="$(pkginfo_field pkgver <<<"$info")"
    # Directory name, not PKGINFO arch: `any` packages are duplicated into
    # os/x86_64 and os/aarch64 and must prune per dest, not as one bucket.
    arch="$(basename "$(dirname "$pkg")")"
    [[ -n "$name" && -n "$ver" && -n "$arch" ]] || continue
    groups["$name|$arch"]+="$ver:$pkg"$'\n'
  done < <(find "$OUT_ABS/os" -type f \( -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' \) | sort)

  pruned=0
  for key in "${!groups[@]}"; do
    sorted=()
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      ver="${entry%%:*}"
      inserted=0
      for i in "${!sorted[@]}"; do
        if [[ "$(vercmp "$ver" "${sorted[$i]%%:*}")" -gt 0 ]]; then
          sorted=("${sorted[@]:0:$i}" "$entry" "${sorted[@]:$i}")
          inserted=1
          break
        fi
      done
      [[ "$inserted" -eq 1 ]] || sorted+=("$entry")
    done <<<"${groups[$key]}"

    for entry in "${sorted[@]:$KEEP_VERSIONS}"; do
      path="${entry#*:}"
      echo "  prune: ${key%|*} ${entry%%:*} (${key#*|}) — beyond --keep $KEEP_VERSIONS"
      rm -f "$path" "$path.sig"
      pruned=$((pruned + 1))
    done
  done
  [[ "$pruned" -eq 0 ]] && echo "  prune: nothing beyond --keep $KEEP_VERSIONS"
  find "$OUT_ABS/os" -type d -empty -delete
else
  echo "  prune: disabled (--keep 0) — os/ grows without bound"
fi

# ── 5. regenerate every database from os/ ────────────────────────────────
# repo-add is run from scratch so a pruned package disappears without
# bookkeeping, matching apt-ftparchive generate over the APT pool.
indexed=0
shopt -s nullglob
for archdir in "$OUT_ABS"/os/*/; do
  [[ -d "$archdir" ]] || continue
  arch="$(basename "$archdir")"
  pkgs=( "$archdir"*.pkg.tar.zst "$archdir"*.pkg.tar.xz )
  [[ ${#pkgs[@]} -gt 0 ]] || continue

  rm -f "$archdir$REPO_NAME".db* "$archdir$REPO_NAME".files* \
        "$archdir"*.old

  add_opts=(--nocolor --include-sigs)
  if [[ -n "$SIGN_KEY" ]]; then
    add_opts+=(--sign --key "$SIGN_KEY")
  fi
  repo-add "${add_opts[@]}" "$archdir$REPO_NAME.db.tar.zst" "${pkgs[@]}"
  rm -f "$archdir"*.old
  indexed=$((indexed + ${#pkgs[@]}))
  echo "  indexed ${#pkgs[@]} package(s) for $arch"
done
shopt -u nullglob

pooled=$(find "$OUT_ABS/os" -type f \( -name '*.pkg.tar.zst' -o -name '*.pkg.tar.xz' \) | wc -l)
pooled=${pooled// /}
[[ "$indexed" -eq "$pooled" ]] || {
  echo "FATAL: index covers $indexed of $pooled pooled packages — refusing to publish" >&2
  exit 1
}

# ── 6. export the key and the client snippet ─────────────────────────────
# repository.key lives at the archive root so APT and pacman clients fetch
# the same file. vulnertrack.pacman.conf is the Include= drop-in.
if [[ -n "$SIGN_KEY" ]]; then
  gpg --armor --export "$SIGN_KEY" > "$OUT_ABS/repository.key"
  echo "  signed with $SIGN_KEY (packages + $REPO_NAME.db, repository.key exported)"
else
  echo "  NOT SIGNED (no --sign-key) — pacman will reject this archive unless"
  echo "  the client sets SigLevel = Never. Intended for local testing only."
fi

# Rewrite only the Server line so a custom --server (R2, arch.vulnertrack.dev)
# does not require a second checked-in snippet. $arch must stay literal for
# pacman to expand it.
awk -v server="$SERVER" '
  /^Server = / { print "Server = " server; next }
  { print }
' "$CONF_SRC" > "$OUT_ABS/vulnertrack.pacman.conf"

echo "  archive: $OUT_ABS ($pooled packages in os/, repo [$REPO_NAME])"
echo "  Server  = $SERVER"
