#!/usr/bin/env bash
# Rebuild and sign the Kite Collector APT repository — statelessly.
#
# There is no reprepro Berkeley DB and no aptly LevelDB here: THE POOL IS
# THE STATE. Every run copies the currently-published pool in, adds this
# release's debs, prunes to the newest N versions per (package, arch), then
# regenerates every index from the accumulated pool with apt-ftparchive and
# re-signs. Nothing but the published tree has to survive between runs,
# which is what makes this work from an ephemeral runner publishing to a
# gh-pages branch — the two database-backed tools would need their state
# committed alongside the archive, and a binary DB in git corrupts the
# moment two releases race.
#
#   # release publish: accumulate dist/*.deb onto the published pool
#   ./scripts/publish-apt-repo.sh --out public --deb-dir dist \
#       --pool-from /tmp/gh-pages --sign-key 79847F85E3FF6E43
#
#   # nightly re-sign: no new debs, just refresh Date:/Valid-Until:
#   ./scripts/publish-apt-repo.sh --out public \
#       --pool-from /tmp/gh-pages --sign-key 79847F85E3FF6E43
#
#   # local, unsigned (tests/e2e/apt-repo drives this inside a container)
#   ./scripts/publish-apt-repo.sh --out /tmp/repo --deb-dir dist
#
# Requires: apt-ftparchive (apt-utils), dpkg-deb + dpkg (dpkg-dev), gzip,
# xz, and gpg when --sign-key is given. Debian/Ubuntu only — run it in a
# container on other hosts (that is what the e2e battery does).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FTPARCHIVE_CONF="$REPO_ROOT/packaging/apt/apt-ftparchive.conf"

OUT_DIR="public"
DEB_DIRS=()
POOL_FROM=""
SIGN_KEY="${APT_SIGN_KEY:-}"
# Valid-Until window. 30 days is short enough that a frozen-archive replay
# (an attacker pinning clients to a Release that predates a security fix)
# expires on its own, and long enough that the nightly re-sign
# (.github/workflows/apt-repo-refresh.yml) can fail unnoticed for four
# weeks before any client breaks. Both properties matter: once Valid-Until
# passes, `apt update` fails HARD on every deployed host, so this number is
# the grace period for noticing a broken refresh job.
VALID_DAYS="${APT_VALID_DAYS:-30}"
# Versions retained per (package, architecture) — the stateless equivalent
# of reprepro's `Limit:`. Bounds the pool, which is the one thing
# statelessness does not bound on its own.
#
# Why 3. GitHub Pages soft-caps a published site at 1 GB, and one release
# contributes roughly 80 MB of debs (collector ~13 MB × amd64/arm64, plus
# the osquery bundle at ~55 MB for amd64). Three versions is ~240 MB, which
# leaves real headroom and keeps the nightly re-sign's pool clone cheap,
# while still covering what the pool is actually for: rolling back to the
# previous release and pinning during a staged rollout.
#
# This is a SERVING window, not an archive. Every deb ever released stays
# downloadable as a GitHub Release asset — pruning here only stops apt from
# offering it, it does not destroy the artifact.
KEEP_VERSIONS="${APT_KEEP_VERSIONS:-3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)         OUT_DIR="$2"; shift 2 ;;
    --deb-dir)     DEB_DIRS+=("$2"); shift 2 ;;
    --pool-from)   POOL_FROM="$2"; shift 2 ;;
    --sign-key)    SIGN_KEY="$2"; shift 2 ;;
    --valid-days)  VALID_DAYS="$2"; shift 2 ;;
    --keep)        KEEP_VERSIONS="$2"; shift 2 ;;
    -h|--help)     sed -n '2,32p' "$0"; exit 0 ;;
    *)             echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in apt-ftparchive dpkg-deb dpkg gzip xz; do
  type -P "$tool" >/dev/null 2>&1 || {
    echo "FATAL: $tool not on PATH — this script needs a Debian/Ubuntu host" >&2
    echo "       (apt-utils + dpkg-dev), or run it inside a container." >&2
    exit 1
  }
done
[[ -f "$FTPARCHIVE_CONF" ]] || { echo "FATAL: missing $FTPARCHIVE_CONF" >&2; exit 1; }

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

# ── 1. seed the pool from what is already published ──────────────────────
# This is the step that turns a one-shot publish into an accumulating
# archive. Without it the regenerated indices describe only this release's
# debs and every previously shipped version becomes unfetchable — no
# rollback, no version pinning, and `apt install kite-collector=1.2.3`
# fails for anyone following a pinned deployment.
mkdir -p "$OUT_ABS/pool/main"
if [[ -n "$POOL_FROM" && -d "$POOL_FROM/pool" ]]; then
  cp -a "$POOL_FROM/pool/." "$OUT_ABS/pool/"
  echo "  seeded pool from $POOL_FROM ($(find "$OUT_ABS/pool" -name '*.deb' | wc -l) debs)"
elif [[ -n "$POOL_FROM" ]]; then
  # First run against a repository that has no pool/ yet (or the very first
  # publish, where gh-pages does not exist). Not an error, but say so —
  # silence here would look identical to a failed fetch that silently
  # dropped the archive's whole history.
  echo "  NOTE: $POOL_FROM has no pool/ — starting a fresh archive"
else
  echo "  NOTE: no --pool-from given — indices will describe only new debs"
fi

# ── 2. add this run's debs ───────────────────────────────────────────────
# Pool path follows Debian convention: pool/<component>/<prefix>/<source>/,
# prefix being the first letter, or lib<x> for lib* so the lib* population
# does not pile into a single directory.
pool_prefix() {
  case "$1" in
    lib?*) printf 'lib%s' "${1:3:1}" ;;
    *)     printf '%s' "${1:0:1}" ;;
  esac
}

added=0
for dir in "${DEB_DIRS[@]:-}"; do
  [[ -n "$dir" && -d "$dir" ]] || continue
  while IFS= read -r deb; do
    pkg="$(dpkg-deb -f "$deb" Package)"
    [[ -n "$pkg" ]] || { echo "  WARN: $deb has no Package field — skipped" >&2; continue; }
    dest="$OUT_ABS/pool/main/$(pool_prefix "$pkg")/$pkg"
    mkdir -p "$dest"
    cp -f "$deb" "$dest/$(basename "$deb")"
    added=$((added + 1))
  done < <(find "$dir" -maxdepth 1 -name '*.deb' -type f | sort)
done
echo "  added $added deb(s) from: ${DEB_DIRS[*]:-<none>}"

total=$(find "$OUT_ABS/pool" -name '*.deb' -type f | wc -l)
[[ "$total" -gt 0 ]] || { echo "FATAL: pool is empty — refusing to publish an empty archive" >&2; exit 1; }

# ── 3. prune to the newest KEEP_VERSIONS per (package, architecture) ─────
# Debian version ordering is not lexicographic and not `sort -V` (epochs,
# `~` pre-release ordering), so comparisons go through
# `dpkg --compare-versions`. Insertion sort is fine at this archive's size
# and avoids depending on any external sort semantics.
if [[ "$KEEP_VERSIONS" -gt 0 ]]; then
  declare -A groups=()
  while IFS= read -r deb; do
    meta="$(dpkg-deb -f "$deb" Package Version Architecture)"
    pkg="$(awk '/^Package:/{print $2}' <<<"$meta")"
    ver="$(awk '/^Version:/{print $2}' <<<"$meta")"
    arch="$(awk '/^Architecture:/{print $2}' <<<"$meta")"
    [[ -n "$pkg" && -n "$ver" && -n "$arch" ]] || continue
    groups["$pkg|$arch"]+="$ver:$deb"$'\n'
  done < <(find "$OUT_ABS/pool" -name '*.deb' -type f | sort)

  pruned=0
  for key in "${!groups[@]}"; do
    sorted=()
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      ver="${entry%%:*}"
      inserted=0
      for i in "${!sorted[@]}"; do
        if dpkg --compare-versions "$ver" gt "${sorted[$i]%%:*}"; then
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
      rm -f "$path"
      pruned=$((pruned + 1))
    done
  done
  [[ "$pruned" -eq 0 ]] && echo "  prune: nothing beyond --keep $KEEP_VERSIONS"
  find "$OUT_ABS/pool" -type d -empty -delete
else
  echo "  prune: disabled (--keep 0) — pool grows without bound"
fi

# ── 4. regenerate every index from the pool ──────────────────────────────
# `generate` rescans the pool from scratch, so a pruned deb disappears from
# Packages without any bookkeeping. The dists/ tree is rebuilt rather than
# patched, for the same reason.
rm -rf "$OUT_ABS/dists"
mkdir -p "$OUT_ABS/dists/stable/main/binary-amd64" \
         "$OUT_ABS/dists/stable/main/binary-arm64"

# Run from inside the archive root rather than passing
# -o Dir::ArchiveDir=... — `generate` reads its positional config file INTO
# the config tree after command-line -o options are applied, so the conf's
# own `ArchiveDir "."` wins and the override is silently discarded. That
# failure mode is nasty: apt-ftparchive walks the wrong tree, prints
# `E: Tree walking failed - ftw`, and still EXITS 0, so `set -e` does not
# catch it and the run continues on to sign an empty archive.
#
# Contents=false is passed here rather than in the conf for the same
# reason, one layer up: a top-level APT::FTPArchive::* switch inside the
# positional config file is ignored, while the identical setting as -o
# takes effect. Both behaviours are asserted by tests/e2e/apt-repo.
( cd "$OUT_ABS" \
  && apt-ftparchive -o APT::FTPArchive::Contents=false generate "$FTPARCHIVE_CONF" )

# Guard the exit-0-on-error behaviour above: every deb in the pool must
# appear in exactly one binary-<arch>/Packages. This is the invariant the
# whole archive rests on, and it catches an empty index, a pool the walker
# could not read, and a deb misfiled into the wrong architecture.
indexed=$(grep -ch '^Package: ' "$OUT_ABS"/dists/stable/main/binary-*/Packages 2>/dev/null \
          | awk '{n += $1} END {print n + 0}')
pooled=$(find "$OUT_ABS/pool" -name '*.deb' -type f | wc -l)
[[ "$indexed" -eq "$pooled" ]] || {
  echo "FATAL: index covers $indexed of $pooled pooled debs — refusing to sign" >&2
  echo "       (apt-ftparchive exits 0 on a failed tree walk; check its E: lines above)" >&2
  exit 1
}
echo "  indexed $indexed/$pooled pooled debs across amd64+arm64"

# Release: Date: comes free, Valid-Until: is Date + ValidTime seconds.
#
# The key is ValidTime, NOT ValidUntil. apt-ftparchive silently ignores
# unrecognised APT::FTPArchive::Release::* keys — verified against apt
# 2.8.3, where both `ValidUntil=<seconds>` and `ValidUntil=<RFC1123 date>`
# produced a Release with NO Valid-Until field and exit status 0. Spelling
# this wrong does not fail the build, it just ships an archive with no
# expiry, which is precisely the replay exposure Valid-Until exists to
# close. tests/e2e/apt-repo asserts the field is present for that reason.
VALID_SECONDS=$((VALID_DAYS * 86400))
release_opts=(-c="$FTPARCHIVE_CONF"
              -o "APT::FTPArchive::Release::ValidTime=$VALID_SECONDS")

# Pin the archive to the signing key. Read the full fingerprint rather than
# echoing back the short key id --sign-key may have been given as: apt
# matches Signed-By against fingerprints, and a short id here is both
# ambiguous and rejected by strict clients.
if [[ -n "$SIGN_KEY" ]]; then
  fpr="$(gpg --batch --with-colons --fingerprint "$SIGN_KEY" 2>/dev/null \
         | awk -F: '/^fpr:/{print $10; exit}')"
  [[ -n "$fpr" ]] || { echo "FATAL: no key in the keyring matches --sign-key $SIGN_KEY" >&2; exit 1; }
  release_opts+=(-o "APT::FTPArchive::Release::Signed-By=$fpr")
fi

apt-ftparchive "${release_opts[@]}" release "$OUT_ABS/dists/stable" \
  > "$OUT_ABS/dists/stable/Release"

grep -qE '^Valid-Until:' "$OUT_ABS/dists/stable/Release" || {
  echo "FATAL: generated Release has no Valid-Until — ValidTime was not applied" >&2
  exit 1
}
echo "  $(grep -E '^Date:' "$OUT_ABS/dists/stable/Release")"
echo "  $(grep -E '^Valid-Until:' "$OUT_ABS/dists/stable/Release") (+${VALID_DAYS}d)"

# ── 5. sign ──────────────────────────────────────────────────────────────
# InRelease (inline signature) is what modern apt fetches; Release.gpg
# (detached) stays for clients that predate it. Both are regenerated every
# run — that is the "re-sign" half of the nightly refresh, and the only
# reason the nightly job exists.
if [[ -n "$SIGN_KEY" ]]; then
  ( cd "$OUT_ABS/dists/stable"
    gpg --batch --yes --clearsign --digest-algo SHA256 -u "$SIGN_KEY" \
        -o InRelease Release
    gpg --batch --yes --detach-sign --digest-algo SHA256 -u "$SIGN_KEY" \
        -o Release.gpg Release )
  # README instructs clients to fetch this as the signed-by keyring.
  gpg --armor --export "$SIGN_KEY" > "$OUT_ABS/repository.key"
  echo "  signed with $SIGN_KEY (InRelease + Release.gpg, repository.key exported)"
else
  echo "  NOT SIGNED (no --sign-key) — apt will reject this archive unless the"
  echo "  client uses [trusted=yes]. Intended for local index testing only."
fi

echo "  archive: $OUT_ABS ($(find "$OUT_ABS/pool" -name '*.deb' -type f | wc -l) debs in pool)"
