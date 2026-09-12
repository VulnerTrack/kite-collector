#!/usr/bin/env bash
# Runs inside a stock debian container. Drives scripts/publish-apt-repo.sh
# through the four shapes it has to survive — first publish, accumulate,
# prune, re-sign-only — and verifies each one with a real apt client over a
# file:// source rather than by grepping the generated files alone.
#
# file:// is deliberate: it exercises the same signature and Valid-Until
# verification path as https, with no web server to flake.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends apt-utils dpkg-dev gnupg ca-certificates >/dev/null

# Drop the distro sources so every later `apt update` talks only to the
# archive under test. Without this, a failure assertion could pass because
# deb.debian.org was unreachable rather than because our Release expired.
mkdir -p /etc/apt/disabled
mv /etc/apt/sources.list /etc/apt/disabled/ 2>/dev/null || true
mv /etc/apt/sources.list.d/* /etc/apt/disabled/ 2>/dev/null || true

# ── throwaway signing key ────────────────────────────────────────────────
export GNUPGHOME=/tmp/gnupg
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' \
    --quick-generate-key "Kite APT Test <apt-test@example.invalid>" default default never
KEY="$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr:/{print $10; exit}')"
[[ -n "$KEY" ]] || fail "could not create a test signing key"
ok "test signing key $KEY"

# ── fixture debs ─────────────────────────────────────────────────────────
mkdeb() { # mkdeb <pkg> <version> <arch> <outdir>
  local pkg="$1" ver="$2" arch="$3" out="$4" stage
  stage="$(mktemp -d)"
  mkdir -p "$stage/DEBIAN" "$stage/usr/bin"
  cat > "$stage/DEBIAN/control" <<EOF
Package: $pkg
Version: $ver
Architecture: $arch
Maintainer: VulnerTrack <hello@vulnertrack.dev>
Description: apt-repo battery fixture ($pkg $ver $arch)
EOF
  printf '#!/bin/sh\necho %s %s\n' "$pkg" "$ver" > "$stage/usr/bin/$pkg"
  chmod 755 "$stage/usr/bin/$pkg"
  mkdir -p "$out"
  dpkg-deb --build -Znone "$stage" "$out/${pkg}_${ver}_${arch}.deb" >/dev/null
  rm -rf "$stage"
}

mkdir -p /debs-v1 /debs-v2
mkdeb kite-collector         1.0.0 amd64 /debs-v1
mkdeb kite-collector         1.0.0 arm64 /debs-v1
mkdeb kite-collector-osquery 1.0.0 amd64 /debs-v1
mkdeb kite-collector         1.1.0 amd64 /debs-v2
mkdeb kite-collector         1.1.0 arm64 /debs-v2

add_source() { # add_source <repo-abs-path>
  cp "$1/repository.key" /usr/share/keyrings/kite-test.asc
  echo "deb [signed-by=/usr/share/keyrings/kite-test.asc] file://$1 stable main" \
    > /etc/apt/sources.list.d/kite-test.list
}

# ── run 1: first publish, no prior pool ──────────────────────────────────
echo "== run 1: first publish =="
/src/scripts/publish-apt-repo.sh --out /repo1 --deb-dir /debs-v1 --sign-key "$KEY"

REL=/repo1/dists/stable/Release
grep -qE '^Date: '        "$REL" || fail "Release has no Date:"
grep -qE '^Valid-Until: ' "$REL" || fail "Release has no Valid-Until:"
grep -qE '^SHA256:'       "$REL" || fail "Release has no SHA256 block"
grep -qE '^SHA512:'       "$REL" || fail "Release has no SHA512 block"
grep -qE "^Signed-By: $KEY\$" "$REL" || fail "Release Signed-By is not the full fingerprint"
ok "Release carries Date/Valid-Until/SHA256/SHA512/Signed-By"

# The identity fields come from packaging/apt/apt-ftparchive.conf. They are
# asserted separately because `apt-ftparchive release` only sees them if the
# config is actually loaded (-c=), and a Release missing Suite/Codename is
# one apt rejects as mismatching the sources.list entry that points at it.
for field in "Origin: VulnerTrack" "Label: Kite Collector Repo" \
             "Suite: stable" "Codename: stable" "Components: main" \
             "Architectures: amd64 arm64"; do
  grep -qxF "$field" "$REL" || fail "Release is missing '$field' — config not loaded?"
done
ok "Release carries the archive identity fields from the checked-in config"

# Valid-Until must be exactly Date + 30 days (the script's default), which
# is the assertion that would have caught the silently-ignored `ValidUntil`
# spelling: a wrong key yields no field at all, a wrong unit yields a wrong
# delta.
d_date=$(date -u -d "$(sed -n 's/^Date: //p' "$REL")" +%s)
d_till=$(date -u -d "$(sed -n 's/^Valid-Until: //p' "$REL")" +%s)
[[ $((d_till - d_date)) -eq $((30 * 86400)) ]] \
  || fail "Valid-Until - Date is $((d_till - d_date))s, expected $((30 * 86400))s"
ok "Valid-Until is Date + 30d exactly"

# Pool layout and per-arch filing.
[[ -f /repo1/pool/main/k/kite-collector/kite-collector_1.0.0_amd64.deb ]] \
  || fail "deb not filed at pool/main/k/kite-collector/"
grep -q '^Filename: pool/main/k/kite-collector/kite-collector_1.0.0_amd64.deb$' \
  /repo1/dists/stable/main/binary-amd64/Packages \
  || fail "amd64 Packages Filename: does not point into the pool"
grep -q 'arm64' /repo1/dists/stable/main/binary-amd64/Packages \
  && fail "arm64 package leaked into the amd64 index"
grep -q '^Architecture: arm64$' /repo1/dists/stable/main/binary-arm64/Packages \
  || fail "arm64 index is missing its package"
ok "pool layout correct, architectures filed apart"

[[ -f /repo1/dists/stable/InRelease && -f /repo1/dists/stable/Release.gpg ]] \
  || fail "InRelease/Release.gpg not produced"
[[ ! -e /repo1/dists/stable/main/Contents-amd64 ]] || fail "Contents files should be disabled"
ok "InRelease + Release.gpg present, Contents suppressed"

add_source /repo1
apt-get update -qq || fail "apt update rejected the signed archive"
apt-get install -y -qq kite-collector >/dev/null || fail "apt install failed"
[[ "$(dpkg-query -W -f='${Version}' kite-collector)" == "1.0.0" ]] \
  || fail "installed version is not 1.0.0"
apt-get install -y -qq kite-collector-osquery >/dev/null \
  || fail "bundle package not installable from the same archive"
ok "apt update + install of both packages from a signed file:// source"
apt-get remove -y -qq kite-collector-osquery kite-collector >/dev/null 2>&1 || true

# ── run 2: accumulate onto the published pool ────────────────────────────
# /repo1 stands in for the gh-pages checkout the release workflow clones.
echo "== run 2: accumulate =="
/src/scripts/publish-apt-repo.sh --out /repo2 --deb-dir /debs-v2 \
  --pool-from /repo1 --sign-key "$KEY"

[[ -f /repo2/pool/main/k/kite-collector/kite-collector_1.0.0_amd64.deb ]] \
  || fail "the previously published 1.0.0 deb was dropped — pool did not accumulate"
[[ -f /repo2/pool/main/k/kite-collector/kite-collector_1.1.0_amd64.deb ]] \
  || fail "the new 1.1.0 deb is missing"
[[ -f /repo2/pool/main/k/kite-collector-osquery/kite-collector-osquery_1.0.0_amd64.deb ]] \
  || fail "the bundle deb was dropped by a release that did not rebuild it"
ok "pool accumulated: 1.0.0 and 1.1.0 both present"

add_source /repo2
apt-get update -qq || fail "apt update rejected the accumulated archive"
[[ "$(apt-cache policy kite-collector | awk '/Candidate:/{print $2}')" == "1.1.0" ]] \
  || fail "candidate is not the newest version"
# The payoff of accumulating: a pinned older version is still fetchable.
apt-get install -y -qq kite-collector=1.0.0 >/dev/null \
  || fail "pinned install of the superseded 1.0.0 failed"
[[ "$(dpkg-query -W -f='${Version}' kite-collector)" == "1.0.0" ]] \
  || fail "pinned install did not land 1.0.0"
ok "newest is the candidate, and the superseded version is still installable"
apt-get remove -y -qq kite-collector >/dev/null 2>&1 || true

# ── run 3: prune ─────────────────────────────────────────────────────────
echo "== run 3: prune to --keep 1 =="
/src/scripts/publish-apt-repo.sh --out /repo3 --pool-from /repo2 \
  --keep 1 --sign-key "$KEY"
[[ -f /repo3/pool/main/k/kite-collector/kite-collector_1.1.0_amd64.deb ]] \
  || fail "prune removed the newest version"
[[ ! -f /repo3/pool/main/k/kite-collector/kite-collector_1.0.0_amd64.deb ]] \
  || fail "prune kept 1.0.0 despite --keep 1"
grep -q 'kite-collector_1\.0\.0' /repo3/dists/stable/main/binary-amd64/Packages \
  && fail "pruned version still listed in Packages — index was patched, not regenerated"
# --keep is per (package, arch), not per archive: the bundle's only version
# is 1.0.0 and must survive a prune that dropped kite-collector 1.0.0.
[[ -f /repo3/pool/main/k/kite-collector-osquery/kite-collector-osquery_1.0.0_amd64.deb ]] \
  || fail "prune counted versions across packages and dropped the bundle's only build"
ok "prune kept the newest per (package, arch) and the index followed"

# ── run 4: re-sign only, no new debs ────────────────────────────────────
# This is the nightly refresh path: same pool, fresh Date:/Valid-Until:.
echo "== run 4: re-sign only =="
before=$(find /repo3/pool -name '*.deb' | wc -l)
sleep 1
/src/scripts/publish-apt-repo.sh --out /repo4 --pool-from /repo3 --sign-key "$KEY"
after=$(find /repo4/pool -name '*.deb' | wc -l)
[[ "$before" -eq "$after" ]] || fail "re-sign changed the pool ($before -> $after debs)"
old_date=$(date -u -d "$(sed -n 's/^Date: //p' /repo3/dists/stable/Release)" +%s)
new_date=$(date -u -d "$(sed -n 's/^Date: //p' /repo4/dists/stable/Release)" +%s)
[[ "$new_date" -gt "$old_date" ]] || fail "re-sign did not advance Date:"
add_source /repo4
apt-get update -qq || fail "apt update rejected the re-signed archive"
ok "pool untouched, Date advanced, archive still verifies"

# ── expiry is load-bearing ───────────────────────────────────────────────
# Prove the client enforces Valid-Until, so the nightly refresh is a real
# dependency and not decoration. Backdate the field, re-sign honestly, and
# apt must refuse the archive.
echo "== expiry enforcement =="
past=$(date -u -d '2 days ago' '+%a, %d %b %Y %H:%M:%S +0000')
sed -i "s/^Valid-Until: .*/Valid-Until: $past/" /repo4/dists/stable/Release
( cd /repo4/dists/stable
  gpg --batch --yes --quiet --clearsign --digest-algo SHA256 -u "$KEY" -o InRelease Release
  gpg --batch --yes --quiet --detach-sign --digest-algo SHA256 -u "$KEY" -o Release.gpg Release )
if apt-get update -qq 2>/dev/null; then
  fail "apt accepted an expired Release — Valid-Until is not being enforced"
fi
ok "apt rejects an expired Release (so a stalled re-sign breaks clients — by design)"

echo "PASS: apt-repo battery"
