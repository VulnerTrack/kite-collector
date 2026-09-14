#!/usr/bin/env bash
# Container half of the installer battery's fixture build. run.sh builds the
# binaries, debs and rpms on the host, then runs this in a stock debian
# container (fixture tree at /fixture, repo read-only at /src) to add what
# needs Debian tooling:
#
#   releases/download/v*/checksums.txt   goreleaser's "<sha256>  <name>" format
#   releases/latest/download/            what GitHub's /latest/ redirect reaches
#   tampered/latest/download/            a release whose binary no longer
#                                        matches its checksums.txt
#   apt/                                 signed archive from
#                                        scripts/publish-apt-repo.sh with both
#                                        collector versions and a stand-in
#                                        kite-collector-osquery bundle for each
set -euo pipefail
: "${OLD_VERSION:?}" "${NEW_VERSION:?}" "${ARCH:?}" "${HOST_UID:?}" "${HOST_GID:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends apt-utils dpkg-dev gnupg xz-utils >/dev/null

R=/fixture/releases
for ver in "$OLD_VERSION" "$NEW_VERSION"; do
  ( cd "$R/download/v$ver"
    sums="$(find . -maxdepth 1 -type f -printf '%f\n' | sort | xargs sha256sum)"
    printf '%s\n' "$sums" > checksums.txt )
done
mkdir -p "$R/latest"
cp -al "$R/download/v$NEW_VERSION" "$R/latest/download"

# Only the binary and its checksums: that is all the binary method reads, and
# download_verified is the same code path the rpm method goes through.
T=/fixture/tampered/latest/download
mkdir -p "$T"
cp "$R/download/v$NEW_VERSION/checksums.txt" "$T/"
cp "$R/download/v$NEW_VERSION/kite-collector_linux_${ARCH}_bin" "$T/"
printf 'tampered' >> "$T/kite-collector_linux_${ARCH}_bin"

# Stand-in for the osquery bundle, one per version. Building the real one
# downloads and harvests osquery (tests/e2e/deb-osquery covers it); what the
# installer decides is only which package name apt gets, and the flavor swap
# rides on the same Conflicts/Replaces/Provides nfpm-osquery.yaml declares.
IN=/fixture/apt-input
mkdir -p "$IN"
for ver in "$OLD_VERSION" "$NEW_VERSION"; do
  cp -l "$R/download/v$ver/kite-collector_${ver}_linux_${ARCH}.deb" "$IN/"
  stage="$(mktemp -d)"
  mkdir -p "$stage/DEBIAN" "$stage/usr/bin"
  cat > "$stage/DEBIAN/control" <<EOF_CONTROL
Package: kite-collector-osquery
Version: $ver
Architecture: $ARCH
Maintainer: VulnerTrack <hello@vulnertrack.dev>
Conflicts: kite-collector
Replaces: kite-collector
Provides: kite-collector
Description: installer battery stand-in for the kite-collector-osquery bundle
EOF_CONTROL
  cp "/fixture/build/$ver/kite-collector" "$stage/usr/bin/kite-collector"
  dpkg-deb --build -Zgzip -z1 "$stage" "$IN/kite-collector-osquery_${ver}_${ARCH}.deb" >/dev/null
  rm -rf "$stage"
done

export GNUPGHOME=/tmp/gnupg
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' \
    --quick-generate-key "Kite Installer Test <installer-test@example.invalid>" default default never
KEY="$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr:/{print $10; exit}')"
[[ -n "$KEY" ]] || { echo "could not create a test signing key"; exit 1; }
/src/scripts/publish-apt-repo.sh --out /fixture/apt --deb-dir "$IN" --sign-key "$KEY" >/dev/null
rm -rf "$IN"

chown -R "$HOST_UID:$HOST_GID" /fixture
