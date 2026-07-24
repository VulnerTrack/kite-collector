#!/bin/sh
#
# Deterministic seed manifest for the ubuntu:20.04 matrix leg (RFC-0149 R2).
# Same three shapes as the 22.04 leg — epoch version, multi-arch install, and
# a purged package. See fixtures/ubuntu-22.04.seed.sh for why each was chosen.
#
# 20.04 is the informational "legacy" leg: its standard-support window closed
# on 2025-05-31, so Canonical eventually retires focal from archive.ubuntu.com
# to old-releases.ubuntu.com. The fallback below keeps the leg meaningful
# across that move instead of turning it into a permanent infra_error, and
# old-releases.ubuntu.com is an official Canonical archive, so §6.1's
# "official archives only" constraint still holds.
set -eu

export DEBIAN_FRONTEND=noninteractive

echo "seed: enabling the i386 foreign architecture"
dpkg --add-architecture i386

echo "seed: refreshing package lists"
if ! apt-get update -qq; then
    echo "seed: archive.ubuntu.com refresh failed; retrying via old-releases.ubuntu.com" >&2
    sed -i \
        -e 's|archive\.ubuntu\.com|old-releases.ubuntu.com|g' \
        -e 's|security\.ubuntu\.com|old-releases.ubuntu.com|g' \
        /etc/apt/sources.list
    apt-get update -qq
fi

echo "seed: installing epoch + multi-arch + purge-probe packages"
apt-get install -y -qq --no-install-recommends \
    -o Acquire::Retries=3 \
    vim \
    libc6:i386 \
    hello

echo "seed: purging the purge-probe package"
apt-get purge -y -qq hello

apt-get clean
rm -rf /var/lib/apt/lists/*

echo "seed: complete"
