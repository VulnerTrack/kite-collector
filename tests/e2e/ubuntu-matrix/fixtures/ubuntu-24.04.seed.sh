#!/bin/sh
#
# Deterministic seed manifest for the ubuntu:24.04 matrix leg (RFC-0149 R2).
# Same three shapes as the 22.04 leg — epoch version, multi-arch install, and
# a purged package — kept as its own file so a release-specific divergence
# (24.04 moved apt sources to the deb822 /etc/apt/sources.list.d layout) can
# be handled here without touching the other legs.
#
# See fixtures/ubuntu-22.04.seed.sh for why each package was chosen.
set -eu

export DEBIAN_FRONTEND=noninteractive

echo "seed: enabling the i386 foreign architecture"
dpkg --add-architecture i386

echo "seed: refreshing package lists"
apt-get update -qq

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
