#!/bin/sh
#
# Deterministic seed manifest for the ubuntu:devel matrix leg (RFC-0149 R7).
# Same three shapes as the 22.04 leg — epoch version, multi-arch install, and
# a purged package. See fixtures/ubuntu-22.04.seed.sh for why each was chosen.
#
# `devel` is the rolling interim tag and this leg is permanently
# informational: it exists so an upstream dpkg/apt output-format change is
# visible here months before it reaches the next LTS. A broken dependency
# graph mid-development-cycle is normal for devel and surfaces as an
# infra_error on a non-blocking leg, which is the intended failure mode.
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
