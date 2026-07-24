#!/bin/sh
#
# Deterministic seed manifest for the ubuntu:22.04 matrix leg (RFC-0149 R2).
#
# Three shapes are installed, each chosen because it is a way dpkg-query
# output can silently corrupt CPE generation downstream:
#
#   vim        an epoch-versioned package ("2:9.x"). The colon is stripped by
#              CPE component normalisation, so the epoch digits fuse onto the
#              upstream version. This is the exact line that has sat unused in
#              internal/discovery/agent/software/testdata/dpkg_input.txt.
#   libc6:i386 an architecture-qualified multi-arch install. dpkg-query then
#              emits two rows named "libc6" differing only in ${Architecture};
#              collapsing or suffix-mangling either one loses a real package.
#   hello      installed then purged, so the leg proves a removed package does
#              not linger in discovery output as a phantom CVE exposure.
#
# Only official Canonical archives are used — no internal mirrors, no
# credentials (§6.1 Information Disclosure).
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
