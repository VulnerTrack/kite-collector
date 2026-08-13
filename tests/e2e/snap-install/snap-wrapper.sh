#!/bin/sh
# Mimics the snapd /snap/bin command shim: export the snap runtime environment
# exactly as snapd would, then exec the versioned binary. Security confinement
# (AppArmor/seccomp) is not emulated — this reproduces the *environment* a
# snap-installed kite-collector sees, not the sandbox.
SNAP_REVISION=x1
SNAP=/snap/kite-collector/$SNAP_REVISION
export SNAP SNAP_REVISION
export SNAP_NAME=kite-collector
export SNAP_INSTANCE_NAME=kite-collector
export SNAP_INSTANCE_KEY=
export SNAP_VERSION=0.0.0-e2e
export SNAP_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
export SNAP_DATA=/var/snap/kite-collector/$SNAP_REVISION
export SNAP_COMMON=/var/snap/kite-collector/common
export SNAP_USER_DATA="${HOME:-/root}/snap/kite-collector/$SNAP_REVISION"
export SNAP_USER_COMMON="${HOME:-/root}/snap/kite-collector/common"
export SNAP_REEXEC=
exec "$SNAP/kite-collector" "$@"
