#!/usr/bin/env bash
# APT repository battery — exercises scripts/publish-apt-repo.sh end to end
# inside a stock debian container: first publish, accumulate onto the
# published pool, prune, re-sign-only, and expiry enforcement, each checked
# with a real apt client.
#
#   ./tests/e2e/apt-repo/run.sh
#   IMAGE=ubuntu:24.04 ./tests/e2e/apt-repo/run.sh
#
# `make test-apt-repo` wraps this. Requires docker. Needs no prebuilt
# collector deb — the battery generates its own fixture packages, because
# what is under test is the archive layout and its signatures, not the
# payload.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${IMAGE:-debian:12}"

# ── drift guard ──────────────────────────────────────────────────────────
# The release workflow and the nightly refresh must both drive the archive
# through this script with the same apt-ftparchive config — a second code
# path that writes Packages/Release by hand is exactly the drift this suite
# exists to prevent. Assert the wiring, since a green battery against the
# script proves nothing if CI has quietly gone back to dpkg-scanpackages.
CONF="$REPO_ROOT/packaging/apt/apt-ftparchive.conf"
PUB="$REPO_ROOT/scripts/publish-apt-repo.sh"
[[ -f "$CONF" ]] || { echo "DRIFT: missing packaging/apt/apt-ftparchive.conf"; exit 1; }
[[ -x "$PUB" ]]  || { echo "DRIFT: scripts/publish-apt-repo.sh is not executable"; exit 1; }

for wf in "$REPO_ROOT/.github/workflows/kite-collector.yml" \
          "$REPO_ROOT/.github/workflows/apt-repo-refresh.yml"; do
  grep -qF "scripts/publish-apt-repo.sh" "$wf" \
    || { echo "DRIFT: $(basename "$wf") does not call scripts/publish-apt-repo.sh"; exit 1; }
done
for banned in "dpkg-scanpackages" "printf \" \$(md5sum"; do
  if grep -qF "$banned" "$REPO_ROOT/.github/workflows/kite-collector.yml"; then
    echo "DRIFT: hand-rolled index generation ('$banned') is back in kite-collector.yml"
    exit 1
  fi
done
# ValidTime, not ValidUntil: apt-ftparchive ignores the latter silently.
grep -qF "ValidTime" "$PUB" || { echo "DRIFT: publish script no longer sets ValidTime"; exit 1; }
echo "  drift guard: both workflows publish through the script, no hand-rolled indices"

echo "  running apt-repo battery in $IMAGE"
docker run --rm \
  -v "$REPO_ROOT:/src:ro" \
  "$IMAGE" bash /src/tests/e2e/apt-repo/battery.sh
