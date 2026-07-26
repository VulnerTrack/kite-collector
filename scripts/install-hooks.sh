#!/usr/bin/env bash
# Point this clone's git hooks at the checked-in .githooks/ directory.
#
# Run once after cloning:
#
#   bash scripts/install-hooks.sh
#
# core.hooksPath is a local config, so this does not touch anything outside
# the current worktree and does not need re-running when hooks change (they
# are versioned in .githooks/).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "git hooks installed — .githooks/ is now the hook directory for this clone."
echo "  bypass one push:  KITE_HOOK_SKIP=1 git push   (or --no-verify)"
echo "  run full 'make all' before push:  KITE_HOOK_FULL=1 git push"
