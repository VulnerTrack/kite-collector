#!/usr/bin/env bash
#
# scripts/ensure-go-tool.sh <binary> <module-path>@<version>
#
# Installs a Go analysis tool if it is missing, and REINSTALLS it when the Go
# version it was built with is older than the toolchain that resolves ./... in
# this module. Used by `make lint`, `make vulncheck` and `make security`.
#
# Why the version check matters: golangci-lint, gosec and govulncheck do not ask
# the `go` command for type information — they type-check with the go/types and
# x/tools packages compiled INTO their own binaries. The Go version of the
# binary is therefore a hard ceiling on the language version it can load. Point
# a tool built with go1.26 at sources resolved by a go1.27 toolchain and it dies
# in ways that all read like repository bugs:
#
#   golangci-lint  panic: file requires newer Go version go1.27
#                         (application built with go1.26)   [inside go/types]
#   gosec          internal error: package "fmt" without types was imported
#   govulncheck    unknown field wfd in struct literal of type splicePipe
#
# None of those are code errors — `go build`, `go vet` and `go test` all pass.
# The fix is always the same: rebuild the tool with a Go at least as new as the
# toolchain in use.
#
# The mismatch is easy to reach and does not announce itself: GOTOOLCHAIN=auto
# uses the LOCAL go whenever it is newer than the go.mod directive (go 1.26.6
# here), so a developer host on go1.27 loads go1.27 stdlib sources — while
# `go install <tool>@latest` may have built the tool months ago, or under an
# older toolchain pinned by the tool's own go.mod.
#
# Only tools that load and type-check Go source get this treatment. gocyclo,
# gocognit, dupl and osv-scanner work on the AST or on go.mod/go.sum and are
# unaffected, so they keep the cheaper `command -v || go install` check in the
# Makefile rather than paying for rebuilds they do not need.
#
# Comparison is at major.minor granularity: the language version is what the
# loader gates on, so a patch-level difference is not a mismatch and must not
# trigger a multi-minute reinstall.
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: $(basename "$0") <binary> <module-path>@<version>" >&2
	exit 2
fi

readonly BIN="$1"
readonly MODULE="$2"

# minor <version> — normalize "go1.27.1-X:nodwarf5" / "1.26.5" to "1.27".
minor() {
	printf '%s\n' "${1#go}" | sed 's/-.*//' | cut -d. -f1,2
}

# install — build the tool. The stale-rebuild path MUST force GOTOOLCHAIN=local,
# otherwise the install re-selects the same older toolchain the tool's go.mod
# pins and faithfully reproduces the mismatch it is meant to fix. That can fail
# when the tool now requires a Go newer than the host, so fall back to the
# default toolchain selection, which may download one.
install() {
	echo "  go install ${MODULE}"
	if GOTOOLCHAIN=local go install "${MODULE}"; then
		return 0
	fi
	echo "  GOTOOLCHAIN=local build failed — retrying with toolchain auto-selection"
	go install "${MODULE}"
}

# The toolchain that will resolve ./... — `go env` reports the version the go
# command re-exec'd into, i.e. what GOTOOLCHAIN actually settled on here.
toolchain_minor="$(minor "$(go env GOVERSION)")"

path="$(command -v "${BIN}" 2>/dev/null || true)"
if [ -z "${path}" ]; then
	echo "${BIN} not on PATH — installing (go${toolchain_minor})"
	install
	exit 0
fi

# `go version -m <binary>` reports the Go that BUILT the binary, for any Go
# binary, e.g. "/home/u/.go/bin/gosec: go1.26.1". Tool-specific `--version`
# output cannot be relied on: gosec installed from source prints only "dev".
built_minor="$(minor "$(go version -m "${path}" 2>/dev/null |
	head -1 | awk '{print $2}')")"

if [ -z "${built_minor}" ]; then
	echo "${BIN} present but its build Go version is unreadable — reinstalling"
	install
	exit 0
fi

# Rebuild only when the tool is OLDER than the toolchain. A tool built with a
# NEWER Go is fine: its loader accepts language versions below its own.
oldest="$(printf '%s\n%s\n' "${built_minor}" "${toolchain_minor}" | sort -V | head -1)"
if [ "${built_minor}" != "${toolchain_minor}" ] && [ "${oldest}" = "${built_minor}" ]; then
	echo "${BIN} was built with go${built_minor} but ./... resolves under go${toolchain_minor}"
	echo "  rebuilding — otherwise it fails inside its source loader, which looks like a code error"
	install
fi

exit 0
