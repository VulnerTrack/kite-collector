.PHONY: build build-host test test-e2e test-smoke-containers test-kite-containers test-ubuntu-matrix pin-ubuntu-matrix check-ubuntu-matrix-digests sim-osquery osquery-checks osquery-edge test-cloud test-otlp test-all lint security vet clean coverage quality quality-tools check-parse-errors vulncheck osv-scan fuzz-quick windows-resources clean-windows-resources validate-wxs

# Let the Go toolchain auto-download the version pinned in go.mod when the
# host `go` is older. Without this, `go 1.26.5` in go.mod fails on hosts with
# 1.26.4 unless GOTOOLCHAIN is already exported. Applies to every recipe.
export GOTOOLCHAIN ?= auto

# Release matrix mirrored from .goreleaser.yaml. Catching cross-OS regressions
# locally (e.g. syscall.Handle vs int on Windows) is the whole point of this
# target — keep it in sync with the goreleaser `goos`/`goarch`/`ignore` block.
#
# Format: `goos/goarch[/...]` — the optional suffix is for future variants.
RELEASE_TARGETS = \
	linux/amd64   linux/arm64 \
	windows/amd64 \
	darwin/amd64  darwin/arm64 \
	freebsd/amd64 freebsd/arm64 \
	openbsd/amd64 openbsd/arm64

# build cross-compiles for every target in RELEASE_TARGETS, producing
# bin/kite-collector_<os>_<arch>. A single target failure aborts the whole
# build (set -e via the leading dash on `exit`). Use build-host for a fast
# host-only iteration loop.
#
# windows-resources runs first so the .syso is in place for every windows
# target in the matrix. The Go toolchain links *.syso next to the entry
# package automatically when GOOS=windows, so a single syso covers all
# windows/* builds.
build: windows-resources
	@mkdir -p bin
	@for target in $(RELEASE_TARGETS); do \
		os=$${target%%/*}; arch=$${target##*/}; \
		out=bin/kite-collector_$${os}_$${arch}; \
		[ "$$os" = "windows" ] && out=$${out}.exe; \
		printf "%-22s " "$${os}/$${arch}"; \
		if CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags="-s -w" -o $$out ./cmd/kite-collector 2>&1; then \
			echo "OK  ($$out)"; \
		else \
			echo "FAIL"; \
			exit 1; \
		fi; \
	done

# windows-resources generates the .syso resource that embeds app.manifest
# into the Windows binary. The manifest declares Common-Controls 6.0 so
# lxn/walk renders modern themed widgets in the install wizard. Without this
# step, the wizard still launches but draws Win95-era widgets.
#
# The .syso is build-tagged by filename suffix: rsrc_windows_amd64.syso is
# only linked when GOOS=windows && GOARCH=amd64. We deliberately produce a
# single amd64 .syso because the release matrix excludes windows/arm64
# (see .goreleaser.yaml). If windows/arm64 is added later, add a second
# rsrc rule for it.
WIN_MANIFEST := cmd/kite-collector/app.manifest
WIN_SYSO     := cmd/kite-collector/rsrc_windows_amd64.syso

windows-resources: $(WIN_SYSO)

$(WIN_SYSO): $(WIN_MANIFEST)
	@command -v rsrc >/dev/null 2>&1 || go install github.com/akavel/rsrc@latest
	@echo "  rsrc  $(WIN_MANIFEST) → $(WIN_SYSO)"
	@if command -v rsrc >/dev/null 2>&1; then \
		rsrc -manifest $(WIN_MANIFEST) -arch amd64 -o $(WIN_SYSO); \
	else \
		GOPATH=$$(go env GOPATH); \
		$$GOPATH/bin/rsrc -manifest $(WIN_MANIFEST) -arch amd64 -o $(WIN_SYSO); \
	fi

clean-windows-resources:
	rm -f $(WIN_SYSO)

# Validate the WiX installer source against two layers of checks:
#   1. xmllint --noout            — XML well-formedness
#   2. xmllint --schema wix.xsd   — WiX 3.x XSD conformance
#   3. wixl --arch x64 -o /tmp/   — actual MSI build (subset wixl supports)
#   4. wixl -D OSQUERY            — same build for the osquery-bundle variant
#
# Layers 3-4 are the only ground truth — wixl implements a subset of WiX 3.x,
# so a wxs can validate clean against the upstream XSD and still fail at
# build time. xmllint catches the schema-level errors editors miss; wixl
# catches the wixl-specific gaps. Run all before pushing wxs edits.
#
# Layer 4 stages zero-byte stand-ins for the osquery payload files — this
# validates the wxs (element support, source paths, GUID/ref wiring), not
# the payload; scripts/build-msi.sh --with-osquery stages the real one.
#
# The vendored schema lives at schemas/wix.xsd. To refresh:
#   curl -fsSL https://raw.githubusercontent.com/wixtoolset/wix3/develop/src/tools/wix/Xsd/wix.xsd -o schemas/wix.xsd
WIX_WXS    := cmd/kite-collector/wix.wxs
WIX_XSD    := schemas/wix.xsd
validate-wxs:
	@echo "[1/4] xmllint well-formedness"
	@xmllint --noout $(WIX_WXS) && echo "  PASS"
	@echo "[2/4] xmllint XSD ($(WIX_XSD))"
	@xmllint --noout --schema $(WIX_XSD) $(WIX_WXS)
	@echo "[3/4] wixl dry build (plain)"
	@if ! command -v wixl >/dev/null 2>&1; then \
		echo "  SKIP — wixl not on PATH (install wixl + msitools to enable)"; \
	else \
		tmp=$$(mktemp -d); trap "rm -rf $$tmp" EXIT; \
		sed -e 's|{{ \.Version }}|0.0.0-dev|g' -e 's|{{ \.ShortCommit }}|dev|g' $(WIX_WXS) > $$tmp/wix.wxs; \
		: > $$tmp/kite-collector.exe; \
		wixl --arch x64 -o $$tmp/test.msi $$tmp/wix.wxs && echo "  PASS — wixl accepts the wxs"; \
	fi
	@echo "[4/4] wixl dry build (-D OSQUERY bundle)"
	@if ! command -v wixl >/dev/null 2>&1; then \
		echo "  SKIP — wixl not on PATH (install wixl + msitools to enable)"; \
	else \
		tmp=$$(mktemp -d); trap "rm -rf $$tmp" EXIT; \
		sed -e 's|{{ \.Version }}|0.0.0-dev|g' -e 's|{{ \.ShortCommit }}|dev|g' $(WIX_WXS) > $$tmp/wix.wxs; \
		: > $$tmp/kite-collector.exe; \
		mkdir -p $$tmp/osquery/osqueryd $$tmp/osquery/certs $$tmp/osquery/packs; \
		: > $$tmp/osquery/osqueryd/osqueryd.exe; \
		: > $$tmp/osquery/certs/certs.pem; \
		for p in windows-hardening windows-attacks vuln-management incident-response it-compliance osquery-monitoring; do \
			: > $$tmp/osquery/packs/$$p.conf; \
		done; \
		cp configs/osquery/osquery.conf configs/osquery/osquery.flags $$tmp/osquery/; \
		wixl --arch x64 -D OSQUERY -o $$tmp/test-osquery.msi $$tmp/wix.wxs && echo "  PASS — wixl accepts the OSQUERY variant"; \
	fi

# build-host is the fast inner-loop target — same flags as the goreleaser
# `kite-collector` build, host platform only. Use this for iterative work;
# use `build` before pushing to catch cross-OS regressions.
build-host:
	CGO_ENABLED=0 go build -o bin/kite-collector ./cmd/kite-collector

run:
	CGO_ENABLED=0 go run ./cmd/kite-collector

# test runs the suite without the race detector. The sqlite + dashboard
# packages perform full schema migrations per t.TempDir, and under -race
# each migration runs ~10× slower; chained across ~250 tests the package
# wall-time exceeds the 30m go-test cap. The race-detector pass lives
# behind `make test-race` for opt-in nightly / pre-release runs.
test:
	go test -count=1 -timeout 30m ./...

test-race:
	go test -race -count=1 -timeout 60m ./...

test-e2e:
	go test -tags e2e -count=1 -timeout 120s ./tests/e2e/...

# Container-discovery smoke test: stands up fixture containers via
# docker-compose and asserts the collector's connection + data quality
# against them. Requires docker + the compose plugin (not just `go test`).
test-smoke-containers:
	./tests/e2e/containers/run.sh

# End-to-end container + settings smoke test through the real kite-collector
# binary (docker discovery source, driven by a settings file). Requires docker
# + the compose plugin.
test-kite-containers:
	./tests/e2e/kite-containers/run.sh

# Ubuntu multi-version package-discovery matrix (RFC-0149). Runs the compiled
# binary's software.Dpkg collector inside real, unmodified ubuntu:20.04/22.04/
# 24.04/devel images and asserts the discovered packages against per-version
# fixtures. Requires docker.
#
# The timeout is generous because each leg pulls a base image and runs an
# apt-get install over the public Ubuntu archive; the assertion work itself is
# milliseconds. Set KITE_MATRIX_TARGET=ubuntu-22.04 to run a single leg, which
# is how the CI matrix splits this across four jobs.
# The go-test timeout sits below the CI job's 30-minute cap on purpose: go
# test panicking with a goroutine dump is a far better diagnostic than the
# runner silently killing the job.
test-ubuntu-matrix:
	go test -tags e2e -count=1 -timeout 1500s ./tests/e2e/ubuntu-matrix/...

# Re-resolve each matrix target's floating tag and write the current digest
# into targets.json. The resulting diff is the reviewable supply-chain event
# a floating tag would otherwise hide (RFC-0149 §6.5).
#
# Invoked via `bash <script>` rather than `./script` so the target does not
# depend on the executable bit surviving a checkout or an archive export.
pin-ubuntu-matrix:
	bash tests/e2e/ubuntu-matrix/pin-digests.sh

# Read-only drift check for the weekly schedule: fails when a pinned digest no
# longer matches what its tag resolves to. Writes nothing.
check-ubuntu-matrix-digests:
	bash tests/e2e/ubuntu-matrix/pin-digests.sh --check

# Simulated osquery environment: runs a real osqueryd exposing its extensions
# socket, then probes it over that socket. Groundwork for an osquery-backed
# collector; requires docker + the compose plugin.
sim-osquery:
	docker compose -f tests/e2e/osquery/docker-compose.osquery.yml run --rm --build probe
	docker compose -f tests/e2e/osquery/docker-compose.osquery.yml down -v

# Full osquery diagnostic battery (the daily drift check, run locally). Reports
# which failure mode hit. Override OSQUERY_VERSION=latest to test drift.
osquery-checks:
	docker compose -f tests/e2e/osquery/docker-compose.osquery.yml run --rm --build checks; \
	  rc=$$?; \
	  docker compose -f tests/e2e/osquery/docker-compose.osquery.yml down -v >/dev/null 2>&1 || true; \
	  exit $$rc

# Edge-case / error-state battery: pins how osquery FAILS (loud errors, silent
# zero-row traps, async event delivery) so collector error handling is designed
# against verified behavior, not assumptions.
osquery-edge:
	docker compose -f tests/e2e/osquery/docker-compose.osquery.yml run --rm --build edge; \
	  rc=$$?; \
	  docker compose -f tests/e2e/osquery/docker-compose.osquery.yml down -v >/dev/null 2>&1 || true; \
	  exit $$rc

test-cloud:
	go test -tags cloud -count=1 -timeout 60s ./internal/discovery/cloud/...

lint:
	golangci-lint run ./...

# Vulnerability scanning gates.
#
# `vulncheck` runs Go's first-party govulncheck against the module graph,
# matching the importer's symbols against the Go vulnerability database.
# `osv-scan` runs Google's osv-scanner against go.sum (broader DB:
# GHSA + OSV + CVE feeds). Findings from both surface real, actionable
# advisories — do NOT silence with -exclude flags. Either bump the
# offending dep or document the suppression with CVE ID, reachability
# analysis, and sunset date in osv-scanner.toml / .govulncheck.yaml.
#
# `security` chains: govulncheck (cheap, network-bound) -> osv-scanner
# (also network-bound) -> gosec (CPU-bound static analysis). Each is
# independently runnable so you can target a specific gate while iterating.
vulncheck:
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

osv-scan:
	@command -v osv-scanner >/dev/null 2>&1 || go install github.com/google/osv-scanner/cmd/osv-scanner@latest
	osv-scanner -r --skip-git .

security: vulncheck osv-scan
	gosec -exclude-generated ./...

vet:
	go vet ./...

clean: clean-windows-resources
	rm -rf bin/

all: vet lint security test build

test-all: vet lint security test test-e2e build

# Deterministic coverage gate for the RFC-0115 telemetry contract surface.
#
# Runs go test with a coverage profile over internal/telemetry/... and the
# emitter (which is the wire layer the contract pins). Computes the total
# statement coverage and exits non-zero if it is below COVERAGE_MIN.
#
# Override scope or threshold from the command line:
#   make coverage COVERAGE_PKGS='./internal/...' COVERAGE_MIN=80
COVERAGE_PKGS ?= ./internal/telemetry/...
COVERAGE_MIN  ?= 90.0
COVERAGE_OUT  ?= coverage.telemetry.out

coverage:
	@echo "=== Coverage gate ($(COVERAGE_MIN)% over $(COVERAGE_PKGS)) ==="
	@go test -count=1 -covermode=atomic -coverprofile=$(COVERAGE_OUT) $(COVERAGE_PKGS) >/dev/null
	@go tool cover -func=$(COVERAGE_OUT) | tail -n 20
	@TOTAL=$$(go tool cover -func=$(COVERAGE_OUT) | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	awk -v total="$$TOTAL" -v min="$(COVERAGE_MIN)" 'BEGIN { \
		if (total + 0 < min + 0) { \
			printf "FAIL — coverage %.1f%% < %.1f%% threshold\n", total, min; \
			exit 1; \
		} \
		printf "PASS — coverage %.1f%% >= %.1f%% threshold\n", total, min; \
	}'

# Deterministic code-quality gate.
#
# Three independent checks, each fails fast on the first violation:
#   1. gocyclo  — per-function cyclomatic complexity (control-flow paths)
#   2. gocognit — per-function cognitive complexity (nested-branch readability)
#   3. dupl     — copy-pasted code blocks above N tokens
#
# Default scope is the RFC-0115 telemetry surface; widen by overriding
# QUALITY_PKGS. Thresholds intentionally tight to keep new code clean —
# raise per-tool thresholds via the env if a target subtree is legacy.
#
#   make quality
#   make quality QUALITY_PKGS=./...                     CYCLO_MAX=15 COGNIT_MAX=20 DUPL_MIN=100
#   make quality QUALITY_PKGS=./internal/dashboard/...  CYCLO_MAX=20
QUALITY_PKGS  ?= ./internal/telemetry/...
CYCLO_MAX     ?= 10
COGNIT_MAX    ?= 15
DUPL_MIN      ?= 80

# go install paths for the standalone quality tools. Run `make quality-tools`
# once to install them under $GOPATH/bin (or $HOME/go/bin), or rely on the
# `quality` target which invokes them on demand.
quality-tools:
	@command -v gocyclo  >/dev/null 2>&1 || go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	@command -v gocognit >/dev/null 2>&1 || go install github.com/uudashr/gocognit/cmd/gocognit@latest
	@command -v dupl     >/dev/null 2>&1 || go install github.com/mibk/dupl@latest

quality: quality-tools
	@echo "=== Quality gate ==="
	@DIRS=$$(go list -f '{{.Dir}}' $(QUALITY_PKGS)); \
	echo "[1/3] gocyclo  (max $(CYCLO_MAX) cyclomatic complexity)"; \
	if gocyclo -over $(CYCLO_MAX) $$DIRS; then \
		echo "  PASS — no function exceeds $(CYCLO_MAX)"; \
	else \
		echo "FAIL — function above cyclomatic complexity $(CYCLO_MAX)"; \
		exit 1; \
	fi; \
	echo "[2/3] gocognit (max $(COGNIT_MAX) cognitive complexity)"; \
	if gocognit -over $(COGNIT_MAX) $$DIRS; then \
		echo "  PASS — no function exceeds $(COGNIT_MAX)"; \
	else \
		echo "FAIL — function above cognitive complexity $(COGNIT_MAX)"; \
		exit 1; \
	fi; \
	echo "[3/3] dupl     (min $(DUPL_MIN) tokens to flag duplicates)"; \
	DUPLS=$$(dupl -t $(DUPL_MIN) -plumbing $$DIRS 2>/dev/null); \
	if [ -z "$$DUPLS" ]; then \
		echo "  PASS — no duplicate blocks at threshold $(DUPL_MIN)"; \
	else \
		echo "FAIL — duplicate blocks found:"; \
		echo "$$DUPLS"; \
		exit 1; \
	fi; \
	echo "=== Quality gate PASSED ==="

# Deterministic schema check for software-parser error logs.
#
# Runs the binary against a minimal agent-only config, captures stderr
# (slog JSON), and validates every "engine: software parse error" record
# against the fixed schema (collector, line, error, raw_line, time, level).
# Passes regardless of how many parse errors the host produces — the gate
# is on schema, not count.
check-parse-errors: build-host
	@scripts/check-parse-errors.sh

# OTLP integration test: starts an OTel Collector in Docker, runs a scan
# in streaming mode, verifies events arrive, then cleans up.
OTEL_CONFIG := /tmp/kite-otel-test-config.yaml
KITE_OTLP_CFG := /tmp/kite-otlp-test.yaml
OTEL_CONTAINER := kite-otel-test
SCAN_TIMEOUT := 15

define OTEL_COLLECTOR_YAML
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: basic
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
endef
export OTEL_COLLECTOR_YAML

define KITE_STREAMING_YAML
discovery:
  sources:
    agent:
      enabled: true
      collect_software: false
streaming:
  otlp:
    endpoint: http://localhost:4318
    protocol: http
endef
export KITE_STREAMING_YAML

test-otlp: build-host
	@echo "=== OTLP Integration Test ==="
	@echo "$$OTEL_COLLECTOR_YAML" > $(OTEL_CONFIG)
	@echo "$$KITE_STREAMING_YAML" > $(KITE_OTLP_CFG)
	@echo "[1/4] Starting OTel Collector..."
	@docker rm -f $(OTEL_CONTAINER) 2>/dev/null || true
	@docker run -d --name $(OTEL_CONTAINER) \
		-p 4318:4318 \
		-v $(OTEL_CONFIG):/etc/otelcol/config.yaml:ro \
		otel/opentelemetry-collector-contrib:latest \
		--config /etc/otelcol/config.yaml >/dev/null
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		curl -sf http://localhost:4318/ >/dev/null 2>&1 && break; \
		sleep 0.5; \
	done
	@echo "[2/4] Running kite-collector scan with OTLP..."
	@timeout $(SCAN_TIMEOUT) ./bin/kite-collector agent --stream --interval 1s \
		--config $(KITE_OTLP_CFG) 2>&1 | tail -5 || true
	@echo "[3/4] Checking collector received events..."
	@RECEIVED=$$(docker logs $(OTEL_CONTAINER) 2>&1 | grep -c "log records" || echo 0); \
	if [ "$$RECEIVED" -gt 0 ]; then \
		echo "[4/4] PASS — $$RECEIVED log records received by OTel Collector"; \
	else \
		echo "[4/4] FAIL — no log records received"; \
		docker logs $(OTEL_CONTAINER) 2>&1 | tail -15; \
		docker rm -f $(OTEL_CONTAINER) 2>/dev/null; \
		rm -f $(OTEL_CONFIG) $(KITE_OTLP_CFG); \
		exit 1; \
	fi
	@docker rm -f $(OTEL_CONTAINER) 2>/dev/null
	@rm -f $(OTEL_CONFIG) $(KITE_OTLP_CFG)
	@echo "=== OTLP test passed ==="

# Quick fuzz pass — 15s budget per parser. Intended for nightly/manual runs,
# NOT part of `make all` (would dominate runtime). The seed-corpus pass IS
# part of `make all` automatically because Go runs Fuzz* seeds during the
# normal `go test` invocation. Crashes found here are kept under
# testdata/fuzz/<FuzzName>/ per Go convention — fix the parser; do NOT mask.
fuzz-quick:
	go test -run=^$$ -fuzz=^FuzzBuildPayload -fuzztime=15s ./internal/emitter/...
	go test -run=^$$ -fuzz=^FuzzLoadConfig    -fuzztime=15s ./internal/config/...
	go test -run=^$$ -fuzz=^FuzzMigrate       -fuzztime=15s ./internal/store/sqlite/...
