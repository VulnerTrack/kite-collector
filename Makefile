.PHONY: build test test-e2e test-cloud test-otlp test-all lint security vet clean coverage quality quality-tools check-parse-errors vulncheck osv-scan fuzz-quick

build:
	CGO_ENABLED=0 go build -o bin/kite-collector ./cmd/kite-collector

test:
	go test -race -count=1 ./...

test-e2e:
	go test -tags e2e -count=1 -timeout 120s ./tests/e2e/...

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

clean:
	rm -rf bin/

all: vet lint security test build

test-all: vet lint security test test-e2e

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
check-parse-errors: build
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

test-otlp: build
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
