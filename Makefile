.PHONY: build test test-e2e test-cloud test-otlp test-all lint security vet clean

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

security:
	gosec ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

all: vet lint security test build

test-all: vet lint security test test-e2e

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
