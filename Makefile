.PHONY: build test test-e2e test-cloud test-all lint security vet clean

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
