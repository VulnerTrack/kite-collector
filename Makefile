.PHONY: build test lint security vet clean

build:
	CGO_ENABLED=0 go build -o bin/kite-collector ./cmd/kite-collector

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

security:
	gosec ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

all: vet lint security test build
