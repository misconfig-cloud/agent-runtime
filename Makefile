.PHONY: build test check

build:
	go build -o bin/misconfig ./cmd/misconfig

test:
	go test -race ./...

check:
	go test -race ./...
	go vet ./...
	go build ./cmd/misconfig
