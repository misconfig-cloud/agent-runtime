.PHONY: build test check release verify-release

RELEASE_VERSION ?=
RELEASE_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%ct HEAD 2>/dev/null)
RELEASE_OUTPUT ?= dist

build:
	go build -o bin/misconfig ./cmd/misconfig

test:
	go test -race ./...

check:
	go test -race ./...
	go vet ./...
	go build ./cmd/misconfig ./cmd/release

release:
	@test -n "$(RELEASE_VERSION)" || (echo "RELEASE_VERSION is required" >&2; exit 2)
	@test -n "$(RELEASE_COMMIT)" || (echo "RELEASE_COMMIT is required" >&2; exit 2)
	SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" go run ./cmd/release \
		--version "$(RELEASE_VERSION)" \
		--commit "$(RELEASE_COMMIT)" \
		--output "$(RELEASE_OUTPUT)"

verify-release:
	go run ./cmd/release --verify "$(RELEASE_OUTPUT)"
