# tui-tools — build, test and lint every tool in the monorepo.

GO      ?= go
BIN     ?= bin
CMDS    := $(notdir $(wildcard cmd/*))
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt fmt-check lint check demo clean tidy install

all: check build

## build: compile every cmd/* into $(BIN) as a static binary.
build:
	@mkdir -p $(BIN)
	@for cmd in $(CMDS); do \
		echo "building $$cmd"; \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(BIN)/$$cmd ./cmd/$$cmd || exit 1; \
	done

## test: run the unit tests.
test:
	$(GO) test ./...

## vet: run the standard static checks.
vet:
	$(GO) vet ./...

## fmt: rewrite the sources with gofmt.
fmt:
	gofmt -w .

## fmt-check: fail when something is not gofmt-clean.
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "these files need gofmt:"; echo "$$out"; exit 1; \
	fi

## lint: fmt-check plus vet. golangci-lint is used when installed.
lint: fmt-check vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

## check: everything CI runs.
check: lint test

## demo: run fwall against the in-memory sample firewall.
demo:
	$(GO) run ./cmd/fwall --demo

## install: install every tool into GOBIN.
install:
	@for cmd in $(CMDS); do \
		CGO_ENABLED=0 $(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/$$cmd || exit 1; \
	done

## tidy: prune and refresh go.mod / go.sum.
tidy:
	$(GO) mod tidy

## clean: remove build output.
clean:
	rm -rf $(BIN)

.PHONY: screenshots
screenshots: build ## Re-render the README screenshots from --demo (needs chrome/chromium)
	python3 docs/screenshots/render.py --bin bin/fwall --out docs/screenshots
