.PHONY: all build test clean docker-build run

GO ?= go
BINARY_NAME ?= bin/mcp-auth-helper

all: test build

build:
	@mkdir -p bin
	$(GO) build -v -ldflags="-w -s" -o $(BINARY_NAME) ./cmd/mcp-auth-helper

test:
	$(GO) test -v -count=1 -race ./...

clean:
	rm -rf bin/

docker-build:
	docker build -t grafana-mcp-oauth:latest -f Dockerfile .

run: build
	./$(BINARY_NAME)
