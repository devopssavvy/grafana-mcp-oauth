.PHONY: all build test clean docker-build docker-build-multiarch run

GO ?= go
BINARY_NAME ?= bin/grafana-mcp-oauth
IMAGE_NAME ?= grafana-mcp-oauth:latest

all: test build

build:
	@mkdir -p bin
	$(GO) build -v -ldflags="-w -s" -o $(BINARY_NAME) ./cmd/grafana-mcp-oauth

test:
	$(GO) test -v -count=1 -race ./...

clean:
	rm -rf bin/

docker-build:
	docker build --network=host -t $(IMAGE_NAME) -f Dockerfile .

docker-build-multiarch:
	docker buildx build --network=host --platform linux/amd64,linux/arm64 -t $(IMAGE_NAME) -f Dockerfile .

run: build
	./$(BINARY_NAME)
