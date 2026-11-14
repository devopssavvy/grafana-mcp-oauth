# syntax=docker/dockerfile:1

# Build stage: supports multi-arch cross-compilation via Docker Buildx
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile static binary for target OS and architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-w -s" -o /app/grafana-mcp-oauth ./cmd/grafana-mcp-oauth

# Create backward-compatible symlinks for legacy container commands
RUN ln -s /app/grafana-mcp-oauth /app/mcp-auth-helper && \
    ln -s /app/grafana-mcp-oauth /app/grafana-mcp-wrapper

# Production stage: minimal Distroless static runtime
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /app/grafana-mcp-oauth /app/grafana-mcp-oauth
COPY --from=builder /app/mcp-auth-helper /app/mcp-auth-helper
COPY --from=builder /app/grafana-mcp-wrapper /app/grafana-mcp-wrapper

# Standard exposed ports:
# 8080: HTTP Gateway (proxy & all mode default)
# 8081: HTTP ext_authz check (extauthz mode default)
# 9001: gRPC Envoy ext_authz (extauthz & all modes)
EXPOSE 8080 8081 9001

# Run as unprivileged nonroot user (UID 65532)
USER 65532:65532

ENTRYPOINT ["/app/grafana-mcp-oauth"]
