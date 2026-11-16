# syntax=docker/dockerfile:1

# Build stage: supports multi-arch cross-compilation via Docker Buildx
# Pinned to immutable cryptographic digest for supply chain integrity
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

# Compile static binary for target OS and architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -mod=vendor -ldflags="-w -s" -o /app/grafana-mcp-oauth ./cmd/grafana-mcp-oauth

# Production stage: minimal Distroless static runtime
# Pinned to immutable cryptographic digest for zero-vulnerability static base
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.title="grafana-mcp-oauth" \
      org.opencontainers.image.description="Zero-Fork OAuth 2.1 & RFC 9728 authentication layer for upstream Grafana MCP server" \
      org.opencontainers.image.source="https://github.com/devopssavvy/grafana-mcp-oauth" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

COPY --from=builder /app/grafana-mcp-oauth /app/grafana-mcp-oauth

# Standard exposed ports:
# 8080: HTTP Gateway (proxy & all mode default)
# 8081: HTTP ext_authz check (extauthz mode default)
# 9001: gRPC Envoy ext_authz (extauthz & all modes)
EXPOSE 8080 8081 9001

# Run as unprivileged nonroot user (UID 65532)
USER 65532:65532

ENTRYPOINT ["/app/grafana-mcp-oauth"]
