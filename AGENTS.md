# AGENTS.md — Development & Architecture Guidelines

This file provides architectural conventions, security invariants, and coding standards for AI coding agents and human contributors working on `grafana-mcp-oauth`.

---

## 1. Core Architecture & State Governance

`grafana-mcp-oauth` is a centralized OAuth 2.1 PKCE and RFC 9728 discovery layer for the Grafana Model Context Protocol (MCP) server. It operates as an Envoy `ext_authz` authorization helper or as a direct authenticated reverse proxy sidecar.

### 1.1 Mandatory Caching & Storage Rules
* **All caches must store to Redis**: Primary caching, rate limiting, and state persistence must target Redis/Valkey.
* **Encrypt sensitive data**: Any sensitive session tokens, credentials, authorization codes, or user identity claims **must be encrypted** using authenticated encryption (XChaCha20-Poly1305 with keys derived via HKDF-SHA3-512) before being stored in Redis. Plaintext storage of sensitive session materials or tokens in Redis is strictly prohibited.
* **In-memory cache constraint**: Only use in-memory cache as an auxiliary/L2 cache when strictly needed (for example, the `TwoTierCache` used for caching public Client ID Metadata Documents), otherwise Redis only.
* **Distributed Rate Limiting**: Rate limiting for authentication and token endpoints must be stored in Redis only (under `mcp:ratelimit:*`). In-memory rate limiting tables are prohibited to guarantee atomic synchronization across multi-pod replicas and prevent local heap exhaustion.

---

## 2. Security Invariants

### 2.1 Zero-Knowledge Session Store
- **Key Storage**: Redis lookup keys must be computed using `crypto.HashTokenKey(token, secret)` (HMAC-SHA3-512 over the token). Never store raw tokens or deterministic hashes without domain separation salts as Redis keys.
- **Client-Derived Keys (RFC 5869)**: When `MCP_MASTER_SECRET` is unset, the gateway derives keys directly from the client's high-entropy Bearer token. Never degrade or hardcode static fallback secrets in production configurations.
- **Single-Use Consumption**: Pending login states (`mcp:pending_auth:`) and authorization codes (`mcp:auth_code:`) must be consumed atomically using Redis Lua scripts (`GETDEL`) to eliminate race conditions and token replay attacks.

### 2.2 Client ID Metadata Document (CIMD) & SSRF Defenses
- **SSRF Prevention**: All outbound HTTP requests fetching client metadata must use `cimd.NewSSRFSafeClient()`. The custom dialer must:
  - Resolve DNS and inspect all candidate IPs against the blocked CIDR lists (RFC 1918 private subnets, loopback, cloud metadata `169.254.169.254`, carrier-grade NAT, and RFC 8215 local IPv4/IPv6 translation).
  - Dial the validated IP address directly (`safeAddr`) to prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
  - Reject all HTTP redirects per draft-ietf-oauth-client-id-metadata-document Section 3.
  - Enforce standard HTTPS ports (`443`, `8443`) unless `CIMD_ALLOW_INSECURE_HTTP` is explicitly enabled for local testing.
- **Strict Client ID Binding**: When `CIMD_ENFORCEMENT=required` or when a session is bound to a client ID, incoming `client_id` parameters on both `/mcp/auth/token` (authorization code grant) and refresh token grants must be verified using `subtle.ConstantTimeCompare` against the session client ID. Empty client IDs must be rejected with HTTP 400 (`invalid_client`) and mismatched client IDs must be rejected with HTTP 400 (`invalid_grant`).

### 2.3 Constant-Time Comparisons
- Always use `crypto/subtle.ConstantTimeCompare` for:
  - PKCE `code_verifier` vs `code_challenge`
  - Browser state cookie `mcp_auth_state` vs internal state
  - `client_id` string matching
  - Token and credential comparisons

### 2.4 Browser Security Headers
- All HTTP responses must include defensive security headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`
- State cookies (`mcp_auth_state`) must be configured with `SameSite=Lax`, `HttpOnly=true`, and `Secure=true` (when serving over HTTPS).

---

## 3. Code Organization

```
pkg/
├── cimd/       # Client ID Metadata Document parser, SSRF-safe client, two-tier cache
├── config/     # Environment variable loading, parsing, and validation
├── crypto/     # HKDF-SHA3-512, XChaCha20-Poly1305 AEAD, and token generation
├── extauthz/   # Envoy external authorization gRPC and HTTP check services
├── oauth/      # OAuth 2.1 PKCE handlers, discovery, and Redis rate limiting
├── proxy/      # Direct authenticated reverse proxy sidecar mode
├── server/     # HTTP/gRPC server lifecycle, listener binding, and dynamic TLS mTLS reloader
└── store/      # Zero-knowledge Redis session and OAuth state store
cmd/
├── grafana-mcp-oauth/ # Production unified binary
└── demo-runner/        # Test runner and live demo mock ecosystem
```

---

## 4. Verification & Testing

Every code modification must be verified before pushing:
```bash
# Run unit and integration tests
go test -v ./...

# Verify container build and linting
make docker-build
```
Ensure that any new functionality is accompanied by comprehensive tests in the corresponding package.
