# Architecture Specification: Grafana MCP OAuth Gateway

Detailed architectural specification for centralized OIDC authentication for Grafana MCP while preserving the Datasource OAuth Passthru mechanism.

---

## 1. Background & Technical Challenges

### 1.1. Grafana's Generic OAuth & Datasource Passthru Mechanism
In Grafana Server:
1. When `[auth.generic_oauth]` is configured, users authenticate via the OAuth 2.0 Authorization Code Flow.
2. Grafana Server directly communicates with the Identity Provider (IdP) to exchange the authorization code for an Access Token, ID Token, and Refresh Token.
3. Grafana stores these tokens in the `user_auth` table of its internal database.
4. Grafana issues a `grafana_session` session cookie to the browser.
5. When the user executes queries against a Data Source (e.g., Prometheus, Loki, ClickHouse, Elasticsearch) with the following setting enabled:
   ```ini
   oauth_pass_thru = true
   ```
   Grafana Server relies on `grafana_session` to look up the user's Access Token in the `user_auth` table and injects this token into the `Authorization: Bearer <user_oauth_token>` header sent to the upstream Data Source. This allows the Data Source to enforce accurate role-based access control (RBAC) according to the user's claims and roles.

### 1.2. Challenges for Grafana MCP Server
* The stock default MCP Server (`mcp-grafana`) connects to Grafana using a static `GRAFANA_SERVICE_ACCOUNT_TOKEN`.
* If the MCP Server uses a static Service Account, Grafana has **no user OAuth token** in the request context, causing queries against Data Sources with `oauth_pass_thru = true` to be denied or evaluated under incorrect permissions.
* Grafana does not provide a public API allowing external clients to send a Bearer token to self-create a `grafana_session` linked to an OAuth token in the `user_auth` table.
* Therefore, every request from the MCP Server to the Grafana API **must carry the user's actual `grafana_session` cookie** issued from Grafana's SSO login flow.

---

## 2. Architecture Solution: Envoy Gateway + `mcp-auth-helper`

The solution adopts a layered architecture:

```
+-----------------------------------------------------------------------------------------+
|                                    CLIENT TIER                                          |
|                                                                                         |
|        [Web Browser User]                             [Coding Agent / MCP Client]       |
|                 |                                                  |                    |
+-----------------|--------------------------------------------------|--------------------+
                  |                                                  |
                  |                                                  | Bearer MCP_Token
                  v                                                  v
+-----------------------------------------------------------------------------------------+
|                                  ENVOY GATEWAY TIER                                     |
|                                                                                         |
|   /dashboards, /explore, /                /mcp/auth/*                /mcp/*             |
|   (Bypass ext_authz)                      (Bypass ext_authz)         (Enforces ext_authz)
|          |                                     |                           |            |
+----------|-------------------------------------|---------------------------|------------+
           |                                     |                           |
           |                                     v                           v
           |                        +-----------------------+   +------------------------+
           |                        |    mcp-auth-helper    |   | gRPC Check()           |
           |                        |   - /mcp/auth/login   |<--| - Validates Token      |
           |                        |   - /mcp/auth/callback|   | - Injects Cookie       |
           |                        |   - /mcp/auth/token   |   | - Strips Authorization |
           |                        +-----------------------+   +------------------------+
           |                                     |                           |
           |                                     v                           |
           |                        +-----------------------+                |
           |                        |   Zero-Knowledge      |                |
           |                        |   Redis Session Store |<---------------+
           |                        +-----------------------+                |
           |                                                                 v (with Cookie)
+----------|------------------------------------------------------------------------------+
|          |                         MCP PROCESSING TIER                                  |
|          |                                                                              |
|          |                                +-----------------------------------+         |
|          |                                | stock grafana/mcp-grafana:latest  |         |
|          |                                | GRAFANA_FORWARD_HEADERS=Cookie    |         |
|          |                                +-----------------------------------+         |
|          |                                                  |                           |
+----------|--------------------------------------------------|---------------------------+
           |                                                  | Cookie: grafana_session
           v                                                  v
+-----------------------------------------------------------------------------------------+
|                                   GRAFANA & DATA TIER                                   |
|                                                                                         |
|                                  [Grafana Server]                                       |
|                                  - Resolves grafana_session                             |
|                                  - Extracts OAuth token from user_auth                  |
|                                  - Applies oauth_pass_thru = true                       |
|                                         |                                               |
|                                         v Bearer <user_oauth_token>                     |
|                                  [Data Sources]                                         |
|                                  (Prometheus / Loki / Tempo)                            |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Authentication & Query Sequence (End-to-End Sequence)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Coding Agent
    participant Envoy as Envoy Gateway (:8080)
    participant Helper as mcp-auth-helper (:8081 / :9001)
    participant Redis as Redis (Zero-Knowledge Store)
    participant Grafana as Grafana Server (:3000)
    participant MCP as Upstream mcp-grafana (:8000)
    participant DS as Datasource (OAuth Passthru)

    Note over Dev,Grafana: Phase 1: User Login & Session Harvesting
    Dev->>Envoy: 1. Access /mcp/auth/login?redirect_uri=...
    Envoy->>Helper: 2. Proxy to mcp-auth-helper
    Helper-->>Dev: 3. HTTP 302 Redirect to /login/generic_oauth?redirect=/mcp/auth/callback
    Dev->>Grafana: 4. Open Grafana SSO login page (IdP authentication)
    Grafana->>Grafana: 5. Exchange OAuth code with IdP -> store tokens in user_auth -> issue grafana_session
    Grafana-->>Dev: 6. Set-Cookie: grafana_session=... and 302 Redirect to /mcp/auth/callback
    Dev->>Envoy: 7. Send /mcp/auth/callback request with grafana_session Cookie
    Envoy->>Helper: 8. Proxy callback to mcp-auth-helper
    Helper->>Grafana: 9. GET /api/user (verify session & fetch user profile)
    Grafana-->>Helper: 10. User profile (ID, username, email)
    Helper->>Helper: 11. Generate MCP Access Token & Refresh Token
    Helper->>Redis: 12. Encrypt session (XChaCha20-Poly1305) & store under HMAC-SHA3-512 Key
    Helper-->>Dev: 13. Redirect to Coding Agent with mcp_access_token & mcp_refresh_token

    Note over Dev,DS: Phase 2: Coding Agent MCP Tool Execution
    Dev->>Envoy: 14. Call MCP Tool (POST /mcp/query, Header: "Authorization: Bearer mcp_at_...")
    Envoy->>Helper: 15. gRPC ext_authz Check()
    Helper->>Redis: 16. Lookup HMAC-SHA3-512(mcp_token) Key & Decrypt payload
    Helper-->>Envoy: 17. CheckResponse OK + Mutate Header:<br/>- Add: "Cookie: grafana_session=..."<br/>- Remove: "Authorization"
    Envoy->>MCP: 18. Forward request to mcp-grafana (carrying user's Cookie)
    MCP->>Grafana: 19. Call Grafana API with grafana_session Cookie
    Grafana->>Grafana: 20. Lookup user's OAuth token from user_auth table
    Grafana->>DS: 21. Forward query with header "Authorization: Bearer <user_oauth_token>"
    DS-->>Grafana: 22. Data RBAC-filtered accurately by OAuth claims
    Grafana-->>MCP: 23. Query result
    MCP-->>Envoy: 24. MCP Response
    Envoy-->>Dev: 25. Return result to Coding Agent
```

---

## 4. Zero-Knowledge Cryptography Security Model

The system establishes multi-layered session security to ensure end-to-end protection:

### 4.1. Token Key Hashing
* **Algorithm**: `HMAC-SHA3-512` (FIPS 202).
* **Purpose**: Hashes client tokens to serve as lookup keys in Redis.
* **Properties**: Even if the entire Redis database is extracted or dumped, attackers cannot reverse engineer user tokens or perform offline rainbow table attacks without the Server Master Secret.

### 4.2. Session Data Encryption (Encryption at Rest)
* **Algorithm**: `XChaCha20-Poly1305` (Authenticated Encryption with Associated Data - AEAD).
* **Nonce Size**: 192-bit (24 bytes) random per write, eliminating nonce collision risks.
* **Encryption Key**: Independently derived per session from the client token using `HKDF-SHA3-512` (with Argon2id supported for master secret derivation).
* **Zero-Knowledge**: Only clients possessing a valid token can derive the key required to decrypt the session payload. The Redis server stores no decryption keys.
* **Distributed State**: All pending login states (`mcp:pending_auth:`) and authorization codes (`mcp:auth_code:`) are stored centrally in Redis with automatic TTLs, fully supporting horizontal autoscaling (Multi-replica / HPA).

---

## 5. Project File Layout

```
.
├── cmd
│   └── mcp-auth-helper
│       └── main.go                 # Go entrypoint: HTTP OAuth + Envoy gRPC ext_authz Server
├── pkg
│   ├── config
│   │   └── config.go               # Configuration loader from environment variables
│   ├── crypto
│   │   ├── crypto.go               # HMAC-SHA3-512, HKDF, Argon2id, XChaCha20-Poly1305
│   │   └── crypto_test.go          # Unit tests for encryption, hashing, and tamper resistance
│   ├── extauthz
│   │   ├── server.go               # Envoy gRPC AuthorizationServer & HTTP check endpoint
│   │   └── server_test.go          # Unit tests for gRPC Check and header mutation
│   ├── oauth
│   │   ├── handler.go              # OAuth SSO login, callback, session harvesting, token refresh
│   │   └── handler_test.go         # Unit tests for OAuth flow and auto-refresh
│   └── store
│       ├── store.go                # Redis Session Store interface and Zero-Knowledge encryption
│       └── store_test.go           # Miniredis unit tests validating security at storage layer
├── deploy
│   ├── docker-compose.yml          # Example compose environment: Envoy + mcp-auth-helper + Redis + mcp-grafana
│   ├── envoy
│   │   ├── envoy.yaml              # Envoy Proxy configuration with routing and ext_authz filter
│   │   └── gateway-api.yaml        # Kubernetes Gateway API manifests (Envoy Gateway)
├── test
│   └── e2e_test.go                 # Comprehensive End-to-End integration test suite
├── Dockerfile                      # Multi-stage Dockerfile for mcp-auth-helper
├── Makefile                        # Build and test automation
├── ARCHITECTURE.md                 # Detailed architecture specification (this document)
└── README.md                       # Overview and quick-start deployment guide
```
