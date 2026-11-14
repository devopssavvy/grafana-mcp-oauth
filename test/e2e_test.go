package test_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"grafana-mcp-oauth/pkg/extauthz"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/store"
)

// Complete E2E Test Suite simulating the full stack with Zero-Manual-Token MCP Discovery:
// Coding Agent (Cursor / Claude) <--> Envoy Gateway (ext_authz) <--> Upstream mcp-grafana <--> Grafana Server (OAuth Passthru Datasource)
func TestE2E_FullSystemIntegration(t *testing.T) {
	// 1. Mock Grafana Server
	var grafanaReceivedCookie string
	mockGrafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("grafana_session")
		if cookie != nil {
			grafanaReceivedCookie = cookie.Value
		}

		switch r.URL.Path {
		case "/", "/dashboards", "/explore", "/login/generic_oauth":
			// Regular web user traffic & SSO login page
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Grafana Web UI Dashboard</body></html>"))

		case "/api/user":
			if cookie == nil || cookie.Value != "valid_user_grafana_session_456" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oauth.GrafanaUser{
				ID:    101,
				Email: "lead-dev@company.com",
				Name:  "Lead Developer",
				Login: "leaddev",
				OrgID: 1,
			})

		case "/api/ds/query":
			// Simulates Datasource Query with OAuth Passthru
			if cookie == nil || cookie.Value != "valid_user_grafana_session_456" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized: Datasource OAuth passthru missing user token"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":{"A":{"frames":[{"schema":{"name":"up"},"data":{"values":[[1700000000],[1]]}}]}}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGrafana.Close()

	// 2. In-Memory Redis
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	masterSecret := []byte("high-entropy-master-secret-salt-for-e2e-testing-32bytes")
	sessionStore, err := store.NewRedisSessionStore(rdb, masterSecret)
	require.NoError(t, err)

	// Forward declaration of envoyGateway so handlers know their public entrypoint
	var gatewayURL string

	// 3. mcp-auth-helper (OAuth handler + ext_authz server)
	oauthHandler := oauth.NewHandler(oauth.Config{
		BaseURL:         "http://gateway.local:8080",
		GrafanaURL:      mockGrafana.URL,
		CallbackBaseURL: "http://gateway.local:8080/mcp/auth/callback",
		SessionTTL:      2 * time.Hour,
		RefreshTTL:      30 * 24 * time.Hour,
		HTTPClient:      mockGrafana.Client(),
	}, sessionStore)

	extAuthServer := extauthz.NewServer(sessionStore, "http://gateway.local:8080", nil)

	// 4. Upstream mcp-grafana simulation (with GRAFANA_FORWARD_HEADERS=Cookie and --base-path /mcp)
	mockStockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forwarded headers (Cookie) are passed to Grafana API
		grafanaReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, mockGrafana.URL+"/api/ds/query", r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if c := r.Header.Get("Cookie"); c != "" {
			grafanaReq.Header.Set("Cookie", c)
		}

		resp, err := mockGrafana.Client().Do(grafanaReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer mockStockMCP.Close()

	// 5. Mock Envoy Gateway Router implementing the exact envoy.yaml routing logic
	envoyGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Route 1: /.well-known/ and /mcp/auth -> mcp-auth-helper HTTP (Bypass ext_authz)
		if strings.HasPrefix(path, "/.well-known/") || strings.HasPrefix(path, "/mcp/auth") {
			mux := http.NewServeMux()
			oauthHandler.RegisterRoutes(mux)
			mux.ServeHTTP(w, r)
			return
		}

		// Route 2: /mcp -> Protected by ext_authz -> Upstream mcp-grafana
		if strings.HasPrefix(path, "/mcp") {
			headersMap := make(map[string]string)
			for k, v := range r.Header {
				if len(v) > 0 {
					headersMap[strings.ToLower(k)] = v[0]
				}
			}

			// Invoke Envoy gRPC ext_authz Check
			checkReq := &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Method:  r.Method,
							Path:    r.URL.Path,
							Headers: headersMap,
						},
					},
				},
			}

			checkResp, err := extAuthServer.Check(r.Context(), checkReq)
			if err != nil || checkResp.GetStatus().GetCode() != int32(codes.OK) {
				denied := checkResp.GetDeniedResponse()
				if denied != nil {
					for _, h := range denied.GetHeaders() {
						w.Header().Set(h.GetHeader().GetKey(), h.GetHeader().GetValue())
					}
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("Unauthorized by ext_authz\n"))
				return
			}

			// ext_authz passed: mutate headers as instructed by ext_authz
			okResp := checkResp.GetOkResponse()
			forwardReq, _ := http.NewRequestWithContext(r.Context(), r.Method, mockStockMCP.URL+r.URL.Path, r.Body)
			for k, v := range r.Header {
				forwardReq.Header[k] = v
			}

			// Remove denied headers (e.g. authorization)
			for _, rm := range okResp.GetHeadersToRemove() {
				forwardReq.Header.Del(rm)
			}

			// Apply injected headers (e.g. Cookie)
			for _, add := range okResp.GetHeaders() {
				forwardReq.Header.Set(add.GetHeader().GetKey(), add.GetHeader().GetValue())
			}

			// Forward to upstream mcp-grafana
			resp, err := http.DefaultClient.Do(forwardReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}

		// Route 3: Default / -> Direct pass-through to Grafana Web (NO ext_authz)
		grafanaForward, _ := http.NewRequestWithContext(r.Context(), r.Method, mockGrafana.URL+r.URL.RequestURI(), r.Body)
		for k, v := range r.Header {
			grafanaForward.Header[k] = v
		}
		resp, err := mockGrafana.Client().Do(grafanaForward)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer envoyGateway.Close()
	gatewayURL = envoyGateway.URL

	// ==========================================
	// RUN INTEGRATION TEST SCENARIOS
	// ==========================================

	t.Run("Scenario 1: Regular Web Users reach Grafana without auth interference", func(t *testing.T) {
		resp, err := http.Get(gatewayURL + "/dashboards")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "Grafana Web UI Dashboard")
	})

	t.Run("Scenario 2: Client discovers OAuth metadata when connecting with only MCP URL", func(t *testing.T) {
		// 1. Client connects to MCP URL without token
		mcpURL := gatewayURL + "/mcp/sse"
		unauthResp, err := http.Get(mcpURL)
		require.NoError(t, err)
		defer unauthResp.Body.Close()

		// Server challenges with 401 and points to protected resource metadata
		assert.Equal(t, http.StatusUnauthorized, unauthResp.StatusCode)
		authChallenge := unauthResp.Header.Get("WWW-Authenticate")
		assert.Contains(t, authChallenge, `resource_metadata="http://gateway.local:8080/.well-known/oauth-protected-resource"`)

		// 2. Client queries /.well-known/oauth-protected-resource
		metaResp, err := http.Get(gatewayURL + "/.well-known/oauth-protected-resource")
		require.NoError(t, err)
		defer metaResp.Body.Close()

		assert.Equal(t, http.StatusOK, metaResp.StatusCode)
		var protectedMeta map[string]interface{}
		err = json.NewDecoder(metaResp.Body).Decode(&protectedMeta)
		require.NoError(t, err)
		assert.Contains(t, protectedMeta["authorization_servers"], "http://gateway.local:8080")

		// 3. Client queries /.well-known/oauth-authorization-server
		authServerResp, err := http.Get(gatewayURL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer authServerResp.Body.Close()

		assert.Equal(t, http.StatusOK, authServerResp.StatusCode)
		var authMeta map[string]interface{}
		err = json.NewDecoder(authServerResp.Body).Decode(&authMeta)
		require.NoError(t, err)

		assert.Equal(t, "http://gateway.local:8080/mcp/auth/login", authMeta["authorization_endpoint"])
		assert.Equal(t, "http://gateway.local:8080/mcp/auth/token", authMeta["token_endpoint"])
	})

	t.Run("Scenario 3: Complete Zero-Manual-Input Client PKCE Authorization Flow", func(t *testing.T) {
		// 1. Coding Agent starts a local loopback server to receive the authorization code
		var receivedAuthCode string
		localAgentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthCode = r.URL.Query().Get("code")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Authentication complete! You may return to Cursor/Claude."))
		}))
		defer localAgentServer.Close()

		// 2. Client generates PKCE code_verifier and code_challenge (S256)
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		hSha := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(hSha[:])

		// 3. Client opens the authorization_endpoint in user's browser
		loginURL := fmt.Sprintf("%s/mcp/auth/login?response_type=code&client_id=cursor&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=state_auto_flow",
			gatewayURL,
			url.QueryEscape(localAgentServer.URL),
			challenge,
		)

		noRedirectClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		loginResp, err := noRedirectClient.Get(loginURL)
		require.NoError(t, err)
		defer loginResp.Body.Close()

		require.Equal(t, http.StatusFound, loginResp.StatusCode)

		// Extract mcp_state from Grafana login redirect
		locParsed, err := url.Parse(loginResp.Header.Get("Location"))
		require.NoError(t, err)
		redirectParam := locParsed.Query().Get("redirect")
		cbParsed, err := url.Parse(redirectParam)
		require.NoError(t, err)
		mcpState := cbParsed.Query().Get("mcp_state")
		require.NotEmpty(t, mcpState)

		// 4. Browser authenticates with Grafana SSO and redirects to callback with session cookie and CSRF state cookie
		callbackReq, err := http.NewRequest(http.MethodGet, gatewayURL+"/mcp/auth/callback?mcp_state="+mcpState, nil)
		require.NoError(t, err)
		for _, c := range loginResp.Cookies() {
			if c.Name == "mcp_auth_state" {
				callbackReq.AddCookie(c)
			}
		}
		callbackReq.AddCookie(&http.Cookie{
			Name:  "grafana_session",
			Value: "valid_user_grafana_session_456",
		})

		// Follow redirect to local agent server
		cbResp, err := http.DefaultClient.Do(callbackReq)
		require.NoError(t, err)
		defer cbResp.Body.Close()

		// Local agent server must have received the authorization code!
		require.NotEmpty(t, receivedAuthCode, "Local agent loopback server must receive the one-time authorization code")

		// 5. Coding Agent exchanges authorization code with code_verifier at /mcp/auth/token
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", receivedAuthCode)
		form.Set("code_verifier", verifier)
		form.Set("redirect_uri", localAgentServer.URL)

		tokenReq, err := http.NewRequest(http.MethodPost, gatewayURL+"/mcp/auth/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		tokenResp, err := http.DefaultClient.Do(tokenReq)
		require.NoError(t, err)
		defer tokenResp.Body.Close()

		assert.Equal(t, http.StatusOK, tokenResp.StatusCode)
		var mcpTokens oauth.TokenResponse
		err = json.NewDecoder(tokenResp.Body).Decode(&mcpTokens)
		require.NoError(t, err)

		require.NotEmpty(t, mcpTokens.AccessToken)
		require.NotEmpty(t, mcpTokens.RefreshToken)

		// 6. Coding Agent uses access token automatically to query MCP Tools
		grafanaReceivedCookie = ""
		mcpToolReq, err := http.NewRequest(http.MethodPost, gatewayURL+"/mcp/query", strings.NewReader(`{"query":"up"}`))
		require.NoError(t, err)
		mcpToolReq.Header.Set("Authorization", "Bearer "+mcpTokens.AccessToken)
		mcpToolReq.Header.Set("Content-Type", "application/json")

		toolCallResp, err := http.DefaultClient.Do(mcpToolReq)
		require.NoError(t, err)
		defer toolCallResp.Body.Close()

		assert.Equal(t, http.StatusOK, toolCallResp.StatusCode)
		toolBody, _ := io.ReadAll(toolCallResp.Body)
		assert.Contains(t, string(toolBody), "frames")

		// Verify Grafana Server received the user's grafana_session cookie
		assert.Equal(t, "valid_user_grafana_session_456", grafanaReceivedCookie)
	})
}
