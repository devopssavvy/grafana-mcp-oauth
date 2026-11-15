package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/store"
)

func setupOAuthTestEnv(t *testing.T) (*oauth.Handler, *store.RedisSessionStore, *httptest.Server) {
	// Mock Grafana Server
	mockGrafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user" {
			cookie, err := r.Cookie("grafana_session")
			if err != nil || cookie.Value != "valid_grafana_session_123" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oauth.GrafanaUser{
				ID:    42,
				Email: "bob@company.com",
				Name:  "Bob Developer",
				Login: "bob",
				OrgID: 1,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st, err := store.NewRedisSessionStore(rdb, []byte("super-secret-master-salt-1234567890"))
	require.NoError(t, err)

	cfg := oauth.Config{
		BaseURL:          "http://localhost:8080",
		GrafanaURL:       mockGrafana.URL,
		GrafanaPublicURL: mockGrafana.URL,
		CallbackBaseURL:  "http://localhost:8080/mcp/auth/callback",
		SessionTTL:       1 * time.Hour,
		RefreshTTL:       24 * time.Hour,
		HTTPClient:       mockGrafana.Client(),
		CIMDEnforcement:  "disabled",
	}

	h := oauth.NewHandler(cfg, st)
	return h, st, mockGrafana
}

func generateTestPKCE() (verifier string, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hSha := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hSha[:])
	return
}

func TestHandler_RFC9728_ProtectedResourceMetadata(t *testing.T) {
	h, _, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	h.HandleProtectedResourceMetadata(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var meta map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&meta)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080/mcp", meta["resource"])
	authServers, ok := meta["authorization_servers"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, authServers, "http://localhost:8080")
}

func TestHandler_RFC8414_AuthorizationServerMetadata(t *testing.T) {
	h, _, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	h.HandleAuthorizationServerMetadata(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var meta map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&meta)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", meta["issuer"])
	assert.Equal(t, "http://localhost:8080/mcp/auth/login", meta["authorization_endpoint"])
	assert.Equal(t, "http://localhost:8080/mcp/auth/token", meta["token_endpoint"])
	assert.Equal(t, []interface{}{"S256"}, meta["code_challenge_methods_supported"])
}

func TestHandler_LoginRedirect_OpenRedirectProtection_And_PKCE(t *testing.T) {
	h, _, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	_, challenge := generateTestPKCE()

	// 1. Missing PKCE challenge must be rejected with 400 Bad Request
	reqNoPKCE := httptest.NewRequest(http.MethodGet, "/mcp/auth/login?redirect_uri=http://localhost:54321/callback", nil)
	wNoPKCE := httptest.NewRecorder()
	h.HandleLogin(wNoPKCE, reqNoPKCE)
	assert.Equal(t, http.StatusBadRequest, wNoPKCE.Code)
	assert.Contains(t, wNoPKCE.Body.String(), "code_challenge is required")

	// 2. Plain PKCE method must be rejected with 400 Bad Request (OAuth 2.1 BCP)
	reqPlainPKCE := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mcp/auth/login?redirect_uri=http://localhost:54321/callback&code_challenge=%s&code_challenge_method=plain", challenge), nil)
	wPlainPKCE := httptest.NewRecorder()
	h.HandleLogin(wPlainPKCE, reqPlainPKCE)
	assert.Equal(t, http.StatusBadRequest, wPlainPKCE.Code)
	assert.Contains(t, wPlainPKCE.Body.String(), "code_challenge_method must be S256")

	// 3. Malicious external redirect_uri must be rejected with 400 Bad Request
	reqMalicious := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mcp/auth/login?redirect_uri=https://evil.attacker.com/steal&code_challenge=%s&code_challenge_method=S256", challenge), nil)
	wMalicious := httptest.NewRecorder()
	h.HandleLogin(wMalicious, reqMalicious)
	assert.Equal(t, http.StatusBadRequest, wMalicious.Code)

	// 4. Valid loopback redirect_uri with S256 PKCE must succeed with 302 to Grafana and set mcp_auth_state cookie
	reqValid := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mcp/auth/login?redirect_uri=http://localhost:54321/callback&state=client_state_xyz&code_challenge=%s&code_challenge_method=S256", challenge), nil)
	wValid := httptest.NewRecorder()
	h.HandleLogin(wValid, reqValid)

	assert.Equal(t, http.StatusFound, wValid.Code)
	location := wValid.Header().Get("Location")
	assert.True(t, strings.HasPrefix(location, mockGrafana.URL+"/login/generic_oauth?redirect="))
	assert.True(t, strings.Contains(location, "mcp_state"))

	// Verify state cookie is set
	cookies := wValid.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "mcp_auth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)
	assert.NotEmpty(t, stateCookie.Value)
	assert.True(t, stateCookie.HttpOnly)
}

func TestHandler_Callback_CSRFProtection_And_SessionValidation(t *testing.T) {
	h, _, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	_, challenge := generateTestPKCE()

	// 1. Initiate login
	loginReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mcp/auth/login?redirect_uri=http://localhost:54321/callback&state=s1&code_challenge=%s&code_challenge_method=S256", challenge), nil)
	loginRec := httptest.NewRecorder()
	h.HandleLogin(loginRec, loginReq)

	loc := loginRec.Header().Get("Location")
	u, _ := url.Parse(loc)
	cbURL, _ := url.Parse(u.Query().Get("redirect"))
	mcpState := cbURL.Query().Get("mcp_state")

	var stateCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "mcp_auth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	// 2. Callback without state cookie (CSRF attack attempt) -> Rejected with 400
	cbReqNoCookie := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+mcpState, nil)
	cbReqNoCookie.AddCookie(&http.Cookie{Name: "grafana_session", Value: "valid_grafana_session_123"})
	cbRecNoCookie := httptest.NewRecorder()
	h.HandleCallback(cbRecNoCookie, cbReqNoCookie)
	assert.Equal(t, http.StatusBadRequest, cbRecNoCookie.Code)
	assert.Contains(t, cbRecNoCookie.Body.String(), "CSRF detected")

	// 3. Callback with state cookie but fake/expired Grafana session -> Rejected with 401
	cbReqFakeSession := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+mcpState, nil)
	cbReqFakeSession.AddCookie(stateCookie)
	cbReqFakeSession.AddCookie(&http.Cookie{Name: "grafana_session", Value: "forged_or_expired_cookie_token"})
	cbRecFakeSession := httptest.NewRecorder()
	h.HandleCallback(cbRecFakeSession, cbReqFakeSession)
	assert.Equal(t, http.StatusUnauthorized, cbRecFakeSession.Code)
}

func TestHandler_FullPKCE_AuthorizationCodeGrant(t *testing.T) {
	h, st, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	// 1. Client prepares PKCE: verifier and S256 challenge
	verifier, challenge := generateTestPKCE()

	loginURL := fmt.Sprintf("/mcp/auth/login?response_type=code&client_id=cursor&redirect_uri=http://127.0.0.1:45678/callback&code_challenge=%s&code_challenge_method=S256&state=state_abc", challenge)
	loginReq := httptest.NewRequest(http.MethodGet, loginURL, nil)
	loginRec := httptest.NewRecorder()
	h.HandleLogin(loginRec, loginReq)

	loc := loginRec.Header().Get("Location")
	u, _ := url.Parse(loc)
	cbURL, _ := url.Parse(u.Query().Get("redirect"))
	mcpState := cbURL.Query().Get("mcp_state")

	var stateCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "mcp_auth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	// 2. Callback from Grafana with valid session and CSRF state cookie
	cbReq := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+mcpState, nil)
	cbReq.AddCookie(stateCookie)
	cbReq.AddCookie(&http.Cookie{
		Name:  "grafana_session",
		Value: "valid_grafana_session_123",
	})
	cbRec := httptest.NewRecorder()
	h.HandleCallback(cbRec, cbReq)

	assert.Equal(t, http.StatusFound, cbRec.Code)
	agentTarget, err := url.Parse(cbRec.Header().Get("Location"))
	require.NoError(t, err)

	authCode := agentTarget.Query().Get("code")
	require.NotEmpty(t, authCode)
	assert.Equal(t, "state_abc", agentTarget.Query().Get("state"))

	// 3a. Token exchange with mismatched redirect_uri -> Rejected with 400
	formBadURI := url.Values{}
	formBadURI.Set("grant_type", "authorization_code")
	formBadURI.Set("code", authCode)
	formBadURI.Set("code_verifier", verifier)
	formBadURI.Set("redirect_uri", "http://127.0.0.1:9999/callback") // mismatch!

	tokenReqBad := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(formBadURI.Encode()))
	tokenReqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecBad := httptest.NewRecorder()
	h.HandleToken(tokenRecBad, tokenReqBad)
	assert.Equal(t, http.StatusBadRequest, tokenRecBad.Code)
	assert.Contains(t, tokenRecBad.Body.String(), "redirect_uri mismatch")

	// 3b. Redo callback to get a new one-time auth code (since old one was consumed)
	// (Re-initiate login to get fresh state)
	loginRec2 := httptest.NewRecorder()
	h.HandleLogin(loginRec2, loginReq)
	u2, _ := url.Parse(loginRec2.Header().Get("Location"))
	cbURL2, _ := url.Parse(u2.Query().Get("redirect"))
	mcpState2 := cbURL2.Query().Get("mcp_state")

	var stateCookie2 *http.Cookie
	for _, c := range loginRec2.Result().Cookies() {
		if c.Name == "mcp_auth_state" {
			stateCookie2 = c
			break
		}
	}
	cbReq2 := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+mcpState2, nil)
	cbReq2.AddCookie(stateCookie2)
	cbReq2.AddCookie(&http.Cookie{Name: "grafana_session", Value: "valid_grafana_session_123"})
	cbRec2 := httptest.NewRecorder()
	h.HandleCallback(cbRec2, cbReq2)
	agentTarget2, _ := url.Parse(cbRec2.Header().Get("Location"))
	authCode2 := agentTarget2.Query().Get("code")

	// 3c. Valid token exchange via POST /mcp/auth/token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode2)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "http://127.0.0.1:45678/callback")

	tokenReq := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.HandleToken(tokenRec, tokenReq)

	assert.Equal(t, http.StatusOK, tokenRec.Code)
	assert.Equal(t, "no-store", tokenRec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", tokenRec.Header().Get("Pragma"))

	var tokResp oauth.TokenResponse
	err = json.NewDecoder(tokenRec.Body).Decode(&tokResp)
	require.NoError(t, err)

	assert.NotEmpty(t, tokResp.AccessToken)
	assert.NotEmpty(t, tokResp.RefreshToken)
	assert.Equal(t, "Bearer", tokResp.TokenType)

	// 4. Verify session exists in store with grafana_session
	sess, err := st.GetSession(tokenReq.Context(), tokResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "bob", sess.Username)
	assert.Equal(t, "valid_grafana_session_123", sess.GrafanaSession)
}

func TestHandler_RefreshTokenGrant(t *testing.T) {
	h, st, mockGrafana := setupOAuthTestEnv(t)
	defer mockGrafana.Close()

	ctx := t.Context()
	oldAccessToken := "mcp_at_old_token_111"
	oldRefreshToken := "mcp_rt_old_refresh_222"

	sess := &store.SessionData{
		UserID:         "42",
		Username:       "bob",
		GrafanaSession: "valid_grafana_session_123",
		RefreshToken:   oldRefreshToken,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	err := st.SaveSession(ctx, oldAccessToken, sess, 1*time.Hour)
	require.NoError(t, err)
	err = st.SaveRefreshTokenSession(ctx, oldRefreshToken, sess, 24*time.Hour)
	require.NoError(t, err)

	// Case 1: Valid refresh token exchange
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", oldRefreshToken)

	tokenReq := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()

	h.HandleToken(tokenRec, tokenReq)

	assert.Equal(t, http.StatusOK, tokenRec.Code)
	assert.Equal(t, "no-store", tokenRec.Header().Get("Cache-Control"))

	var resp oauth.TokenResponse
	err = json.NewDecoder(tokenRec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEqual(t, oldAccessToken, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, oldRefreshToken, resp.RefreshToken)

	// Verify old refresh token was consumed (atomic single-use rotation)
	_, err = st.GetAndDeleteRefreshSession(ctx, oldRefreshToken)
	assert.ErrorIs(t, err, store.ErrInvalidRefreshToken)

	// Verify new access token is active
	newSess, err := st.GetSession(ctx, resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "bob", newSess.Username)
	assert.Equal(t, "valid_grafana_session_123", newSess.GrafanaSession)

	// Case 2: Grafana session expired -> Refresh must be rejected with 401
	expiredAccessToken := "mcp_at_expired_grafana"
	expiredRefreshToken := "mcp_rt_expired_grafana"
	expiredSess := &store.SessionData{
		UserID:         "42",
		Username:       "bob",
		GrafanaSession: "expired_or_revoked_session",
		RefreshToken:   expiredRefreshToken,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	_ = st.SaveSession(ctx, expiredAccessToken, expiredSess, 1*time.Hour)
	_ = st.SaveRefreshTokenSession(ctx, expiredRefreshToken, expiredSess, 24*time.Hour)

	formExpired := url.Values{}
	formExpired.Set("grant_type", "refresh_token")
	formExpired.Set("refresh_token", expiredRefreshToken)

	tokenReqExpired := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(formExpired.Encode()))
	tokenReqExpired.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecExpired := httptest.NewRecorder()

	h.HandleToken(tokenRecExpired, tokenReqExpired)
	assert.Equal(t, http.StatusUnauthorized, tokenRecExpired.Code)
	assert.Contains(t, tokenRecExpired.Body.String(), "associated Grafana session has expired or was revoked")
}

func TestHandler_BodySizeLimit_OnTokenEndpoint(t *testing.T) {
	h, _, _ := setupOAuthTestEnv(t)
	defer h.Close()

	// Send an oversized body (> 64KB)
	hugeData := strings.Repeat("a", 70*1024)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("huge", hugeData)

	req := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.HandleToken(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "body exceeds size limit")
}

func TestHandler_InvalidGrafanaSessionFormat(t *testing.T) {
	h, st, _ := setupOAuthTestEnv(t)
	defer h.Close()

	ctx := context.Background()
	state := "mcp_st_session_format_test"
	reqAuth := &store.PendingAuthRequest{
		ClientID:            "client-1",
		RedirectURI:         "http://127.0.0.1:4000/cb",
		CodeChallenge:       "challenge_val",
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now(),
	}
	err := st.SavePendingAuth(ctx, state, reqAuth, 10*time.Minute)
	require.NoError(t, err)

	// Callback with malicious/malformed cookie containing injection characters
	req := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "mcp_auth_state", Value: state})
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: "session; injected_attr=1\r\n"})
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid session token format")
}

func TestHandler_RateLimiting(t *testing.T) {
	h, _, _ := setupOAuthTestEnv(t)
	defer h.Close()

	// Exhaust rate limit on /mcp/auth/login (limit 60 reqs/min)
	clientIP := "198.51.100.5"
	var lastCode int
	for i := 0; i < 65; i++ {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login?redirect_uri=http://localhost:54321/cb&code_challenge=xyz&code_challenge_method=S256", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
		lastCode = rec.Code
	}

	assert.Equal(t, http.StatusTooManyRequests, lastCode, "Request exceeding rate limit must receive 429 Too Many Requests")
}

func TestHandler_CIMD_Enforcement(t *testing.T) {
	// Set up mock Grafana server
	mockGrafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oauth.GrafanaUser{
				ID:    1,
				Login: "alice",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockGrafana.Close()

	// Set up mock CIMD server
	mockCIMD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/client.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id":     fmt.Sprintf("http://%s/oauth/client.json", r.Host),
				"client_name":   "Valid MCP Client",
				"redirect_uris": []string{"http://127.0.0.1/callback", "http://localhost/callback"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockCIMD.Close()

	validClientID := fmt.Sprintf("%s/oauth/client.json", mockCIMD.URL)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st, err := store.NewRedisSessionStore(rdb, []byte("super-secret-master-salt-1234567890"))
	require.NoError(t, err)

	verifier, challenge := generateTestPKCE()

	t.Run("required mode: missing client_id is rejected", func(t *testing.T) {
		h := oauth.NewHandler(oauth.Config{
			BaseURL:               "http://localhost:8080",
			GrafanaURL:            mockGrafana.URL,
			CIMDEnforcement:       "required",
			CIMDAllowInsecureHTTP: true,
		}, st)
		defer h.Close()

		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login?redirect_uri=http://127.0.0.1:54321/callback&code_challenge="+challenge+"&code_challenge_method=S256", nil)
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "client_id is required")
	})

	t.Run("required mode: non-URL client_id is rejected", func(t *testing.T) {
		h := oauth.NewHandler(oauth.Config{
			BaseURL:               "http://localhost:8080",
			GrafanaURL:            mockGrafana.URL,
			CIMDEnforcement:       "required",
			CIMDAllowInsecureHTTP: true,
		}, st)
		defer h.Close()

		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login?client_id=plain-string-agent&redirect_uri=http://127.0.0.1:54321/callback&code_challenge="+challenge+"&code_challenge_method=S256", nil)
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid_client")
	})

	t.Run("required mode: redirect_uri not in metadata is rejected", func(t *testing.T) {
		h := oauth.NewHandler(oauth.Config{
			BaseURL:               "http://localhost:8080",
			GrafanaURL:            mockGrafana.URL,
			CIMDEnforcement:       "required",
			CIMDAllowInsecureHTTP: true,
		}, st)
		defer h.Close()

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mcp/auth/login?client_id=%s&redirect_uri=http://127.0.0.1:54321/unauthorized-path&code_challenge=%s&code_challenge_method=S256", url.QueryEscape(validClientID), challenge), nil)
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "not authorized in client metadata document")
	})

	t.Run("required mode: valid CIMD with dynamic loopback port succeeds", func(t *testing.T) {
		h := oauth.NewHandler(oauth.Config{
			BaseURL:               "http://localhost:8080",
			GrafanaURL:            mockGrafana.URL,
			CIMDEnforcement:       "required",
			CIMDAllowInsecureHTTP: true,
		}, st)
		defer h.Close()

		// Uses ephemeral port 59182 on 127.0.0.1, matching document's http://127.0.0.1/callback per RFC 8252 Sec 7.3
		loginURI := fmt.Sprintf("/mcp/auth/login?client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
			url.QueryEscape(validClientID),
			url.QueryEscape("http://127.0.0.1:59182/callback"),
			challenge,
		)
		req := httptest.NewRequest(http.MethodGet, loginURI, nil)
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/login/generic_oauth")

		// Extract mcp_auth_state cookie
		var stateCookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "mcp_auth_state" {
				stateCookie = c
				break
			}
		}
		require.NotNil(t, stateCookie)

		// Complete callback
		cbReq := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+stateCookie.Value, nil)
		cbReq.AddCookie(stateCookie)
		cbReq.AddCookie(&http.Cookie{Name: "grafana_session", Value: "valid_session_12345"})
		cbRec := httptest.NewRecorder()
		h.HandleCallback(cbRec, cbReq)

		assert.Equal(t, http.StatusFound, cbRec.Code)
		cbLoc := cbRec.Header().Get("Location")
		assert.Contains(t, cbLoc, "http://127.0.0.1:59182/callback?code=mcp_code_")

		u, err := url.Parse(cbLoc)
		require.NoError(t, err)
		authCode := u.Query().Get("code")
		require.NotEmpty(t, authCode)

		// Token exchange with matching client_id
		tokenBody := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:59182/callback"},
			"client_id":     {validClientID},
		}
		tokReq := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(tokenBody.Encode()))
		tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokRec := httptest.NewRecorder()
		h.HandleToken(tokRec, tokReq)

		assert.Equal(t, http.StatusOK, tokRec.Code)
		var tokResp oauth.TokenResponse
		err = json.NewDecoder(tokRec.Body).Decode(&tokResp)
		require.NoError(t, err)
		assert.NotEmpty(t, tokResp.AccessToken)
	})

	t.Run("token exchange with mismatched client_id fails", func(t *testing.T) {
		h := oauth.NewHandler(oauth.Config{
			BaseURL:               "http://localhost:8080",
			GrafanaURL:            mockGrafana.URL,
			CIMDEnforcement:       "required",
			CIMDAllowInsecureHTTP: true,
		}, st)
		defer h.Close()

		loginURI := fmt.Sprintf("/mcp/auth/login?client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
			url.QueryEscape(validClientID),
			url.QueryEscape("http://127.0.0.1:59182/callback"),
			challenge,
		)
		req := httptest.NewRequest(http.MethodGet, loginURI, nil)
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)

		var stateCookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "mcp_auth_state" {
				stateCookie = c
				break
			}
		}
		require.NotNil(t, stateCookie)

		cbReq := httptest.NewRequest(http.MethodGet, "/mcp/auth/callback?mcp_state="+stateCookie.Value, nil)
		cbReq.AddCookie(stateCookie)
		cbReq.AddCookie(&http.Cookie{Name: "grafana_session", Value: "valid_session_12345"})
		cbRec := httptest.NewRecorder()
		h.HandleCallback(cbRec, cbReq)
		require.Equal(t, http.StatusFound, cbRec.Code)

		u, err := url.Parse(cbRec.Header().Get("Location"))
		require.NoError(t, err)
		authCode := u.Query().Get("code")

		// Token exchange with wrong client_id
		tokenBody := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:59182/callback"},
			"client_id":     {"https://imposter.example.com/client.json"},
		}
		tokReq := httptest.NewRequest(http.MethodPost, "/mcp/auth/token", strings.NewReader(tokenBody.Encode()))
		tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokRec := httptest.NewRecorder()
		h.HandleToken(tokRec, tokReq)

		assert.Equal(t, http.StatusBadRequest, tokRec.Code)
		assert.Contains(t, tokRec.Body.String(), "client_id mismatch")
	})

	t.Run("RFC 8414 metadata advertises CIMD support", func(t *testing.T) {
		hRequired := oauth.NewHandler(oauth.Config{
			BaseURL:         "http://localhost:8080",
			CIMDEnforcement: "required",
		}, st)
		defer hRequired.Close()

		rec := httptest.NewRecorder()
		hRequired.HandleAuthorizationServerMetadata(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		var meta map[string]interface{}
		err := json.NewDecoder(rec.Body).Decode(&meta)
		require.NoError(t, err)
		assert.Equal(t, true, meta["client_id_metadata_document_supported"])

		hDisabled := oauth.NewHandler(oauth.Config{
			BaseURL:         "http://localhost:8080",
			CIMDEnforcement: "disabled",
		}, st)
		defer hDisabled.Close()

		rec2 := httptest.NewRecorder()
		hDisabled.HandleAuthorizationServerMetadata(rec2, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var meta2 map[string]interface{}
		err = json.NewDecoder(rec2.Body).Decode(&meta2)
		require.NoError(t, err)
		assert.Nil(t, meta2["client_id_metadata_document_supported"])
	})
}
