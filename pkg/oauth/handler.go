package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"grafana-mcp-oauth/pkg/cimd"
	"grafana-mcp-oauth/pkg/crypto"
	"grafana-mcp-oauth/pkg/store"

	"github.com/redis/go-redis/v9"
)

// Config holds configuration parameters for the OAuth handler.
type Config struct {
	BaseURL               string // e.g. "http://localhost:8080" (Gateway Public Base URL)
	GrafanaURL            string // e.g. "http://grafana:3000" (Internal backend API URL)
	GrafanaPublicURL      string // e.g. "http://localhost:8080" (Public URL for browser redirects, defaults to BaseURL)
	CallbackBaseURL       string // e.g. "http://localhost:8080/mcp/auth/callback" or relative "/mcp/auth/callback"
	CookieSecure          bool   // Force Secure attribute on cookies
	IdPTokenURL           string
	ClientID              string
	ClientSecret          string
	SessionTTL            time.Duration
	RefreshTTL            time.Duration
	PendingAuthTTL        time.Duration
	AuthCodeTTL           time.Duration
	RateLimitLoginRPM     int                   // Max requests per minute per IP for /mcp/auth/login (default: 60)
	RateLimitTokenRPM     int                   // Max requests per minute per IP for /mcp/auth/token (default: 120)
	TrustedProxies        []*net.IPNet          // Parsed CIDRs/IPs allowed to supply X-Forwarded-For headers
	RedisClient           redis.UniversalClient // Redis client for distributed rate limiting
	CIMDEnforcement       string                // "required", "permissive", "disabled" (default: "required")
	CIMDAllowInsecureHTTP bool                  // Allow http:// and loopback IPs for testing/dev
	CIMDCacheTTL          time.Duration         // Cache TTL for CIMD metadata
	CIMDCache             cimd.Cache            // Custom or distributed CIMD cache (optional)
	CIMDFetcher           *cimd.Fetcher         // Custom or mock CIMD fetcher (optional)
	HTTPClient            *http.Client
	Logger                *slog.Logger
}

// Handler manages browser SSO login, MCP client discovery (RFC 9728, RFC 8414), PKCE, and token lifecycle.
type Handler struct {
	cfg          Config
	store        store.SessionStore
	loginLimiter RateLimiter
	tokenLimiter RateLimiter
	cimdFetcher  *cimd.Fetcher
}

// GrafanaUser is an alias to store.GrafanaUser for API compatibility.
type GrafanaUser = store.GrafanaUser

// TokenResponse represents the OAuth 2.1 token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// NewHandler creates a new OAuth handler.
func NewHandler(cfg Config, s store.SessionStore) *Handler {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.GrafanaPublicURL == "" {
		if cfg.GrafanaURL != "" {
			cfg.GrafanaPublicURL = cfg.GrafanaURL
		} else {
			cfg.GrafanaPublicURL = cfg.BaseURL
		}
	}
	cfg.GrafanaPublicURL = strings.TrimRight(cfg.GrafanaPublicURL, "/")

	if cfg.CallbackBaseURL == "" {
		cfg.CallbackBaseURL = cfg.BaseURL + "/mcp/auth/callback"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 2 * time.Hour
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.PendingAuthTTL <= 0 {
		cfg.PendingAuthTTL = 5 * time.Minute
	}
	if cfg.AuthCodeTTL <= 0 {
		cfg.AuthCodeTTL = 1 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	loginRPM := cfg.RateLimitLoginRPM
	if loginRPM <= 0 {
		loginRPM = 60
	}
	tokenRPM := cfg.RateLimitTokenRPM
	if tokenRPM <= 0 {
		tokenRPM = 120
	}

	if cfg.CIMDEnforcement == "" {
		cfg.CIMDEnforcement = "required"
	}
	cfg.CIMDEnforcement = strings.ToLower(strings.TrimSpace(cfg.CIMDEnforcement))
	if cfg.CIMDEnforcement != "permissive" && cfg.CIMDEnforcement != "disabled" {
		cfg.CIMDEnforcement = "required"
	}

	cimdFetcher := cfg.CIMDFetcher
	if cimdFetcher == nil && cfg.CIMDEnforcement != "disabled" {
		cimdFetcher = cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: cfg.CIMDAllowInsecureHTTP,
			DefaultTTL:        cfg.CIMDCacheTTL,
			Cache:             cfg.CIMDCache,
			Logger:            cfg.Logger,
		})
	}

	redisClient := cfg.RedisClient
	if redisClient == nil {
		if rs, ok := s.(interface{ Client() redis.UniversalClient }); ok {
			redisClient = rs.Client()
		}
	}

	var loginLimiter RateLimiter
	var tokenLimiter RateLimiter
	if redisClient != nil {
		loginLimiter = NewRedisRateLimiter(redisClient, "mcp:ratelimit:login", loginRPM, time.Minute, cfg.Logger)
		tokenLimiter = NewRedisRateLimiter(redisClient, "mcp:ratelimit:token", tokenRPM, time.Minute, cfg.Logger)
	}

	return &Handler{
		cfg:          cfg,
		store:        s,
		loginLimiter: loginLimiter,
		tokenLimiter: tokenLimiter,
		cimdFetcher:  cimdFetcher,
	}
}

// RegisterRoutes registers OAuth and discovery endpoints on the provided ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
			fn(w, r)
		}
	}

	// RFC 9728 Protected Resource Metadata (MCP Discovery)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", wrap(h.HandleProtectedResourceMetadata))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", wrap(h.HandleProtectedResourceMetadata))

	// RFC 8414 Authorization Server Metadata
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", wrap(h.HandleAuthorizationServerMetadata))

	// OAuth Endpoints
	mux.HandleFunc("GET /mcp/auth/login", wrap(h.HandleLogin))
	mux.HandleFunc("GET /mcp/auth/callback", wrap(h.HandleCallback))
	mux.HandleFunc("POST /mcp/auth/token", wrap(h.HandleToken))
	mux.HandleFunc("GET /mcp/auth/health", wrap(h.HandleHealth))
}

// HandleProtectedResourceMetadata serves RFC 9728 OAuth 2.0 Protected Resource Metadata for MCP clients.
func (h *Handler) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"resource": fmt.Sprintf("%s/mcp", h.cfg.BaseURL),
		"authorization_servers": []string{
			h.cfg.BaseURL,
		},
		"scopes_supported":         []string{"mcp"},
		"bearer_methods_supported": []string{"header"},
	})
}

// HandleAuthorizationServerMetadata serves RFC 8414 OAuth 2.0 Authorization Server Metadata.
func (h *Handler) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	meta := map[string]interface{}{
		"issuer":                                h.cfg.BaseURL,
		"authorization_endpoint":                fmt.Sprintf("%s/mcp/auth/login", h.cfg.BaseURL),
		"token_endpoint":                        fmt.Sprintf("%s/mcp/auth/token", h.cfg.BaseURL),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"scopes_supported":                      []string{"mcp"},
	}
	if h.cfg.CIMDEnforcement != "disabled" {
		meta["client_id_metadata_document_supported"] = true
	}
	_ = json.NewEncoder(w).Encode(meta)
}

// HandleLogin initiates browser SSO by redirecting to Grafana generic OAuth.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Rate limiting: 60 requests per minute per IP via distributed Redis
	clientIP := ExtractClientIP(r, h.cfg.TrustedProxies)
	if h.loginLimiter != nil && !h.loginLimiter.Allow(r.Context(), clientIP) {
		h.cfg.Logger.Warn("Rate limit exceeded on /mcp/auth/login", "client_ip", clientIP)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate_limit_exceeded: too many login requests, please try again later", http.StatusTooManyRequests)
		return
	}

	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	clientState := q.Get("state")
	clientID := q.Get("client_id")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// OAuth 2.1 BCP (RFC 9700): PKCE S256 is mandatory for all public clients
	if codeChallenge == "" {
		http.Error(w, "invalid_request: code_challenge is required for OAuth 2.1 PKCE", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "S256" {
		http.Error(w, "invalid_request: code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri: required for authorization code flow & must be loopback (RFC 8252 Section 7.3)
	if redirectURI == "" {
		http.Error(w, "invalid_request: redirect_uri is required for authorization code flow", http.StatusBadRequest)
		return
	}
	if !isAllowedRedirectURI(redirectURI) {
		h.cfg.Logger.Warn("Rejected login request with untrusted redirect_uri", "redirect_uri", redirectURI)
		http.Error(w, "Invalid redirect_uri: only local loopback URLs (http://localhost or http://127.0.0.1) without fragments are permitted", http.StatusBadRequest)
		return
	}

	// CIMD (Client ID Metadata Document) Enforcement per draft-ietf-oauth-client-id-metadata-document
	switch h.cfg.CIMDEnforcement {
	case "required":
		if clientID == "" {
			h.cfg.Logger.Warn("Login rejected: missing client_id (CIMD enforcement is required)", "remote_addr", clientIP)
			http.Error(w, "invalid_client: client_id is required and must be a valid Client ID Metadata Document URL", http.StatusBadRequest)
			return
		}
		if err := h.validateCIMD(r.Context(), clientID, redirectURI); err != nil {
			h.cfg.Logger.Warn("Login rejected: CIMD validation failed", "client_id", clientID, "error", err)
			http.Error(w, "invalid_client: client metadata document could not be fetched or verified", http.StatusBadRequest)
			return
		}
	case "permissive":
		if clientID != "" && isPossibleURL(clientID) {
			if err := h.validateCIMD(r.Context(), clientID, redirectURI); err != nil {
				h.cfg.Logger.Warn("Login rejected in permissive mode: CIMD validation failed", "client_id", clientID, "error", err)
				http.Error(w, "invalid_client: client metadata document could not be fetched or verified", http.StatusBadRequest)
				return
			}
		}
	case "disabled":
		// No CIMD validation
	}

	// Check if the user already has an active, authenticated Grafana session.
	// If active and prompt != "login", issue the authorization code directly,
	// preventing redundant SSO redirects and eliminating the "stuck on Grafana page" loop.
	if q.Get("prompt") != "login" {
		var grafanaSession string
		for _, c := range r.Cookies() {
			if c.Name == "grafana_session" {
				grafanaSession = c.Value
				break
			}
		}
		if grafanaSession != "" && isValidGrafanaSession(grafanaSession) {
			userInfo, err := h.fetchGrafanaUser(r.Context(), grafanaSession)
			if err == nil && userInfo != nil {
				authCode, err := crypto.GenerateRandomToken("mcp_code_", 32)
				if err != nil {
					http.Error(w, "failed to generate authorization code", http.StatusInternalServerError)
					return
				}

				authCtx := &store.AuthCodeContext{
					GrafanaSession:      grafanaSession,
					UserInfo:            userInfo,
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
					ExpiresAt:           time.Now().Add(h.cfg.AuthCodeTTL),
				}

				if err := h.store.SaveAuthCode(r.Context(), authCode, authCtx, h.cfg.AuthCodeTTL); err != nil {
					h.cfg.Logger.Error("Failed to store authorization code in Redis", "error", err)
					http.Error(w, "failed to save authorization code", http.StatusInternalServerError)
					return
				}

				redirectTarget, err := url.Parse(redirectURI)
				if err != nil {
					http.Error(w, "invalid redirect target", http.StatusBadRequest)
					return
				}

				tq := redirectTarget.Query()
				tq.Set("code", authCode)
				if clientState != "" {
					tq.Set("state", clientState)
				}
				redirectTarget.RawQuery = tq.Encode()

				h.cfg.Logger.Info("Authenticated Grafana session detected: redirecting browser back to MCP client with authorization code",
					"redirect_uri", redirectURI,
					"username", userInfo.Login,
				)

				if !isAllowedRedirectURI(redirectTarget.String()) {
					http.Error(w, "invalid redirect target: must be local loopback", http.StatusBadRequest)
					return
				}
				w.Header().Set("Location", redirectTarget.String())
				w.WriteHeader(http.StatusFound)
				return
			}
			h.cfg.Logger.Debug("Existing grafana_session cookie could not be verified against Grafana; proceeding with SSO login flow", "error", err)
		}
	}

	// Generate internal state to track this flow
	internalState, err := crypto.GenerateRandomToken("mcp_st_", 16)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Save pending request to distributed Redis store with 15-minute TTL
	pendingReq := &store.PendingAuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ClientState:         clientState,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		CreatedAt:           time.Now(),
	}
	if err := h.store.SavePendingAuth(r.Context(), internalState, pendingReq, h.cfg.PendingAuthTTL); err != nil {
		h.cfg.Logger.Error("Failed to save pending auth request to store", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Set browser state cookie to protect against OAuth Login CSRF / Session Fixation
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration (true in HTTPS production, configurable for local dev)
	http.SetCookie(w, &http.Cookie{
		Name:     "mcp_auth_state",
		Value:    internalState,
		Path:     "/mcp/auth",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   int(h.cfg.PendingAuthTTL.Seconds()),
	})

	// Derive the relative callback path required by Grafana's ValidateRedirectTo
	callbackPath := "/mcp/auth/callback?mcp_state=" + internalState
	if cbURL, err := url.Parse(h.cfg.CallbackBaseURL); err == nil && cbURL.Path != "" {
		callbackPath = cbURL.Path + "?mcp_state=" + internalState
	}

	// Set Grafana post-login redirect cookies so Grafana redirects to callback upon completing login
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration
	http.SetCookie(w, &http.Cookie{
		Name:     "redirect_to",
		Value:    url.QueryEscape(callbackPath),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   int(h.cfg.PendingAuthTTL.Seconds()),
	})
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration
	http.SetCookie(w, &http.Cookie{
		Name:     "redirectTo",
		Value:    url.QueryEscape(callbackPath),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   int(h.cfg.PendingAuthTTL.Seconds()),
	})

	// Redirect browser to Grafana generic OAuth via public URL
	// Provide redirect, redirectTo, and redirect_to parameters for maximum compatibility with Grafana
	grafanaLoginURL := fmt.Sprintf("%s/login/generic_oauth?redirect=%s&redirectTo=%s&redirect_to=%s",
		strings.TrimRight(h.cfg.GrafanaPublicURL, "/"),
		url.QueryEscape(callbackPath),
		url.QueryEscape(callbackPath),
		url.QueryEscape(callbackPath),
	)

	h.cfg.Logger.Info("Redirecting user to Grafana SSO login",
		"client_redirect_uri", redirectURI,
	)

	http.Redirect(w, r, grafanaLoginURL, http.StatusFound)
}

// HandleCallback receives the browser redirect from Grafana, extracts grafana_session, and issues an authorization code.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	internalState := r.URL.Query().Get("mcp_state")
	if internalState == "" {
		http.Error(w, "Bad Request: missing mcp_state", http.StatusBadRequest)
		return
	}

	// Verify browser state cookie using constant-time comparison to prevent OAuth Login CSRF (A07)
	stateCookie, err := r.Cookie("mcp_auth_state")
	if err != nil || stateCookie.Value == "" || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(internalState)) != 1 {
		h.cfg.Logger.Warn("Callback state cookie missing or mismatched (possible OAuth Login CSRF)",
			"mcp_state", internalState,
		)
		http.Error(w, "Authentication failed: state cookie verification failed or CSRF detected.", http.StatusBadRequest)
		return
	}

	// Clear the state and redirect cookies
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration (true in HTTPS production, configurable for local dev)
	http.SetCookie(w, &http.Cookie{
		Name:     "mcp_auth_state",
		Value:    "",
		Path:     "/mcp/auth",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   -1,
	})
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration
	http.SetCookie(w, &http.Cookie{
		Name:     "redirect_to",
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   -1,
	})
	// #nosec G124 -- Secure flag dynamically matches CookieSecure configuration
	http.SetCookie(w, &http.Cookie{
		Name:     "redirectTo",
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
		MaxAge:   -1,
	})

	// Retrieve and delete pending auth from distributed store atomically (single-use)
	req, err := h.store.GetAndDeletePendingAuth(r.Context(), internalState)
	if err != nil {
		h.cfg.Logger.Warn("Callback with unknown, expired, or already used mcp_state", "mcp_state", internalState)
		http.Error(w, "Authentication request expired or invalid. Please try again.", http.StatusBadRequest)
		return
	}

	// Extract grafana_session cookie
	var grafanaSession string
	for _, c := range r.Cookies() {
		if c.Name == "grafana_session" {
			grafanaSession = c.Value
			break
		}
	}

	if grafanaSession == "" {
		h.cfg.Logger.Warn("Callback missing grafana_session cookie", "remote_addr", r.RemoteAddr)
		http.Error(w, "Authentication failed: missing grafana_session cookie from Grafana SSO.", http.StatusUnauthorized)
		return
	}

	// Validate character set and length of grafana_session cookie (defense-in-depth against header injection / smuggling)
	if !isValidGrafanaSession(grafanaSession) {
		h.cfg.Logger.Warn("Callback with malformed or invalid grafana_session cookie", "remote_addr", r.RemoteAddr)
		http.Error(w, "Authentication failed: invalid session token format.", http.StatusBadRequest)
		return
	}

	// Strictly verify user details from Grafana using the harvested session cookie
	userInfo, err := h.fetchGrafanaUser(r.Context(), grafanaSession)
	if err != nil {
		h.cfg.Logger.Error("Session verification failed against Grafana API; rejecting unauthenticated session", "error", err)
		http.Error(w, "Authentication failed: invalid or expired Grafana session", http.StatusUnauthorized)
		return
	}

	// If this was an OAuth 2.1 Authorization Code Flow from an MCP Client
	if req.RedirectURI != "" {
		// Generate one-time Authorization Code
		authCode, err := crypto.GenerateRandomToken("mcp_code_", 32)
		if err != nil {
			http.Error(w, "failed to generate authorization code", http.StatusInternalServerError)
			return
		}

		authCtx := &store.AuthCodeContext{
			GrafanaSession:      grafanaSession,
			UserInfo:            userInfo,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			ExpiresAt:           time.Now().Add(h.cfg.AuthCodeTTL),
		}

		// Persist authorization code in distributed store with AuthCodeTTL
		if err := h.store.SaveAuthCode(r.Context(), authCode, authCtx, h.cfg.AuthCodeTTL); err != nil {
			h.cfg.Logger.Error("Failed to store authorization code in Redis", "error", err)
			http.Error(w, "failed to save authorization code", http.StatusInternalServerError)
			return
		}

		redirectTarget, err := url.Parse(req.RedirectURI)
		if err != nil {
			http.Error(w, "invalid redirect target", http.StatusBadRequest)
			return
		}

		q := redirectTarget.Query()
		q.Set("code", authCode)
		if req.ClientState != "" {
			q.Set("state", req.ClientState)
		}
		redirectTarget.RawQuery = q.Encode()

		h.cfg.Logger.Info("Redirecting browser back to MCP client with authorization code",
			"redirect_uri", req.RedirectURI,
			"username", userInfo.Login,
		)

		// Validate redirectTarget host is strictly loopback (RFC 8252 Section 7.3)
		if !isAllowedRedirectURI(redirectTarget.String()) {
			http.Error(w, "invalid redirect target: must be local loopback", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", redirectTarget.String())
		w.WriteHeader(http.StatusFound)
		return
	}

	// Direct browser confirmation fallback (XSS sanitized & anti-cache)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusOK)
	escapedUser := html.EscapeString(userInfo.Login)
	escapedURL := html.EscapeString(h.cfg.BaseURL)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Grafana MCP Login</title></head>
<body style="font-family:sans-serif;background:#111;color:#eee;padding:40px;">
    <h2>✓ Authentication Succeeded</h2>
    <p>User <strong>%s</strong> is authenticated. Your coding agent is now authorized at <code>%s/mcp</code>.</p>
</body>
</html>`, escapedUser, escapedURL)
}

// HandleToken handles OAuth 2.1 token exchange (authorization_code with PKCE) and refresh.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting: 120 requests per minute per IP via distributed Redis
	clientIP := ExtractClientIP(r, h.cfg.TrustedProxies)
	if h.tokenLimiter != nil && !h.tokenLimiter.Allow(r.Context(), clientIP) {
		h.cfg.Logger.Warn("Rate limit exceeded on /mcp/auth/token", "client_ip", clientIP)
		w.Header().Set("Retry-After", "60")
		sendTokenError(w, http.StatusTooManyRequests, "slow_down", "rate limit exceeded, please try again later")
		return
	}

	// Limit POST request body size to 64KB to prevent memory exhaustion DoS
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	if err := r.ParseForm(); err != nil {
		sendTokenError(w, http.StatusBadRequest, "invalid_request", "invalid form data or body exceeds size limit")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		sendTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grant types: authorization_code, refresh_token")
	}
}

// handleAuthorizationCodeGrant exchanges an authorization code and PKCE verifier for MCP tokens.
func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" {
		sendTokenError(w, http.StatusBadRequest, "invalid_request", "missing code parameter")
		return
	}

	// Atomically retrieve and delete authorization code from distributed store (enforces RFC 6749 single-use and eliminates race conditions)
	authCtx, err := h.store.GetAndDeleteAuthCode(r.Context(), code)
	if err != nil {
		sendTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired, or already used")
		return
	}

	if time.Now().After(authCtx.ExpiresAt) {
		sendTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has expired")
		return
	}

	// Strictly verify redirect_uri match per RFC 6749 Section 4.1.3:
	// If redirect_uri was present in authorization request, it MUST be present and match exactly here.
	if authCtx.RedirectURI != "" {
		if redirectURI == "" || authCtx.RedirectURI != redirectURI {
			h.cfg.Logger.Warn("Token exchange rejected due to redirect_uri mismatch",
				"expected", authCtx.RedirectURI,
				"received", redirectURI,
			)
			sendTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch or missing")
			return
		}
	}

	// Verify client_id in token request per OAuth 2.1 Section 4.1.3 and CIMD specification (AGENTS.md §2.2)
	reqClientID := r.FormValue("client_id")
	if h.cfg.CIMDEnforcement == "required" || authCtx.ClientID != "" {
		if reqClientID == "" {
			h.cfg.Logger.Warn("Token exchange rejected: missing client_id parameter", "expected", authCtx.ClientID)
			sendTokenError(w, http.StatusBadRequest, "invalid_client", "client_id parameter is required")
			return
		}
		if subtle.ConstantTimeCompare([]byte(reqClientID), []byte(authCtx.ClientID)) != 1 {
			h.cfg.Logger.Warn("Token exchange rejected due to client_id mismatch",
				"expected", authCtx.ClientID,
				"received", reqClientID,
			)
			sendTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}
	} else if reqClientID != "" {
		if subtle.ConstantTimeCompare([]byte(reqClientID), []byte(authCtx.ClientID)) != 1 {
			h.cfg.Logger.Warn("Token exchange rejected due to client_id mismatch",
				"expected", authCtx.ClientID,
				"received", reqClientID,
			)
			sendTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}
	}

	// Verify PKCE with constant-time comparison
	if codeVerifier == "" || !verifyPKCE(codeVerifier, authCtx.CodeChallenge, authCtx.CodeChallengeMethod) {
		h.cfg.Logger.Warn("PKCE verification failed", "username", authCtx.UserInfo.Login)
		sendTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier verification failed")
		return
	}

	// Generate access token & refresh token
	accessToken, err := crypto.GenerateRandomToken("mcp_at_", 32)
	if err != nil {
		sendTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}
	refreshToken, err := crypto.GenerateRandomToken("mcp_rt_", 32)
	if err != nil {
		sendTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}

	expiresAt := time.Now().Add(h.cfg.SessionTTL)
	sessionData := &store.SessionData{
		UserID:         fmt.Sprintf("%d", authCtx.UserInfo.ID),
		Username:       authCtx.UserInfo.Login,
		Email:          authCtx.UserInfo.Email,
		ClientID:       authCtx.ClientID,
		GrafanaSession: authCtx.GrafanaSession,
		RefreshToken:   refreshToken,
		UserClaims: map[string]interface{}{
			"org_id": authCtx.UserInfo.OrgID,
			"name":   authCtx.UserInfo.Name,
		},
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// Encrypt and persist session under access token (SessionTTL e.g. 2 hours)
	if err := h.store.SaveSession(r.Context(), accessToken, sessionData, h.cfg.SessionTTL); err != nil {
		h.cfg.Logger.Error("failed to save session to store", "error", err)
		sendTokenError(w, http.StatusInternalServerError, "server_error", "store error")
		return
	}

	// Encrypt and persist session under refresh token (RefreshTTL e.g. 30 days) to decouple refresh from access token expiry
	if err := h.store.SaveRefreshTokenSession(r.Context(), refreshToken, sessionData, h.cfg.RefreshTTL); err != nil {
		h.cfg.Logger.Error("failed to save refresh token session to store", "error", err)
	}

	h.cfg.Logger.Info("Issued MCP access token via Authorization Code Grant with PKCE",
		"username", authCtx.UserInfo.Login,
	)

	// Set required RFC 6749 Section 5.1 anti-caching headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int64(h.cfg.SessionTTL.Seconds()),
		"scope":        "mcp",
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRefreshTokenGrant issues a new access token using an existing refresh token with atomic single-use rotation and active Grafana session verification.
func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		sendTokenError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token parameter")
		return
	}

	reqClientID := r.FormValue("client_id")
	if h.cfg.CIMDEnforcement == "required" && reqClientID == "" {
		sendTokenError(w, http.StatusBadRequest, "invalid_client", "client_id parameter is required")
		return
	}

	// Atomically retrieve and delete the refresh session using Lua script (eliminates race condition & enforces single-use)
	session, err := h.store.GetAndDeleteRefreshSession(r.Context(), refreshToken)
	if err != nil {
		sendTokenError(w, http.StatusUnauthorized, "invalid_grant", "refresh token is invalid, expired, or already used")
		return
	}

	// Verify client_id binding per OAuth 2.1 Section 4.3.2 and CIMD specification
	if h.cfg.CIMDEnforcement == "required" || session.ClientID != "" {
		if reqClientID == "" {
			sendTokenError(w, http.StatusBadRequest, "invalid_client", "client_id parameter is required")
			return
		}
		if subtle.ConstantTimeCompare([]byte(reqClientID), []byte(session.ClientID)) != 1 {
			sendTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}
	} else if reqClientID != "" {
		if subtle.ConstantTimeCompare([]byte(reqClientID), []byte(session.ClientID)) != 1 {
			sendTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}
	}

	// Active upstream session verification & rotation: Attempt to rotate the Grafana session to extend its inactive lifetime
	rotatedSession, rotErr := RotateGrafanaSession(r.Context(), h.cfg.GrafanaURL, session.GrafanaSession, h.cfg.HTTPClient)
	if rotErr != nil {
		if errors.Is(rotErr, ErrGrafanaSessionInvalid) {
			h.cfg.Logger.Warn("Refresh token rejected: upstream Grafana session expired or revoked", "error", rotErr)
			sendTokenError(w, http.StatusUnauthorized, "invalid_grant", "associated Grafana session has expired or was revoked")
			return
		}
		// If rotation encountered an unexpected error (e.g. endpoint not found on older Grafana), fall back to verifying user
		if _, uErr := h.fetchGrafanaUser(r.Context(), session.GrafanaSession); uErr != nil {
			h.cfg.Logger.Warn("Refresh token rejected: upstream Grafana session expired or revoked", "error", uErr)
			sendTokenError(w, http.StatusUnauthorized, "invalid_grant", "associated Grafana session has expired or was revoked")
			return
		}
	} else if rotatedSession != "" {
		session.GrafanaSession = rotatedSession
		session.LastRotatedAt = time.Now()
	}

	newAccessToken, err := crypto.GenerateRandomToken("mcp_at_", 32)
	if err != nil {
		sendTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	newRefreshToken, err := crypto.GenerateRandomToken("mcp_rt_", 32)
	if err != nil {
		sendTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}

	session.ExpiresAt = time.Now().Add(h.cfg.SessionTTL)
	session.RefreshToken = newRefreshToken

	// Save new access token session (SessionTTL)
	if err := h.store.SaveSession(r.Context(), newAccessToken, session, h.cfg.SessionTTL); err != nil {
		sendTokenError(w, http.StatusInternalServerError, "server_error", "store error")
		return
	}

	// Save new refresh token session (RefreshTTL)
	if err := h.store.SaveRefreshTokenSession(r.Context(), newRefreshToken, session, h.cfg.RefreshTTL); err != nil {
		h.cfg.Logger.Error("failed to save rotated refresh token session", "error", err)
	}

	// RFC 6749 Section 5.1 anti-caching headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	resp := map[string]any{
		"access_token": newAccessToken,
		"token_type":   "Bearer",
		"expires_in":   int64(h.cfg.SessionTTL.Seconds()),
		"scope":        "mcp",
	}
	if newRefreshToken != "" {
		resp["refresh_token"] = newRefreshToken
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleHealth returns 200 OK.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// fetchGrafanaUser calls Grafana /api/user with the harvested session cookie, bounded to 1MB body.
func (h *Handler) fetchGrafanaUser(ctx context.Context, grafanaSession string) (*store.GrafanaUser, error) {
	reqURL := fmt.Sprintf("%s/api/user", strings.TrimRight(h.cfg.GrafanaURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("grafana_session=%s", grafanaSession))

	resp, err := h.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request to grafana failed: %w", err)
	}
	defer resp.Body.Close()

	// Bound response reader to 1MB to prevent memory exhaustion
	boundedBody := io.LimitReader(resp.Body, 1<<20)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(boundedBody)
		return nil, fmt.Errorf("grafana returned status %d: %s", resp.StatusCode, string(body))
	}

	var user store.GrafanaUser
	if err := json.NewDecoder(boundedBody).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode grafana user response: %w", err)
	}

	return &user, nil
}

// verifyPKCE verifies code_verifier against code_challenge using SHA256 and constant-time comparison per RFC 7636.
func verifyPKCE(verifier, challenge, method string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	// RFC 7636 Section 4.1: verifier must be between 43 and 128 characters
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	if method != "S256" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// isAllowedRedirectURI restricts redirect_uri to loopback HTTP/HTTPS interfaces per RFC 8252 and RFC 6749.
func isAllowedRedirectURI(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Scheme must be http or https
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// URI Fragments are strictly forbidden per RFC 6749 Section 3.1.2
	if u.Fragment != "" {
		return false
	}

	hostname := u.Hostname()
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}

	// Check if hostname is an explicit loopback IP
	ip := net.ParseIP(hostname)
	if ip != nil && ip.IsLoopback() {
		return true
	}

	return false
}

func sendTokenError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// isValidGrafanaSession verifies that the Grafana session token conforms to safe alphanumeric/base64url characters.
func isValidGrafanaSession(s string) bool {
	if len(s) < 16 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '=') {
			return false
		}
	}
	return true
}

// Close gracefully releases handler resources including background rate limiter tickers.
func (h *Handler) Close() {
	if h.loginLimiter != nil {
		h.loginLimiter.Close()
	}
	if h.tokenLimiter != nil {
		h.tokenLimiter.Close()
	}
}

func (h *Handler) validateCIMD(ctx context.Context, clientID, redirectURI string) error {
	if h.cimdFetcher == nil {
		return fmt.Errorf("CIMD fetcher not initialized")
	}
	doc, err := h.cimdFetcher.Fetch(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to fetch client metadata: %w", err)
	}
	if !cimd.ValidateRedirectURI(doc, redirectURI) {
		return fmt.Errorf("redirect_uri %q is not authorized in client metadata document", redirectURI)
	}
	return nil
}

func isPossibleURL(raw string) bool {
	return strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://")
}
