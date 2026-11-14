package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"grafana-mcp-oauth/pkg/store"
)

// Config configures the MCP authenticated reverse proxy.
type Config struct {
	TargetURL string
	BaseURL   string
	Logger    *slog.Logger
}

// Proxy is a reverse proxy that authenticates incoming MCP requests via Bearer token,
// translates the token into a grafana_session cookie, and forwards to stock mcp-grafana.
type Proxy struct {
	targetURL *url.URL
	baseURL   string
	store     store.SessionStore
	logger    *slog.Logger
	rp        *httputil.ReverseProxy
}

// NewProxy creates a new authenticated MCP reverse proxy.
func NewProxy(cfg Config, s store.SessionStore) (*Proxy, error) {
	if cfg.TargetURL == "" {
		cfg.TargetURL = "http://127.0.0.1:8000"
	}
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	p := &Proxy{
		targetURL: target,
		baseURL:   cfg.BaseURL,
		store:     s,
		logger:    cfg.Logger,
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
		// FlushInterval: -1 ensures immediate flushing for SSE text/event-stream
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Error("Upstream proxy error", "error", err, "path", r.URL.Path)
			http.Error(w, "Bad Gateway: Upstream MCP server unavailable", http.StatusBadGateway)
		},
	}

	p.rp = rp
	return p, nil
}

// ServeHTTP handles incoming requests, validates MCP access tokens, injects the session cookie,
// and proxies to upstream stock mcp-grafana.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := extractBearerToken(authHeader)

	if token == "" {
		p.logger.Warn("Missing or invalid Authorization header", "path", r.URL.Path, "method", r.Method)
		p.send401(w, `Bearer resource_metadata="`+p.baseURL+`/.well-known/oauth-protected-resource"`, "Unauthorized: Missing Bearer token")
		return
	}

	session, err := p.store.GetSession(r.Context(), token)
	if err != nil {
		p.logger.Warn("Session validation failed", "error", err, "path", r.URL.Path)
		p.send401(w, `Bearer error="invalid_token", resource_metadata="`+p.baseURL+`/.well-known/oauth-protected-resource"`, "Unauthorized: Session invalid or expired")
		return
	}

	// Clone request and mutate headers for upstream forwarding
	outReq := r.Clone(r.Context())

	// Strip Bearer Authorization header so internal token never leaks upstream
	outReq.Header.Del("Authorization")

	// Inject grafana_session cookie
	existingCookie := r.Header.Get("Cookie")
	outReq.Header.Set("Cookie", buildCookieHeader(existingCookie, session.GrafanaSession))
	outReq.Header.Set("X-Forwarded-User", session.Username)

	p.logger.Debug("Forwarding authenticated MCP request",
		"username", session.Username,
		"path", r.URL.Path,
		"method", r.Method,
	)

	p.rp.ServeHTTP(w, outReq)
}

func (p *Proxy) send401(w http.ResponseWriter, challenge string, message string) {
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(message + "\n"))
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func buildCookieHeader(existingCookie, grafanaSession string) string {
	sessionCookie := fmt.Sprintf("grafana_session=%s", grafanaSession)
	if existingCookie == "" {
		return sessionCookie
	}

	// Strip any untrusted or stale grafana_session cookies provided by client case-insensitively (fixes Cookie Smuggling)
	var parts []string
	for _, c := range strings.Split(existingCookie, ";") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		kv := strings.SplitN(c, "=", 2)
		cookieName := strings.TrimSpace(kv[0])
		if !strings.EqualFold(cookieName, "grafana_session") {
			parts = append(parts, c)
		}
	}
	parts = append(parts, sessionCookie)
	return strings.Join(parts, "; ")
}
