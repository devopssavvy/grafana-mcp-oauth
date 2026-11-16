package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"grafana-mcp-oauth/pkg/store"
)

type contextKey string

const (
	requestBodyContextKey contextKey = "mcp_request_body"
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
		ModifyResponse: func(resp *http.Response) error {
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Header.Set("X-Accel-Buffering", "no")
				return nil
			}

			// If upstream returned an error about session initialization being in progress,
			// retry transparently after a short backoff because notifications/initialized arrives
			// within milliseconds.
			if resp.Request != nil && resp.Body != nil {
				if bodyBytes, ok := resp.Request.Context().Value(requestBodyContextKey).([]byte); ok && len(bodyBytes) > 0 {
					respBytes, err := io.ReadAll(resp.Body)
					if err == nil {
						_ = resp.Body.Close()
						if bytes.Contains(respBytes, []byte("is invalid during session initialization")) {
							p.logger.Info("Upstream MCP session is still initializing; retrying message request after brief backoff",
								"path", resp.Request.URL.Path,
							)
							backoffs := []time.Duration{150 * time.Millisecond, 250 * time.Millisecond, 400 * time.Millisecond}
							for _, backoff := range backoffs {
								time.Sleep(backoff)
								retryReq, err := http.NewRequestWithContext(
									resp.Request.Context(),
									resp.Request.Method,
									resp.Request.URL.String(),
									bytes.NewReader(bodyBytes),
								)
								if err != nil {
									break
								}
								retryReq.Header = resp.Request.Header.Clone()
								retryResp, err := http.DefaultTransport.RoundTrip(retryReq)
								if err == nil {
									newRespBytes, err := io.ReadAll(retryResp.Body)
									_ = retryResp.Body.Close()
									if err == nil && !bytes.Contains(newRespBytes, []byte("is invalid during session initialization")) {
										p.logger.Info("Transparent retry succeeded: MCP session initialized",
											"path", resp.Request.URL.Path,
										)
										retryResp.Body = io.NopCloser(bytes.NewReader(newRespBytes))
										*resp = *retryResp
										return nil
									}
								}
							}
						}
						resp.Body = io.NopCloser(bytes.NewReader(respBytes))
					}
				}
			}
			return nil
		},
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

	// Buffer POST request bodies to support transparent retry on session initialization
	if r.Method == http.MethodPost && r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		if err == nil {
			_ = r.Body.Close()
			outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			outReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
			outReq = outReq.WithContext(context.WithValue(outReq.Context(), requestBodyContextKey, bodyBytes))
		}
	}

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
