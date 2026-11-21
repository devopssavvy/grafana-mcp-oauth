package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"grafana-mcp-oauth/pkg/crypto"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/store"
)

type contextKey string

const (
	requestBodyContextKey contextKey = "mcp_request_body"
	// #nosec G101 -- context key for internal request context, not a hardcoded credential
	bearerTokenContextKey contextKey = "mcp_internal_auth"
)

var sessionIDRegex = regexp.MustCompile(`(?i)[?&]session_?id=([a-zA-Z0-9_\-\.]+)`)

// RotateFunc defines the function signature for rotating a Grafana session token.
type RotateFunc func(ctx context.Context, grafanaURL string, currentSession string) (string, error)

// Config configures the MCP authenticated reverse proxy.
type Config struct {
	TargetURL        string
	BaseURL          string
	InstanceURL      string
	GrafanaURL       string        // Backend Grafana API URL (e.g. http://grafana:3000)
	RotationInterval time.Duration // Interval to trigger sliding keep-alive rotation (default 5m)
	SessionTTL       time.Duration // Session validity lifetime to slide on rotation (default 2h)
	Logger           *slog.Logger
	PeerClient       *http.Client
	GrafanaClient    *http.Client
	RotateFunc       RotateFunc // Optional custom rotator for testing
}

// Proxy is a reverse proxy that authenticates incoming MCP requests via Bearer token,
// translates the token into a grafana_session cookie, and forwards to stock mcp-grafana.
type Proxy struct {
	targetURL        *url.URL
	baseURL          string
	instanceURL      string
	grafanaURL       string
	rotationInterval time.Duration
	sessionTTL       time.Duration
	store            store.SessionStore
	logger           *slog.Logger
	peerClient       *http.Client
	grafanaClient    *http.Client
	rotateFunc       RotateFunc
	rp               *httputil.ReverseProxy
	inFlightRotation sync.Map
	rotationCooldown sync.Map
	activeSessions   sync.Map
	stopKeepalive    context.CancelFunc
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

	if cfg.InstanceURL == "" {
		cfg.InstanceURL = cfg.BaseURL
	}
	cfg.InstanceURL = strings.TrimRight(cfg.InstanceURL, "/")

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	peerClient := cfg.PeerClient
	if peerClient == nil {
		peerClient = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Prohibit redirects on peer forwarding to prevent credential leakage
			},
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, fmt.Errorf("invalid address %q: %w", addr, err)
					}
					dialer := &net.Dialer{
						Timeout:   5 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					if ip := net.ParseIP(host); ip != nil {
						// Block cloud metadata (169.254.169.254 / link-local)
						if ip.IsLinkLocalUnicast() || ip.String() == "169.254.169.254" {
							return nil, fmt.Errorf("peer forward to metadata IP blocked: %s", ip)
						}
						return dialer.DialContext(ctx, network, addr)
					}
					// Pre-resolve DNS hostnames to verify candidate IPs against metadata / link-local addresses (SSRF defense-in-depth)
					ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
					if err != nil {
						return nil, fmt.Errorf("DNS lookup failed for peer host %s: %w", host, err)
					}
					var safeIPs []net.IP
					for _, ip := range ips {
						if ip.IsLinkLocalUnicast() || ip.String() == "169.254.169.254" {
							return nil, fmt.Errorf("peer host %s resolved to blocked metadata IP %s", host, ip)
						}
						safeIPs = append(safeIPs, ip)
					}
					if len(safeIPs) == 0 {
						return nil, fmt.Errorf("no IP addresses resolved for peer host %s", host)
					}
					var lastErr error
					for _, sip := range safeIPs {
						safeAddr := net.JoinHostPort(sip.String(), port)
						conn, err := dialer.DialContext(ctx, network, safeAddr)
						if err == nil {
							return conn, nil
						}
						lastErr = err
					}
					return nil, fmt.Errorf("failed to connect to resolved IPs for %s: %w", host, lastErr)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}

	grafanaClient := cfg.GrafanaClient
	if grafanaClient == nil {
		grafanaClient = &http.Client{Timeout: 5 * time.Second}
	}

	rotationInterval := cfg.RotationInterval
	if rotationInterval < 0 {
		rotationInterval = 0 // explicitly disabled
	} else if rotationInterval == 0 && cfg.GrafanaURL != "" {
		rotationInterval = 5 * time.Minute
	}

	rotateFunc := cfg.RotateFunc
	if rotateFunc == nil {
		rotateFunc = func(ctx context.Context, gURL, curSess string) (string, error) {
			return oauth.RotateGrafanaSession(ctx, gURL, curSess, grafanaClient)
		}
	}

	sessionTTL := cfg.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = 2 * time.Hour
	}

	p := &Proxy{
		targetURL:        target,
		baseURL:          cfg.BaseURL,
		instanceURL:      cfg.InstanceURL,
		grafanaURL:       strings.TrimRight(cfg.GrafanaURL, "/"),
		rotationInterval: rotationInterval,
		sessionTTL:       sessionTTL,
		store:            s,
		logger:           cfg.Logger,
		peerClient:       peerClient,
		grafanaClient:    grafanaClient,
		rotateFunc:       rotateFunc,
	}

	keepaliveCtx, keepaliveCancel := context.WithCancel(context.Background())
	p.stopKeepalive = keepaliveCancel
	if p.rotationInterval > 0 && p.grafanaURL != "" {
		go p.startKeepaliveWorker(keepaliveCtx)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// For GET requests (e.g. SSE stream), route /mcp and /mcp/ to /mcp/sse for SSE compatibility.
			// For POST requests, keep /mcp (normalizing /mcp/ to /mcp) for Streamable HTTP compatibility.
			if req.Method == http.MethodGet && (req.URL.Path == "/mcp" || req.URL.Path == "/mcp/") {
				req.URL.Path = "/mcp/sse"
			} else if req.URL.Path == "/mcp/" {
				req.URL.Path = "/mcp"
			}
			// If request carries Mcp-Session-Id or X-Session-Id header but no query param,
			// populate query parameter sessionid so upstream go-sdk SSE handler accepts it seamlessly.
			if q := req.URL.Query(); q.Get("sessionid") == "" && q.Get("sessionId") == "" && q.Get("session_id") == "" {
				if sid := extractSessionID(req); sid != "" {
					q.Set("sessionid", sid)
					req.URL.RawQuery = q.Encode()
				}
			}
		},
		// FlushInterval: -1 ensures immediate flushing for SSE text/event-stream
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			// Register Streamable HTTP session if Mcp-Session-Id header is returned by upstream
			if resp != nil {
				if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
					regCtx, regCancel := context.WithTimeout(context.Background(), 5*time.Second)
					if regErr := p.store.RegisterMCPSession(regCtx, sid, p.instanceURL, 120*time.Second); regErr != nil {
						p.logger.Warn("Failed to register Streamable HTTP session in Redis", "session_id", sid, "error", regErr)
					} else {
						p.logger.Info("Registered active MCP Streamable HTTP session in Redis", "session_id", sid, "instance", p.instanceURL)
					}
					regCancel()
				}
			}

			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Header.Set("X-Accel-Buffering", "no")
				if resp.Request != nil && resp.Body != nil {
					var token, username string
					if t, ok := resp.Request.Context().Value(bearerTokenContextKey).(string); ok {
						token = t
					}
					username = resp.Request.Header.Get("X-Forwarded-User")

					sseCtx, cancel := context.WithCancel(resp.Request.Context())
					resp.Body = &sseBodyWrapper{
						ReadCloser: resp.Body,
						proxy:      p,
						ctx:        sseCtx,
						cancel:     cancel,
						token:      token,
						username:   username,
					}
				}
				return nil
			}

			// If upstream returned an error about session initialization being in progress,
			// retry transparently after a short backoff because notifications/initialized arrives
			// within milliseconds.
			if resp.Request != nil && resp.Body != nil {
				if bodyBytes, ok := resp.Request.Context().Value(requestBodyContextKey).([]byte); ok {
					respBytes, err := io.ReadAll(resp.Body)
					if err == nil {
						_ = resp.Body.Close()
						if bytes.Contains(respBytes, []byte("is invalid during session initialization")) && len(bodyBytes) > 0 {
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
						} else if resp.StatusCode == http.StatusNotFound && len(bodyBytes) > 0 {
							// If upstream returned 404, check for path adaptation between /mcp (Streamable HTTP) and /mcp/sse (SSE transport)
							var altPath string
							if resp.Request.URL.Path == "/mcp" {
								altPath = "/mcp/sse"
							} else if resp.Request.URL.Path == "/mcp/sse" {
								altPath = "/mcp"
							}
							if altPath != "" {
								retryURL := *resp.Request.URL
								retryURL.Path = altPath
								retryReq, rErr := http.NewRequestWithContext(resp.Request.Context(), resp.Request.Method, retryURL.String(), bytes.NewReader(bodyBytes))
								if rErr == nil {
									retryReq.Header = resp.Request.Header.Clone()
									retryResp, doErr := p.peerClient.Do(retryReq)
									if doErr == nil {
										retryRespBytes, err := io.ReadAll(retryResp.Body)
										_ = retryResp.Body.Close()
										if err == nil && retryResp.StatusCode != http.StatusNotFound {
											p.logger.Info("Transparent path adaptation succeeded",
												"original_path", resp.Request.URL.Path,
												"adapted_path", altPath,
												"status", retryResp.StatusCode,
											)
											retryResp.Body = io.NopCloser(bytes.NewReader(retryRespBytes))
											*resp = *retryResp
											return nil
										}
									}
								}
							}

							// If still not found and indicates missing session, attempt cross-replica peer forwarding
							if bytes.Contains(respBytes, []byte("session not found")) {
								sessID := extractSessionID(resp.Request)
								isPeerHop := resp.Request.Header.Get("X-MCP-Peer-Hop") == "true"
								if sessID != "" && !isPeerHop {
									ownerURL, err := p.store.GetMCPSession(resp.Request.Context(), sessID)
									if err == nil && ownerURL != "" && !isSelf(ownerURL, p.instanceURL) {
										p.logger.Info("Upstream MCP session not found locally; forwarding to peer replica",
											"session_id", sessID,
											"peer", ownerURL,
											"path", resp.Request.URL.Path,
										)
										targetURL, err := url.Parse(ownerURL)
										if err == nil && (targetURL.Scheme == "http" || targetURL.Scheme == "https") {
											peerReqURL := *resp.Request.URL
											peerReqURL.Scheme = targetURL.Scheme
											peerReqURL.Host = targetURL.Host
											peerReq, err := http.NewRequestWithContext(
												resp.Request.Context(),
												resp.Request.Method,
												peerReqURL.String(),
												bytes.NewReader(bodyBytes),
											)
											if err == nil {
												peerReq.Header = resp.Request.Header.Clone()
												peerReq.Header.Set("X-MCP-Peer-Hop", "true")
												if token, ok := resp.Request.Context().Value(bearerTokenContextKey).(string); ok && token != "" {
													peerReq.Header.Set("Authorization", "Bearer "+token)
												}
												peerResp, err := p.peerClient.Do(peerReq)
												if err != nil {
													p.logger.Warn("Cross-replica peer forwarding network error",
														"session_id", sessID,
														"peer", ownerURL,
														"error", err,
													)
												} else {
													peerRespBytes, err := io.ReadAll(peerResp.Body)
													_ = peerResp.Body.Close()
													if err == nil {
														if peerResp.StatusCode != http.StatusNotFound {
															p.logger.Info("Cross-replica peer forwarding succeeded",
																"session_id", sessID,
																"peer", ownerURL,
																"status", peerResp.StatusCode,
															)
															// Renew session TTL in Redis on successful forward
															renewCtx, renewCancel := context.WithTimeout(context.Background(), 2*time.Second)
															_ = p.store.RegisterMCPSession(renewCtx, sessID, ownerURL, 120*time.Second)
															renewCancel()

															peerResp.Body = io.NopCloser(bytes.NewReader(peerRespBytes))
															*resp = *peerResp
															return nil
														}
														// Peer returned 404; prune dead session from Redis immediately
														_ = p.store.DeleteMCPSession(resp.Request.Context(), sessID)
														p.logger.Info("Pruned dead MCP session from Redis following peer 404",
															"session_id", sessID,
															"peer", ownerURL,
														)
													}
												}
											}
										}
									}
								}
								p.logger.Warn("Upstream MCP session not found; client is using a stale session ID or server restarted",
									"session_id", sessID,
									"path", resp.Request.URL.Path,
									"query", resp.Request.URL.RawQuery,
								)
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

	grafanaSession := session.GrafanaSession
	username := session.Username

	// Record active session for continuous sliding keepalive
	p.touchActiveSession(token, username)

	// Trigger proactive sliding keep-alive rotation of Grafana session if due
	if p.grafanaURL != "" && p.rotationInterval > 0 && grafanaSession != "" {
		lastRotated := session.LastRotatedAt
		if lastRotated.IsZero() {
			lastRotated = session.CreatedAt
		}
		if time.Since(lastRotated) >= p.rotationInterval {
			p.triggerAsyncGrafanaRotation(token, grafanaSession, username)
		}
	}

	// Clone request and mutate headers for upstream forwarding
	outReq := r.Clone(r.Context())

	// Strip Bearer Authorization header so internal token never leaks upstream
	outReq.Header.Del("Authorization")

	// Inject grafana_session cookie
	existingCookie := r.Header.Get("Cookie")
	outReq.Header.Set("Cookie", buildCookieHeader(existingCookie, grafanaSession))
	outReq.Header.Set("X-Forwarded-User", username)

	p.logger.Debug("Forwarding authenticated MCP request",
		"username", username,
		"path", r.URL.Path,
		"method", r.Method,
	)

	// Buffer POST request bodies to support transparent retry on session initialization
	if r.Method == http.MethodPost && r.Body != nil {
		const maxBodyBytes = 4 * 1024 * 1024
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		if len(bodyBytes) > maxBodyBytes {
			p.logger.Warn("Request body exceeded maximum size limit", "size", len(bodyBytes), "limit", maxBodyBytes)
			http.Error(w, "Payload Too Large: MCP message body exceeds 4MB limit", http.StatusRequestEntityTooLarge)
			return
		}
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		outReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		outReq = outReq.WithContext(context.WithValue(outReq.Context(), requestBodyContextKey, bodyBytes))
	}

	outReq = outReq.WithContext(context.WithValue(outReq.Context(), bearerTokenContextKey, token))
	p.rp.ServeHTTP(w, outReq)
}

type sseBodyWrapper struct {
	io.ReadCloser
	proxy      *Proxy
	ctx        context.Context
	cancel     context.CancelFunc
	sessionID  string
	registered bool
	buf        []byte
	mu         sync.Mutex
	token      string
	username   string
}

func (w *sseBodyWrapper) Read(p []byte) (int, error) {
	n, err := w.ReadCloser.Read(p)
	if n > 0 {
		w.mu.Lock()
		if !w.registered {
			w.buf = append(w.buf, p[:n]...)
			if m := sessionIDRegex.FindSubmatch(w.buf); len(m) > 1 {
				w.sessionID = string(m[1])
				w.registered = true
				w.buf = nil
				sessID := w.sessionID

				// Register in Redis with 120s TTL
				regCtx, regCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if regErr := w.proxy.store.RegisterMCPSession(regCtx, sessID, w.proxy.instanceURL, 120*time.Second); regErr != nil {
					w.proxy.logger.Warn("Failed to register MCP session in Redis", "session_id", sessID, "error", regErr)
				} else {
					w.proxy.logger.Info("Registered active MCP SSE session in Redis", "session_id", sessID, "instance", w.proxy.instanceURL)
				}
				regCancel()

				// Launch background sliding renewal ticker
				go func(sid string, bgCtx context.Context) {
					ticker := time.NewTicker(30 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-bgCtx.Done():
							return
						case <-ticker.C:
							tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
							_ = w.proxy.store.RegisterMCPSession(tCtx, sid, w.proxy.instanceURL, 120*time.Second)
							tCancel()
							if w.token != "" {
								w.proxy.touchActiveSession(w.token, w.username)
							}
						}
					}
				}(sessID, w.ctx)
			} else if len(w.buf) > 4096 {
				w.buf = w.buf[len(w.buf)-1024:]
			}
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *sseBodyWrapper) Close() error {
	w.mu.Lock()
	sessID := w.sessionID
	w.cancel()
	w.mu.Unlock()

	// Never delete the session from Redis immediately on SSE stream closure.
	// Preserving the session in Redis for its TTL (120s sliding window) allows:
	// 1. Reconnection & token-refresh flows where the client closes the SSE stream
	//    and subsequently sends POST requests to an alternate replica.
	// 2. High-availability peer forwarding to continue routing to the session owner.
	// Truly dead sessions are cleaned up automatically via Redis TTL or pruned
	// upon receiving an explicit 404 from the peer replica.
	if sessID != "" {
		w.proxy.logger.Debug("SSE stream closed for MCP session (retained in Redis for TTL)", "session_id", sessID)
	}
	return w.ReadCloser.Close()
}

func extractSessionID(req *http.Request) string {
	if req == nil {
		return ""
	}
	// 1. Check MCP standard headers (Streamable HTTP & SSE)
	for _, h := range []string{"Mcp-Session-Id", "X-Session-Id", "Session-Id"} {
		if val := strings.TrimSpace(req.Header.Get(h)); val != "" {
			return val
		}
	}
	// 2. Check URL query parameters
	if req.URL != nil {
		q := req.URL.Query()
		for _, k := range []string{"sessionId", "sessionid", "session_id"} {
			if val := strings.TrimSpace(q.Get(k)); val != "" {
				return val
			}
		}
	}
	return ""
}

func isSelf(a, b string) bool {
	if a == b {
		return true
	}
	uA, errA := url.Parse(a)
	uB, errB := url.Parse(b)
	if errA == nil && errB == nil {
		return strings.EqualFold(uA.Host, uB.Host)
	}
	return false
}

type activeSessionInfo struct {
	token        string
	username     string
	lastActivity time.Time
}

func (p *Proxy) touchActiveSession(token, username string) {
	if token == "" {
		return
	}
	p.activeSessions.Store(token, &activeSessionInfo{
		token:        token,
		username:     username,
		lastActivity: time.Now(),
	})
}

func (p *Proxy) startKeepaliveWorker(ctx context.Context) {
	checkInterval := p.rotationInterval / 2
	if checkInterval > time.Minute {
		checkInterval = time.Minute
	}
	if checkInterval < 10*time.Millisecond {
		checkInterval = 10 * time.Millisecond
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.activeSessions.Range(func(key, val any) bool {
				token, ok := key.(string)
				if !ok || token == "" {
					p.activeSessions.Delete(key)
					return true
				}
				info, ok := val.(*activeSessionInfo)
				if !ok || info == nil {
					p.activeSessions.Delete(key)
					return true
				}

				// If session has been inactive longer than sessionTTL, prune it
				if time.Since(info.lastActivity) > p.sessionTTL {
					p.activeSessions.Delete(key)
					return true
				}

				if p.store == nil || p.grafanaURL == "" || p.rotationInterval <= 0 {
					return true
				}

				sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
				sess, err := p.store.GetSession(sCtx, info.token)
				sCancel()
				if err != nil {
					// Session expired or revoked in store
					p.activeSessions.Delete(key)
					return true
				}

				if sess.GrafanaSession == "" {
					return true
				}

				lastRotated := sess.LastRotatedAt
				if lastRotated.IsZero() {
					lastRotated = sess.CreatedAt
				}

				if time.Since(lastRotated) >= p.rotationInterval {
					p.triggerAsyncGrafanaRotation(info.token, sess.GrafanaSession, info.username)
				}
				return true
			})
		}
	}
}

// Close gracefully stops the proxy background keepalive worker.
func (p *Proxy) Close() {
	if p.stopKeepalive != nil {
		p.stopKeepalive()
	}
}

func (p *Proxy) triggerAsyncGrafanaRotation(token, currentSession, username string) {
	if nextRetry, ok := p.rotationCooldown.Load(token); ok {
		if time.Now().Before(nextRetry.(time.Time)) {
			return // Cooldown active after previous rotation failure to prevent upstream stampede
		}
		p.rotationCooldown.Delete(token)
	}

	if _, loaded := p.inFlightRotation.LoadOrStore(token, true); loaded {
		return // Rotation already in-flight for this session
	}

	go func() {
		defer p.inFlightRotation.Delete(token)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		lockID, err := crypto.GenerateRandomToken("lock_", 16)
		if err != nil {
			lockID = fmt.Sprintf("lock_%d", time.Now().UnixNano())
		}

		if p.store != nil {
			acquired, err := p.store.AcquireRotationLock(ctx, token, lockID, 15*time.Second)
			if err != nil {
				p.logger.Debug("Failed to acquire distributed rotation lock", "error", err)
			}
			if !acquired {
				return // Another replica/pod is already rotating this session
			}
			defer func() {
				_ = p.store.ReleaseRotationLock(ctx, token, lockID)
			}()

			// Re-fetch latest session under distributed lock to prevent double-rotation race conditions
			latestSession, err := p.store.GetSession(ctx, token)
			if err == nil && latestSession != nil {
				lastRotated := latestSession.LastRotatedAt
				if lastRotated.IsZero() {
					lastRotated = latestSession.CreatedAt
				}
				if time.Since(lastRotated) < p.rotationInterval {
					return // Already rotated by another pod/goroutine
				}
				if latestSession.GrafanaSession != "" {
					currentSession = latestSession.GrafanaSession
				}
			}
		}

		newSession, err := p.rotateFunc(ctx, p.grafanaURL, currentSession)
		if err != nil {
			if errors.Is(err, oauth.ErrGrafanaSessionInvalid) {
				p.activeSessions.Delete(token)
				p.logger.Warn("Grafana session expired or revoked upstream; pruned from active keepalive", "username", username)
				return
			}
			// Enforce a 1-minute cooldown so failure does not stampede Grafana on subsequent requests
			p.rotationCooldown.Store(token, time.Now().Add(1*time.Minute))
			p.logger.Warn("Failed to rotate Grafana session cookie in background", "error", err, "username", username)
			return
		}

		p.rotationCooldown.Delete(token)

		if newSession == "" {
			newSession = currentSession
		}

		if p.store != nil {
			if err := p.store.UpdateGrafanaSession(ctx, token, newSession, p.sessionTTL); err != nil {
				p.logger.Warn("Failed to persist rotated Grafana session cookie in store", "error", err, "username", username)
				return
			}
		}

		if newSession != currentSession {
			p.logger.Info("Successfully rotated and persisted Grafana session cookie in background",
				"username", username,
			)
		} else {
			p.logger.Info("Successfully kept Grafana session active in background (SkipRotation threshold)",
				"username", username,
			)
		}
	}()
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
