package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"grafana-mcp-oauth/pkg/store"
)

type mockStore struct {
	mu          sync.Mutex
	sessions    map[string]*store.SessionData
	mcpSessions map[string]string
}

func (m *mockStore) SaveSession(ctx context.Context, token string, s *store.SessionData, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		m.sessions = make(map[string]*store.SessionData)
	}
	cp := *s
	m.sessions[token] = &cp
	return nil
}

func (m *mockStore) GetSession(ctx context.Context, token string) (*store.SessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	cp := *s
	return &cp, nil
}

func (m *mockStore) DeleteSession(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

func (m *mockStore) UpdateGrafanaSession(ctx context.Context, token string, newGrafanaSession string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[token]; ok {
		cp := *s
		cp.GrafanaSession = newGrafanaSession
		cp.LastRotatedAt = time.Now()
		if ttl > 0 {
			cp.ExpiresAt = time.Now().Add(ttl)
		}
		m.sessions[token] = &cp
		return nil
	}
	return fmt.Errorf("not found")
}

func (m *mockStore) SaveRefreshTokenSession(ctx context.Context, refreshToken string, session *store.SessionData, ttl time.Duration) error {
	return nil
}

func (m *mockStore) GetAndDeleteRefreshSession(ctx context.Context, refreshToken string) (*store.SessionData, error) {
	return nil, store.ErrInvalidRefreshToken
}

func (m *mockStore) SaveRefreshToken(ctx context.Context, refreshToken string, token string, ttl time.Duration) error {
	return nil
}

func (m *mockStore) GetTokenByRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	return "", fmt.Errorf("not found")
}

func (m *mockStore) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	return nil
}

func (m *mockStore) SavePendingAuth(ctx context.Context, state string, req *store.PendingAuthRequest, ttl time.Duration) error {
	return nil
}

func (m *mockStore) GetPendingAuth(ctx context.Context, state string) (*store.PendingAuthRequest, error) {
	return nil, store.ErrPendingAuthNotFound
}

func (m *mockStore) GetAndDeletePendingAuth(ctx context.Context, state string) (*store.PendingAuthRequest, error) {
	return nil, store.ErrPendingAuthNotFound
}

func (m *mockStore) DeletePendingAuth(ctx context.Context, state string) error {
	return nil
}

func (m *mockStore) SaveAuthCode(ctx context.Context, code string, authCode *store.AuthCodeContext, ttl time.Duration) error {
	return nil
}

func (m *mockStore) GetAuthCode(ctx context.Context, code string) (*store.AuthCodeContext, error) {
	return nil, store.ErrAuthCodeNotFound
}

func (m *mockStore) GetAndDeleteAuthCode(ctx context.Context, code string) (*store.AuthCodeContext, error) {
	return nil, store.ErrAuthCodeNotFound
}

func (m *mockStore) DeleteAuthCode(ctx context.Context, code string) error {
	return nil
}

func (m *mockStore) RegisterMCPSession(ctx context.Context, sessionID string, instanceURL string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mcpSessions == nil {
		m.mcpSessions = make(map[string]string)
	}
	m.mcpSessions[sessionID] = instanceURL
	return nil
}

func (m *mockStore) GetMCPSession(ctx context.Context, sessionID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mcpSessions == nil {
		return "", store.ErrSessionNotFound
	}
	url, ok := m.mcpSessions[sessionID]
	if !ok {
		return "", store.ErrSessionNotFound
	}
	return url, nil
}

func (m *mockStore) DeleteMCPSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mcpSessions != nil {
		delete(m.mcpSessions, sessionID)
	}
	return nil
}

func (m *mockStore) AcquireRotationLock(ctx context.Context, token, lockID string, ttl time.Duration) (bool, error) {
	return true, nil
}

func (m *mockStore) ReleaseRotationLock(ctx context.Context, token, lockID string) error {
	return nil
}

func TestProxy_Authentication(t *testing.T) {
	var receivedCookie string
	var receivedAuthHeader string
	var receivedUser string

	// Upstream mock stock mcp-grafana
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookie = r.Header.Get("Cookie")
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedUser = r.Header.Get("X-Forwarded-User")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"status":"ok"}}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-mcp-token": {
				GrafanaSession: "secret-cookie-xyz-123",
				Username:       "alice",
				Email:          "alice@example.com",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://gateway:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	// 1. Missing Token -> 401
	req := httptest.NewRequest(http.MethodGet, "http://gateway:8080/mcp/sse", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if wwwAuth != `Bearer resource_metadata="http://gateway:8080/.well-known/oauth-protected-resource"` {
		t.Errorf("unexpected WWW-Authenticate header: %s", wwwAuth)
	}

	// 2. Invalid Token -> 401
	req = httptest.NewRequest(http.MethodGet, "http://gateway:8080/mcp/sse", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	// 3. Valid Token -> Forwarded with Cookie and Authorization stripped
	req = httptest.NewRequest(http.MethodPost, "http://gateway:8080/mcp/messages", nil)
	req.Header.Set("Authorization", "Bearer valid-mcp-token")
	req.Header.Set("Cookie", "other_cookie=value")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if receivedAuthHeader != "" {
		t.Errorf("expected Authorization header to be stripped, got: %s", receivedAuthHeader)
	}
	expectedCookie := "other_cookie=value; grafana_session=secret-cookie-xyz-123"
	if receivedCookie != expectedCookie {
		t.Errorf("expected Cookie %q, got %q", expectedCookie, receivedCookie)
	}
	if receivedUser != "alice" {
		t.Errorf("expected X-Forwarded-User 'alice', got %q", receivedUser)
	}

	// 4. Client attempts Cookie Smuggling / Precedence attack with malicious grafana_session
	req = httptest.NewRequest(http.MethodPost, "http://gateway:8080/mcp/messages", nil)
	req.Header.Set("Authorization", "Bearer valid-mcp-token")
	req.Header.Set("Cookie", "grafana_session=malicious_attacker_session; other_cookie=value")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	expectedSanitizedCookie := "other_cookie=value; grafana_session=secret-cookie-xyz-123"
	if receivedCookie != expectedSanitizedCookie {
		t.Errorf("Cookie smuggling prevention failed! expected %q, got %q", expectedSanitizedCookie, receivedCookie)
	}
}

func TestProxy_SSEStreaming(t *testing.T) {
	// Upstream mock that writes an initial SSE event, then waits
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}
		_, _ = w.Write([]byte("event: endpoint\ndata: /mcp/messages?sessionId=s1\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-999",
				Username:       "bob",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/mcp/sse", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "event: endpoint\ndata: /mcp/messages?sessionId=s1\n\n" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestProxy_RetryOnSessionInitialization(t *testing.T) {
	attempts := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"method \"tools/call\" is invalid during session initialization"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"user_info"}]}}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-999",
				Username:       "bob",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp/messages?sessionId=test-sess", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"user_info"`) {
		t.Fatalf("expected retry response to contain user_info, got: %s", string(body))
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestProxy_SessionNotFound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("session not found"))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-999",
				Username:       "bob",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp/sse?sessionid=stale-id", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "session not found") {
		t.Fatalf("expected body to contain 'session not found', got: %s", string(body))
	}
}

func TestProxy_CrossReplicaPeerForwarding(t *testing.T) {
	// Upstream 1 (Replica 1 owns session "sess-replica-1")
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessID := r.URL.Query().Get("sessionId")
		if sessID == "sess-replica-1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"handled_by_replica_1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("session not found"))
	}))
	defer upstream1.Close()

	// Upstream 2 (Replica 2 does not own session "sess-replica-1")
	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("session not found"))
	}))
	defer upstream2.Close()

	sharedStore := &mockStore{
		sessions: map[string]*store.SessionData{
			"test-bearer-token": {
				GrafanaSession: "grafana-cookie-123",
				Username:       "alice",
			},
		},
		mcpSessions: make(map[string]string),
	}

	// Create Proxy 1
	var proxy1Server *httptest.Server
	p1, err := NewProxy(Config{
		TargetURL: upstream1.URL,
		BaseURL:   "http://replica1:8080",
	}, sharedStore)
	if err != nil {
		t.Fatalf("NewProxy 1 failed: %v", err)
	}
	proxy1Server = httptest.NewServer(p1)
	defer proxy1Server.Close()
	p1.instanceURL = proxy1Server.URL

	// Create Proxy 2
	p2, err := NewProxy(Config{
		TargetURL:   upstream2.URL,
		BaseURL:     "http://replica2:8080",
		InstanceURL: "http://replica2-internal:8080",
	}, sharedStore)
	if err != nil {
		t.Fatalf("NewProxy 2 failed: %v", err)
	}
	proxy2Server := httptest.NewServer(p2)
	defer proxy2Server.Close()

	// Register session "sess-replica-1" pointing to Proxy 1
	_ = sharedStore.RegisterMCPSession(context.Background(), "sess-replica-1", proxy1Server.URL, 1*time.Minute)

	// Client sends POST to Proxy 2 for "sess-replica-1"
	req, _ := http.NewRequest(
		http.MethodPost,
		proxy2Server.URL+"/mcp/messages?sessionId=sess-replica-1",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`),
	)
	req.Header.Set("Authorization", "Bearer test-bearer-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "handled_by_replica_1") {
		t.Fatalf("expected body to contain 'handled_by_replica_1', got: %s", string(body))
	}
}

func TestProxy_PayloadTooLarge(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-123",
				Username:       "alice",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	// 5MB payload
	hugeBody := strings.Repeat("A", 5*1024*1024)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp/messages", strings.NewReader(hugeBody))
	req.Header.Set("Authorization", "Bearer valid-token")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Payload Too Large, got %d", resp.StatusCode)
	}
}

func TestProxy_PeerForwarding_DeadSessionPruning(t *testing.T) {
	// Upstream 1 returns 404 session not found
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	}))
	defer upstream1.Close()

	// Upstream 2 also returns 404 session not found
	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	}))
	defer upstream2.Close()

	sharedStore := &mockStore{
		sessions: map[string]*store.SessionData{
			"test-bearer-token": {
				GrafanaSession: "grafana-cookie-123",
				Username:       "alice",
			},
		},
		mcpSessions: make(map[string]string),
	}

	p1, _ := NewProxy(Config{
		TargetURL: upstream1.URL,
		BaseURL:   "http://replica1:8080",
	}, sharedStore)
	proxy1Server := httptest.NewServer(p1)
	defer proxy1Server.Close()
	p1.instanceURL = proxy1Server.URL

	p2, _ := NewProxy(Config{
		TargetURL:   upstream2.URL,
		BaseURL:     "http://replica2:8080",
		InstanceURL: "http://replica2-internal:8080",
	}, sharedStore)
	proxy2Server := httptest.NewServer(p2)
	defer proxy2Server.Close()

	// Register session pointing to Proxy 1
	deadSessionID := "dead-session-999"
	_ = sharedStore.RegisterMCPSession(context.Background(), deadSessionID, proxy1Server.URL, 1*time.Minute)

	// Client sends POST to Proxy 2 for deadSessionID
	req, _ := http.NewRequest(
		http.MethodPost,
		proxy2Server.URL+"/mcp/messages?sessionId="+deadSessionID,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`),
	)
	req.Header.Set("Authorization", "Bearer test-bearer-token")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}

	// Verify dead session was pruned from store
	_, err = sharedStore.GetMCPSession(context.Background(), deadSessionID)
	if err == nil {
		t.Errorf("expected dead session to be pruned from store, but it was still present")
	}
}

func TestProxy_PathRewrite_MCPToSSE(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-123",
				Username:       "alice",
			},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstream.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	// 1. GET /mcp -> rewrites to /mcp/sse
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if receivedPath != "/mcp/sse" {
		t.Errorf("expected upstream path /mcp/sse, got %s", receivedPath)
	}

	// 2. POST /mcp/ -> normalizes to /mcp for Streamable HTTP
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/mcp/", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if receivedPath != "/mcp" {
		t.Errorf("expected upstream path /mcp, got %s", receivedPath)
	}

	// 3. POST /mcp -> stays /mcp for Streamable HTTP
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if receivedPath != "/mcp" {
		t.Errorf("expected upstream path /mcp, got %s", receivedPath)
	}

	// 4. GET /mcp/sse -> stays /mcp/sse
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/mcp/sse", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if receivedPath != "/mcp/sse" {
		t.Errorf("expected upstream path /mcp/sse, got %s", receivedPath)
	}
}

func TestProxy_TransparentPathAdaptation(t *testing.T) {
	// Upstream only has /mcp (Streamable HTTP)
	upstreamStreamable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result":"streamable_ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer upstreamStreamable.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {GrafanaSession: "sess-123", Username: "alice"},
		},
	}

	p, err := NewProxy(Config{
		TargetURL: upstreamStreamable.URL,
		BaseURL:   "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	server := httptest.NewServer(p)
	defer server.Close()

	// Client sends POST /mcp/sse (e.g. legacy configured client), proxy transparently adapts to /mcp
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp/sse", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after path adaptation, got %d: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "streamable_ok") {
		t.Errorf("expected streamable_ok in response, got %s", string(body))
	}
}

func TestProxy_CrossReplicaPeerForwarding_StreamableHTTPHeader(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"handled_by_replica_1_streamable"}`))
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	}))
	defer upstream2.Close()

	sharedStore := &mockStore{
		sessions: map[string]*store.SessionData{
			"test-bearer-token": {
				GrafanaSession: "grafana-cookie-123",
				Username:       "alice",
			},
		},
		mcpSessions: make(map[string]string),
	}

	p1, _ := NewProxy(Config{
		TargetURL: upstream1.URL,
		BaseURL:   "http://replica1:8080",
	}, sharedStore)
	proxy1Server := httptest.NewServer(p1)
	defer proxy1Server.Close()
	p1.instanceURL = proxy1Server.URL

	p2, _ := NewProxy(Config{
		TargetURL:   upstream2.URL,
		BaseURL:     "http://replica2:8080",
		InstanceURL: "http://replica2-internal:8080",
	}, sharedStore)
	proxy2Server := httptest.NewServer(p2)
	defer proxy2Server.Close()

	streamSessID := "stream-session-xyz-456"
	_ = sharedStore.RegisterMCPSession(context.Background(), streamSessID, proxy1Server.URL, 1*time.Minute)

	// Client sends POST to Proxy 2 using Mcp-Session-Id header (no query parameters)
	req, _ := http.NewRequest(
		http.MethodPost,
		proxy2Server.URL+"/mcp/messages",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`),
	)
	req.Header.Set("Authorization", "Bearer test-bearer-token")
	req.Header.Set("Mcp-Session-Id", streamSessID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "handled_by_replica_1_streamable") {
		t.Fatalf("expected body to contain 'handled_by_replica_1_streamable', got: %s", string(body))
	}
}

func TestProxy_SSEDisconnect_SessionRetainedInStore(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if ok {
			_, _ = w.Write([]byte("event: endpoint\ndata: /mcp/sse?sessionid=retain-test-session\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-999",
				Username:       "bob",
			},
		},
		mcpSessions: make(map[string]string),
	}

	p, _ := NewProxy(Config{
		TargetURL:   upstream.URL,
		BaseURL:     "http://localhost:8080",
		InstanceURL: "http://localhost:8080",
	}, s)
	server := httptest.NewServer(p)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/mcp/sse", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	// Read event so session is registered
	buf := make([]byte, 256)
	_, _ = resp.Body.Read(buf)

	// Close the connection explicitly
	_ = resp.Body.Close()

	// Verify that the session is STILL retained in store (NOT deleted on disconnect)
	loc, err := s.GetMCPSession(context.Background(), "retain-test-session")
	if err != nil || loc == "" {
		t.Fatalf("expected session to be retained in store after disconnect, but got error: %v", err)
	}
}

func TestProxy_PeerForwarding_BlockedMetadataIPs(t *testing.T) {
	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				GrafanaSession: "sess-999",
				Username:       "bob",
			},
		},
		mcpSessions: map[string]string{
			// Point session to cloud metadata IP
			"metadata-attack-session": "http://169.254.169.254:80",
		},
	}

	// Upstream that returns 404 session not found to trigger peer forwarding
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("session not found"))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{
		TargetURL:   upstream.URL,
		BaseURL:     "http://localhost:8080",
		InstanceURL: "http://localhost:8080",
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	server := httptest.NewServer(p)
	defer server.Close()

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp?sessionId=metadata-attack-session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Peer forward to metadata IP must be blocked, returning 404
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 when peer forwarding to metadata IP is blocked, got %d", resp.StatusCode)
	}
}

func TestProxy_SlidingKeepAlive_GrafanaSessionRotation(t *testing.T) {
	var receivedCookie string
	var cookieMu sync.Mutex

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieMu.Lock()
		receivedCookie = r.Header.Get("Cookie")
		cookieMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"valid-token": {
				UserID:         "user-1",
				Username:       "alice",
				GrafanaSession: "initial-cookie-111",
				CreatedAt:      time.Now().Add(-15 * time.Minute),
				LastRotatedAt:  time.Now().Add(-10 * time.Minute),
			},
		},
	}

	rotationCalled := make(chan string, 5)
	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 5 * time.Minute,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			rotationCalled <- currentSession
			return "rotated-cookie-222", nil
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	server := httptest.NewServer(p)
	defer server.Close()

	// 1. First request triggers async rotation, but forwards immediately with initial cookie
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cookieMu.Lock()
	firstSentCookie := receivedCookie
	cookieMu.Unlock()
	if !strings.Contains(firstSentCookie, "grafana_session=initial-cookie-111") {
		t.Errorf("first request should carry initial cookie, got: %s", firstSentCookie)
	}

	// 2. Wait for background rotation to complete
	select {
	case oldSess := <-rotationCalled:
		if oldSess != "initial-cookie-111" {
			t.Errorf("expected rotator called with initial-cookie-111, got: %s", oldSess)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background rotation was not triggered")
	}

	// Allow store update to persist
	time.Sleep(50 * time.Millisecond)

	// Verify store was updated with rotated cookie
	sess, err := s.GetSession(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if sess.GrafanaSession != "rotated-cookie-222" {
		t.Errorf("expected store updated to rotated-cookie-222, got %s", sess.GrafanaSession)
	}

	// 3. Second request must now forward with the newly rotated cookie
	req2, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer valid-token")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	resp2.Body.Close()

	cookieMu.Lock()
	secondSentCookie := receivedCookie
	cookieMu.Unlock()
	if !strings.Contains(secondSentCookie, "grafana_session=rotated-cookie-222") {
		t.Errorf("second request should carry rotated cookie, got: %s", secondSentCookie)
	}
}

func TestProxy_SlidingKeepAlive_InFlightDeduplication(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"dedup-token": {
				UserID:         "user-1",
				Username:       "alice",
				GrafanaSession: "cookie-before-dedup",
				CreatedAt:      time.Now().Add(-10 * time.Minute),
				LastRotatedAt:  time.Now().Add(-10 * time.Minute),
			},
		},
	}

	var rotateCalls int32
	rotateStarted := make(chan struct{}, 1)
	rotateRelease := make(chan struct{})

	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 1 * time.Minute,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			atomic.AddInt32(&rotateCalls, 1)
			select {
			case rotateStarted <- struct{}{}:
			default:
			}
			<-rotateRelease
			return "cookie-after-dedup", nil
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	server := httptest.NewServer(p)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)

	// Send first request which starts the in-flight rotation
	req1, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Bearer dedup-token")
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	resp1.Body.Close()

	select {
	case <-rotateStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("rotate was not started within 2s")
	}

	// Send concurrent requests while rotation is still in flight
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dedup-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("concurrent request failed: %v", err)
		}
		resp.Body.Close()
	}

	// Release the in-flight rotation
	close(rotateRelease)
	time.Sleep(50 * time.Millisecond)

	// Verify only exactly 1 rotation occurred despite 6 total requests
	if calls := atomic.LoadInt32(&rotateCalls); calls != 1 {
		t.Errorf("expected exactly 1 rotation call, got %d", calls)
	}
}

func TestProxy_SlidingKeepAlive_ErrorResilience(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"error-token": {
				UserID:         "user-1",
				Username:       "alice",
				GrafanaSession: "resilient-cookie",
				CreatedAt:      time.Now().Add(-10 * time.Minute),
				LastRotatedAt:  time.Now().Add(-10 * time.Minute),
			},
		},
	}

	var rotateCalls int32
	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 1 * time.Minute,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			atomic.AddInt32(&rotateCalls, 1)
			return "", fmt.Errorf("simulated network error to Grafana")
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	server := httptest.NewServer(p)
	defer server.Close()

	// 1. First request triggers async rotation which fails
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer error-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK despite background rotation failure, got %d", resp.StatusCode)
	}

	// Wait for background rotation goroutine to complete and set failure cooldown
	time.Sleep(50 * time.Millisecond)

	// 2. Second request arrives immediately: must NOT trigger rotateFunc again due to failure cooldown
	req2, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer error-token")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on second request, got %d", resp2.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)
	if calls := atomic.LoadInt32(&rotateCalls); calls != 1 {
		t.Errorf("expected exactly 1 rotate call due to cooldown backoff, got %d", calls)
	}

	// Verify original cookie remains intact
	sess, _ := s.GetSession(context.Background(), "error-token")
	if sess.GrafanaSession != "resilient-cookie" {
		t.Errorf("cookie should remain resilient-cookie, got: %s", sess.GrafanaSession)
	}
}

func TestProxy_BackgroundKeepaliveWorker(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	initialExpiresAt := time.Now().Add(10 * time.Minute)
	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"bg-token": {
				UserID:         "user-bg",
				Username:       "bob",
				GrafanaSession: "cookie-initial-bg",
				CreatedAt:      time.Now().Add(-10 * time.Minute),
				LastRotatedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt:      initialExpiresAt,
			},
		},
	}

	rotationCh := make(chan string, 5)
	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 40 * time.Millisecond,
		SessionTTL:       2 * time.Hour,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			rotationCh <- currentSession
			return "cookie-rotated-bg", nil
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	server := httptest.NewServer(p)
	defer server.Close()

	// Send an initial request to touch/register the active session
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer bg-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("initial request failed: %v", err)
	}
	resp.Body.Close()

	// Drain any immediate rotation from ServeHTTP
	select {
	case <-rotationCh:
	case <-time.After(500 * time.Millisecond):
	}

	// Update LastRotatedAt in store to simulate rotation interval elapsed
	s.mu.Lock()
	if sess, ok := s.sessions["bg-token"]; ok {
		sess.LastRotatedAt = time.Now().Add(-100 * time.Millisecond)
		sess.GrafanaSession = "cookie-before-bg-worker"
	}
	s.mu.Unlock()

	// DO NOT send any more HTTP requests!
	// The background keepalive worker MUST detect that rotation is due and rotate automatically!
	select {
	case oldSess := <-rotationCh:
		if oldSess != "cookie-before-bg-worker" {
			t.Errorf("expected bg worker rotation with cookie-before-bg-worker, got: %s", oldSess)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background keepalive worker did NOT trigger rotation without incoming requests!")
	}

	// Verify store was updated and session TTL was slid forward
	time.Sleep(50 * time.Millisecond)
	updatedSess, err := s.GetSession(context.Background(), "bg-token")
	if err != nil {
		t.Fatalf("failed to get updated session: %v", err)
	}
	if updatedSess.GrafanaSession != "cookie-rotated-bg" {
		t.Errorf("expected store session updated to cookie-rotated-bg, got: %s", updatedSess.GrafanaSession)
	}
	if !updatedSess.ExpiresAt.After(initialExpiresAt) {
		t.Errorf("expected ExpiresAt to slide forward past %v, got %v", initialExpiresAt, updatedSess.ExpiresAt)
	}
}

func TestProxy_SlidingKeepAlive_SkipRotationThreshold(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"skip-token": {
				UserID:         "user-skip",
				Username:       "charlie",
				GrafanaSession: "steady-cookie",
				CreatedAt:      time.Now().Add(-10 * time.Minute),
				LastRotatedAt:  time.Now().Add(-10 * time.Minute),
				ExpiresAt:      time.Now().Add(30 * time.Minute),
			},
		},
	}

	rotatedCalled := make(chan struct{}, 1)
	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 1 * time.Minute,
		SessionTTL:       2 * time.Hour,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			rotatedCalled <- struct{}{}
			// Return same cookie simulating Grafana 200 OK without Set-Cookie (SkipRotationTime)
			return currentSession, nil
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	server := httptest.NewServer(p)
	defer server.Close()

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer skip-token")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	select {
	case <-rotatedCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation was not called")
	}

	time.Sleep(50 * time.Millisecond)

	sess, err := s.GetSession(context.Background(), "skip-token")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	// Cookie value remains steady
	if sess.GrafanaSession != "steady-cookie" {
		t.Errorf("expected cookie to remain steady-cookie, got: %s", sess.GrafanaSession)
	}
	// But LastRotatedAt was updated and ExpiresAt was slid forward
	if time.Since(sess.LastRotatedAt) > 2*time.Second {
		t.Errorf("expected LastRotatedAt updated to now, got: %v", sess.LastRotatedAt)
	}
	if !sess.ExpiresAt.After(time.Now().Add(1 * time.Hour)) {
		t.Errorf("expected ExpiresAt slid forward to ~2h, got: %v", sess.ExpiresAt)
	}
}

func TestProxy_BackgroundKeepalive_RemainingTTLOnIdleSession(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	defer upstream.Close()

	s := &mockStore{
		sessions: map[string]*store.SessionData{
			"idle-token": {
				UserID:         "user-idle",
				Username:       "dave",
				GrafanaSession: "cookie-before-idle-rot",
				CreatedAt:      time.Now().Add(-50 * time.Minute),
				LastRotatedAt:  time.Now().Add(-50 * time.Minute),
				ExpiresAt:      time.Now().Add(10 * time.Minute),
			},
		},
	}

	rotated := make(chan struct{}, 1)
	p, err := NewProxy(Config{
		TargetURL:        upstream.URL,
		BaseURL:          "http://localhost:8080",
		InstanceURL:      "http://localhost:8080",
		GrafanaURL:       "http://grafana:3000",
		RotationInterval: 30 * time.Millisecond,
		SessionTTL:       1 * time.Hour,
		RotateFunc: func(ctx context.Context, grafanaURL string, currentSession string) (string, error) {
			rotated <- struct{}{}
			return "cookie-after-idle-rot", nil
		},
	}, s)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	// Simulate an active session whose lastActivity was 45 minutes ago (15 minutes remaining on 1h TTL)
	p.activeSessions.Store("idle-token", &activeSessionInfo{
		token:        "idle-token",
		username:     "dave",
		lastActivity: time.Now().Add(-45 * time.Minute),
	})

	select {
	case <-rotated:
	case <-time.After(2 * time.Second):
		t.Fatal("expected background rotation for idle session")
	}

	time.Sleep(50 * time.Millisecond)

	sess, err := s.GetSession(context.Background(), "idle-token")
	if err != nil {
		t.Fatalf("failed to get updated session: %v", err)
	}
	if sess.GrafanaSession != "cookie-after-idle-rot" {
		t.Errorf("expected rotated cookie, got: %s", sess.GrafanaSession)
	}

	// The session expiration must be bounded to ~15 minutes (lastActivity + sessionTTL), NOT extended to a full 1h from now
	maxExpectedExpiry := time.Now().Add(20 * time.Minute)
	minExpectedExpiry := time.Now().Add(10 * time.Minute)
	if sess.ExpiresAt.After(maxExpectedExpiry) {
		t.Errorf("expected ExpiresAt bounded by remaining idle TTL (~15m), but got: %v (more than %v)", sess.ExpiresAt, maxExpectedExpiry)
	}
	if sess.ExpiresAt.Before(minExpectedExpiry) {
		t.Errorf("expected ExpiresAt at least %v, but got: %v", minExpectedExpiry, sess.ExpiresAt)
	}
}
