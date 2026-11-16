package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"grafana-mcp-oauth/pkg/store"
)

type mockStore struct {
	sessions map[string]*store.SessionData
}

func (m *mockStore) SaveSession(ctx context.Context, token string, s *store.SessionData, ttl time.Duration) error {
	m.sessions[token] = s
	return nil
}

func (m *mockStore) GetSession(ctx context.Context, token string) (*store.SessionData, error) {
	s, ok := m.sessions[token]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return s, nil
}

func (m *mockStore) DeleteSession(ctx context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *mockStore) UpdateGrafanaSession(ctx context.Context, token string, newGrafanaSession string, ttl time.Duration) error {
	if s, ok := m.sessions[token]; ok {
		s.GrafanaSession = newGrafanaSession
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
