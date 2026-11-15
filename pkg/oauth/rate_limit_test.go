package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/oauth"
)

func TestExtractClientIP_UntrustedDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
	req.RemoteAddr = "203.0.113.195:45678"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")
	req.Header.Set("X-Real-IP", "198.51.100.2")

	// When trustedProxies is omitted or nil, XFF/X-Real-IP MUST be ignored to prevent IP spoofing
	ip := oauth.ExtractClientIP(req)
	assert.Equal(t, "203.0.113.195", ip)

	ipNil := oauth.ExtractClientIP(req, nil)
	assert.Equal(t, "203.0.113.195", ipNil)
}

func TestExtractClientIP_WithTrustedProxies(t *testing.T) {
	trusted := config.ParseTrustedProxies("10.0.0.0/8, 127.0.0.1, ::1")
	require.NotEmpty(t, trusted)

	t.Run("untrusted remote peer ignores XFF and X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
		req.RemoteAddr = "192.168.1.50:54321"
		req.Header.Set("X-Forwarded-For", "203.0.113.5")
		req.Header.Set("X-Real-IP", "203.0.113.6")

		ip := oauth.ExtractClientIP(req, trusted)
		assert.Equal(t, "192.168.1.50", ip)
	})

	t.Run("trusted IPv4 proxy uses leftmost XFF client IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
		req.RemoteAddr = "10.0.1.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.2")

		ip := oauth.ExtractClientIP(req, trusted)
		assert.Equal(t, "203.0.113.77", ip)
	})

	t.Run("trusted proxy falls back to X-Real-IP if XFF empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
		req.RemoteAddr = "127.0.0.1:44321"
		req.Header.Set("X-Real-IP", "198.51.100.88")

		ip := oauth.ExtractClientIP(req, trusted)
		assert.Equal(t, "198.51.100.88", ip)
	})

	t.Run("trusted proxy with malformed XFF falls back to remote IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
		req.RemoteAddr = "10.0.1.1:12345"
		req.Header.Set("X-Forwarded-For", "not-a-valid-ip")

		ip := oauth.ExtractClientIP(req, trusted)
		assert.Equal(t, "10.0.1.1", ip)
	})

	t.Run("trusted IPv6 proxy loopback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp/auth/login", nil)
		req.RemoteAddr = "[::1]:56789"
		req.Header.Set("X-Forwarded-For", "2001:db8::1")

		ip := oauth.ExtractClientIP(req, trusted)
		assert.Equal(t, "2001:db8::1", ip)
	})
}

func TestIPRateLimiter_AllowAndClose(t *testing.T) {
	limiter := oauth.NewIPRateLimiter(2, 50*time.Millisecond)
	defer limiter.Close()

	clientIP := "192.0.2.1"
	assert.True(t, limiter.Allow(clientIP))
	assert.True(t, limiter.Allow(clientIP))
	assert.False(t, limiter.Allow(clientIP), "third request within window should be rejected")

	// Wait for window reset
	time.Sleep(60 * time.Millisecond)
	assert.True(t, limiter.Allow(clientIP), "request after window expiration should be allowed")

	// Verify Close is idempotent and does not panic
	limiter.Close()
	limiter.Close()
}
