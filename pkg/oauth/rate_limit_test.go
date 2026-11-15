package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

func TestRedisRateLimiter_DistributedSynchronization(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()

	// Simulate Replica 1 and Replica 2 sharing the same Redis instance
	replica1 := oauth.NewRedisRateLimiter(rdb, "mcp:ratelimit:test", 3, 2*time.Second, nil)
	replica2 := oauth.NewRedisRateLimiter(rdb, "mcp:ratelimit:test", 3, 2*time.Second, nil)
	defer replica1.Close()
	defer replica2.Close()

	clientIP := "192.0.2.1"

	// Request 1 on Replica 1
	assert.True(t, replica1.Allow(ctx, clientIP), "replica1 request 1 should be allowed")
	// Request 2 on Replica 2
	assert.True(t, replica2.Allow(ctx, clientIP), "replica2 request 2 should be allowed")
	// Request 3 on Replica 1
	assert.True(t, replica1.Allow(ctx, clientIP), "replica1 request 3 should be allowed")
	// Request 4 on Replica 2 - limit reached (3 requests), should be rejected across replicas
	assert.False(t, replica2.Allow(ctx, clientIP), "replica2 request 4 should be rejected across replicas")
	assert.False(t, replica1.Allow(ctx, clientIP), "replica1 request 5 should also be rejected")

	// Fast-forward miniredis time by 3 seconds
	mr.FastForward(3 * time.Second)

	// After window expires, counter resets
	assert.True(t, replica1.Allow(ctx, clientIP), "request after window expiration should be allowed")
}

func TestRedisRateLimiter_FailOpenOnNilClient(t *testing.T) {
	limiter := oauth.NewRedisRateLimiter(nil, "mcp:ratelimit:nil", 10, time.Minute, nil)
	assert.True(t, limiter.Allow(context.Background(), "192.0.2.5"), "nil redis client should fail open")
}
