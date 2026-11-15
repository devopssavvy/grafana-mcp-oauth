package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter defines the interface for distributed rate limiting.
type RateLimiter interface {
	Allow(ctx context.Context, ip string) bool
	Close()
}

// RedisRateLimiter provides atomic distributed sliding/fixed-window rate limiting in Redis per client IP.
// All gateway replicas share the exact same synchronized counter in Redis. No in-memory bucket table
// is maintained to prevent inter-replica desynchronization and eliminate memory exhaustion risks.
type RedisRateLimiter struct {
	client  redis.UniversalClient
	prefix  string
	maxReqs int
	window  time.Duration
	logger  *slog.Logger
	script  *redis.Script
}

// luaRateLimitScript provides atomic rate limit counting with automatic key expiration.
var luaRateLimitScript = redis.NewScript(`
	local current = redis.call('INCR', KEYS[1])
	if current == 1 then
		redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
	elseif redis.call('TTL', KEYS[1]) < 0 then
		redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
	end
	if current > tonumber(ARGV[1]) then
		return 0
	end
	return 1
`)

// NewRedisRateLimiter creates a new RedisRateLimiter.
func NewRedisRateLimiter(client redis.UniversalClient, prefix string, maxReqs int, window time.Duration, logger *slog.Logger) *RedisRateLimiter {
	if prefix == "" {
		prefix = "mcp:ratelimit"
	}
	if window <= 0 {
		window = time.Minute
	}
	if maxReqs <= 0 {
		maxReqs = 60
	}
	return &RedisRateLimiter{
		client:  client,
		prefix:  prefix,
		maxReqs: maxReqs,
		window:  window,
		logger:  logger,
		script:  luaRateLimitScript,
	}
}

// Allow atomically checks and increments the request counter in Redis for the given IP.
// If Redis is nil or fails, it fails open to prevent blocking legitimate authentication traffic.
func (r *RedisRateLimiter) Allow(ctx context.Context, ip string) bool {
	if r == nil || r.client == nil || ip == "" {
		return true
	}
	key := fmt.Sprintf("%s:%s", r.prefix, ip)
	windowSecs := int(r.window.Seconds())
	if windowSecs <= 0 {
		windowSecs = 60
	}

	res, err := r.script.Run(ctx, r.client, []string{key}, r.maxReqs, windowSecs).Int()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("Redis rate limit check failed; failing open", "error", err, "ip", ip, "key", key)
		}
		return true
	}
	return res == 1
}

// Close is a no-op for RedisRateLimiter as Redis TTL handles expiration without local background goroutines.
func (r *RedisRateLimiter) Close() {}

// ExtractClientIP extracts the client IP from RemoteAddr, or from X-Forwarded-For / X-Real-IP if RemoteAddr is a trusted proxy.
func ExtractClientIP(r *http.Request, trustedProxies ...[]*net.IPNet) string {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || remoteIPStr == "" {
		remoteIPStr = strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
	}
	remoteIP := net.ParseIP(remoteIPStr)

	var proxies []*net.IPNet
	if len(trustedProxies) > 0 {
		proxies = trustedProxies[0]
	}

	// Only inspect forwarded headers if remote peer is explicitly in trustedProxies
	if remoteIP != nil && isTrustedPeer(remoteIP, proxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				ip := strings.TrimSpace(parts[0])
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	return remoteIPStr
}

func isTrustedPeer(ip net.IP, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 || ip == nil {
		return false
	}
	for _, cidr := range trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
