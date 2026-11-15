package oauth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPRateLimiter provides sliding-window in-memory rate limiting per client IP.
type IPRateLimiter struct {
	mu        sync.Mutex
	limits    map[string]*clientBucket
	maxReqs   int
	window    time.Duration
	cleanInt  time.Duration
	stopChan  chan struct{}
	closeOnce sync.Once
}

type clientBucket struct {
	count     int
	resetTime time.Time
}

// NewIPRateLimiter creates a new rate limiter allowing maxReqs within window.
func NewIPRateLimiter(maxReqs int, window time.Duration) *IPRateLimiter {
	limiter := &IPRateLimiter{
		limits:   make(map[string]*clientBucket),
		maxReqs:  maxReqs,
		window:   window,
		cleanInt: 5 * time.Minute,
		stopChan: make(chan struct{}),
	}
	go limiter.cleanupLoop()
	return limiter
}

// Allow checks if a request from the given IP is within rate limits.
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	bucket, exists := l.limits[ip]
	if !exists || now.After(bucket.resetTime) {
		l.limits[ip] = &clientBucket{
			count:     1,
			resetTime: now.Add(l.window),
		}
		return true
	}

	if bucket.count >= l.maxReqs {
		return false
	}

	bucket.count++
	return true
}

func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanInt)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopChan:
			return
		case now := <-ticker.C:
			l.mu.Lock()
			for ip, bucket := range l.limits {
				if now.After(bucket.resetTime) {
					delete(l.limits, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Close stops background cleanup goroutines safely and idempotently.
func (l *IPRateLimiter) Close() {
	l.closeOnce.Do(func() {
		close(l.stopChan)
	})
}

// ExtractClientIP extracts the client IP from RemoteAddr, or from X-Forwarded-For / X-Real-IP if RemoteAddr is a trusted proxy.
func ExtractClientIP(r *http.Request, trustedProxies ...[]*net.IPNet) string {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || remoteIPStr == "" {
		remoteIPStr = r.RemoteAddr
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
