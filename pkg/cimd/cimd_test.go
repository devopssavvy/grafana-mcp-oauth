package cimd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/cimd"
)

func TestValidateDocument(t *testing.T) {
	validDoc := &cimd.Document{
		ClientID:     "https://client.example.com/oauth/client.json",
		ClientName:   "Example Client",
		RedirectURIs: []string{"http://127.0.0.1/callback", "https://client.example.com/callback"},
	}

	t.Run("valid document", func(t *testing.T) {
		err := cimd.ValidateDocument(validDoc, "https://client.example.com/oauth/client.json")
		assert.NoError(t, err)
	})

	t.Run("nil document", func(t *testing.T) {
		err := cimd.ValidateDocument(nil, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
	})

	t.Run("missing client_id", func(t *testing.T) {
		doc := &cimd.Document{
			RedirectURIs: []string{"http://127.0.0.1/callback"},
		}
		err := cimd.ValidateDocument(doc, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing client_id")
	})

	t.Run("client_id mismatch", func(t *testing.T) {
		doc := &cimd.Document{
			ClientID:     "https://attacker.com/client.json",
			RedirectURIs: []string{"http://127.0.0.1/callback"},
		}
		err := cimd.ValidateDocument(doc, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not match requested client_id")
	})

	t.Run("missing redirect_uris", func(t *testing.T) {
		doc := &cimd.Document{
			ClientID:     "https://client.example.com/oauth/client.json",
			RedirectURIs: []string{},
		}
		err := cimd.ValidateDocument(doc, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain at least one redirect_uri")
	})

	t.Run("relative redirect_uri", func(t *testing.T) {
		doc := &cimd.Document{
			ClientID:     "https://client.example.com/oauth/client.json",
			RedirectURIs: []string{"/relative/callback"},
		}
		err := cimd.ValidateDocument(doc, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid redirect_uri")
	})

	t.Run("redirect_uri with fragment", func(t *testing.T) {
		doc := &cimd.Document{
			ClientID:     "https://client.example.com/oauth/client.json",
			RedirectURIs: []string{"http://127.0.0.1/callback#frag"},
		}
		err := cimd.ValidateDocument(doc, "https://client.example.com/oauth/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain fragment")
	})
}

func TestValidateRedirectURI(t *testing.T) {
	doc := &cimd.Document{
		ClientID: "https://client.example.com/oauth/client.json",
		RedirectURIs: []string{
			"http://127.0.0.1/callback",
			"http://localhost/mcp-auth",
			"https://app.example.com/auth/callback",
		},
	}

	t.Run("exact match non-loopback", func(t *testing.T) {
		assert.True(t, cimd.ValidateRedirectURI(doc, "https://app.example.com/auth/callback"))
		assert.False(t, cimd.ValidateRedirectURI(doc, "https://app.example.com/auth/other"))
		assert.False(t, cimd.ValidateRedirectURI(doc, "https://app.example.com:8443/auth/callback"))
	})

	t.Run("RFC 8252 loopback dynamic port matching", func(t *testing.T) {
		// 127.0.0.1 with ephemeral ports
		assert.True(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1:54321/callback"))
		assert.True(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1:8080/callback"))
		assert.True(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1/callback"))

		// localhost with ephemeral ports
		assert.True(t, cimd.ValidateRedirectURI(doc, "http://localhost:38291/mcp-auth"))
		assert.True(t, cimd.ValidateRedirectURI(doc, "http://localhost/mcp-auth"))

		// Hostname mismatch between 127.0.0.1 and localhost is rejected per RFC 8252 Section 7.3
		assert.False(t, cimd.ValidateRedirectURI(doc, "http://localhost:54321/callback"))
		assert.False(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1:38291/mcp-auth"))

		// Mismatched path
		assert.False(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1:54321/wrong-path"))

		// Mismatched scheme (https vs http for loopback)
		assert.False(t, cimd.ValidateRedirectURI(doc, "https://127.0.0.1:54321/callback"))
	})

	t.Run("invalid requested URIs", func(t *testing.T) {
		assert.False(t, cimd.ValidateRedirectURI(doc, ""))
		assert.False(t, cimd.ValidateRedirectURI(doc, "not-a-url"))
		assert.False(t, cimd.ValidateRedirectURI(doc, "http://127.0.0.1/callback#fragment"))
		assert.False(t, cimd.ValidateRedirectURI(nil, "http://127.0.0.1/callback"))
	})
}

func TestSSRF_IsBlockedIP(t *testing.T) {
	// Private IPv4
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("10.0.0.1"), false))
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("172.16.5.10"), false))
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("192.168.1.100"), false))

	// Cloud metadata service (critical)
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("169.254.169.254"), false))
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("169.254.169.254"), true)) // Even in dev!

	// Loopback
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("127.0.0.1"), false))
	assert.False(t, cimd.IsBlockedIP(net.ParseIP("127.0.0.1"), true)) // Allowed when dev flag is true

	// Public IP
	assert.False(t, cimd.IsBlockedIP(net.ParseIP("93.184.216.34"), false))
	assert.False(t, cimd.IsBlockedIP(net.ParseIP("8.8.8.8"), false))

	// IPv6 Loopback
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("::1"), false))
	assert.False(t, cimd.IsBlockedIP(net.ParseIP("::1"), true))

	// IPv6 ULA & Link-local
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("fc00::1"), false))
	assert.True(t, cimd.IsBlockedIP(net.ParseIP("fe80::1"), false))
}

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()
	cache := cimd.NewMemoryCache()
	doc := &cimd.Document{ClientID: "https://example.com/client.json"}

	// Cache miss
	_, ok := cache.Get(ctx, "https://example.com/client.json")
	assert.False(t, ok)

	// Cache set & hit
	err := cache.Set(ctx, "https://example.com/client.json", doc, 100*time.Millisecond)
	assert.NoError(t, err)
	got, ok := cache.Get(ctx, "https://example.com/client.json")
	assert.True(t, ok)
	assert.Equal(t, doc.ClientID, got.ClientID)

	// Cache expiry
	time.Sleep(120 * time.Millisecond)
	_, ok = cache.Get(ctx, "https://example.com/client.json")
	assert.False(t, ok)

	// Cache delete
	err = cache.Set(ctx, "https://example.com/client2.json", doc, 1*time.Hour)
	assert.NoError(t, err)
	err = cache.Delete(ctx, "https://example.com/client2.json")
	assert.NoError(t, err)
	_, ok = cache.Get(ctx, "https://example.com/client2.json")
	assert.False(t, ok)

	// Cache clear
	err = cache.Set(ctx, "https://example.com/client3.json", doc, 1*time.Hour)
	assert.NoError(t, err)
	err = cache.Clear(ctx)
	assert.NoError(t, err)
	_, ok = cache.Get(ctx, "https://example.com/client3.json")
	assert.False(t, ok)
}

func TestMemoryCache_CapacityAndPruning(t *testing.T) {
	ctx := context.Background()
	// Create cache bounded to 3 entries
	cache := cimd.NewMemoryCacheWithCapacity(3)
	doc := &cimd.Document{ClientID: "https://example.com/client.json"}

	// Fill to capacity
	_ = cache.Set(ctx, "https://example.com/1.json", doc, 1*time.Hour)
	_ = cache.Set(ctx, "https://example.com/2.json", doc, 50*time.Millisecond)
	_ = cache.Set(ctx, "https://example.com/3.json", doc, 1*time.Hour)
	assert.Equal(t, 3, cache.Len())

	// Wait for entry 2 to expire
	time.Sleep(60 * time.Millisecond)

	// Inserting a 4th entry should trigger expired entry pruning and fit
	_ = cache.Set(ctx, "https://example.com/4.json", doc, 1*time.Hour)
	assert.LessOrEqual(t, cache.Len(), 3)
	_, ok := cache.Get(ctx, "https://example.com/4.json")
	assert.True(t, ok)

	// Explicit CleanupExpired
	cache.CleanupExpired()
	assert.LessOrEqual(t, cache.Len(), 3)
}

func TestFetcher_Fetch(t *testing.T) {
	var requestCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)

		if r.URL.Path == "/oauth/client.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id":     fmt.Sprintf("http://%s/oauth/client.json", r.Host),
				"client_name":   "My Coding Agent",
				"redirect_uris": []string{"http://127.0.0.1/callback"},
			})
			return
		}

		if r.URL.Path == "/no-store/client.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id":     fmt.Sprintf("http://%s/no-store/client.json", r.Host),
				"client_name":   "No Store Agent",
				"redirect_uris": []string{"http://127.0.0.1/callback"},
			})
			return
		}

		if r.URL.Path == "/max-age-zero/client.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=0")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id":     fmt.Sprintf("http://%s/max-age-zero/client.json", r.Host),
				"client_name":   "Max Age Zero Agent",
				"redirect_uris": []string{"http://127.0.0.1/callback"},
			})
			return
		}

		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/oauth/client.json", http.StatusFound)
			return
		}

		if r.URL.Path == "/large.json" {
			w.Header().Set("Content-Type", "application/json")
			// Return payload > 64KB
			_, _ = w.Write([]byte(`{"client_id":"http://` + r.Host + `/large.json","padding":"` + strings.Repeat("A", 70*1024) + `"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	t.Run("insecure http rejected when AllowInsecureHTTP is false", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: false,
		})
		_, err := f.Fetch(context.Background(), "http://client.example.com/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scheme must be https")
	})

	t.Run("userinfo in URL is rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{AllowInsecureHTTP: true})
		_, err := f.Fetch(context.Background(), "http://user:pass@example.com/client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain userinfo")
	})

	t.Run("fragment in URL is rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{AllowInsecureHTTP: true})
		_, err := f.Fetch(context.Background(), "http://example.com/client.json#section")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain a URL fragment")
	})

	t.Run("bare domain without path is rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{AllowInsecureHTTP: true})
		_, err := f.Fetch(context.Background(), "http://example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must contain a path component")
	})

	t.Run("relative dot-segments in path are rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{AllowInsecureHTTP: true})
		_, err := f.Fetch(context.Background(), "http://example.com/a/../client.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "relative dot-segments")
	})

	t.Run("query parameters in URL are rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{AllowInsecureHTTP: true})
		_, err := f.Fetch(context.Background(), "http://example.com/client.json?param=1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query parameters")
	})

	t.Run("no-store and max-age=0 are not cached", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: true,
			HTTPClient:        server.Client(),
		})

		noStoreURL := fmt.Sprintf("%s/no-store/client.json", server.URL)
		c1 := atomic.LoadInt64(&requestCount)
		_, err := f.Fetch(context.Background(), noStoreURL)
		require.NoError(t, err)
		assert.Equal(t, c1+1, atomic.LoadInt64(&requestCount))

		// Second fetch must NOT hit cache
		_, err = f.Fetch(context.Background(), noStoreURL)
		require.NoError(t, err)
		assert.Equal(t, c1+2, atomic.LoadInt64(&requestCount), "no-store document must not be cached")

		maxAgeZeroURL := fmt.Sprintf("%s/max-age-zero/client.json", server.URL)
		c2 := atomic.LoadInt64(&requestCount)
		_, err = f.Fetch(context.Background(), maxAgeZeroURL)
		require.NoError(t, err)
		assert.Equal(t, c2+1, atomic.LoadInt64(&requestCount))

		// Second fetch must NOT hit cache
		_, err = f.Fetch(context.Background(), maxAgeZeroURL)
		require.NoError(t, err)
		assert.Equal(t, c2+2, atomic.LoadInt64(&requestCount), "max-age=0 document must not be cached")
	})

	t.Run("successful fetch and caching with AllowInsecureHTTP", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: true,
			HTTPClient:        server.Client(),
		})

		clientURL := fmt.Sprintf("%s/oauth/client.json", server.URL)
		initialCount := atomic.LoadInt64(&requestCount)

		doc, err := f.Fetch(context.Background(), clientURL)
		require.NoError(t, err)
		assert.Equal(t, clientURL, doc.ClientID)
		assert.Equal(t, "My Coding Agent", doc.ClientName)
		assert.Equal(t, initialCount+1, atomic.LoadInt64(&requestCount))

		// Second fetch hits cache
		doc2, err := f.Fetch(context.Background(), clientURL)
		require.NoError(t, err)
		assert.Equal(t, doc.ClientID, doc2.ClientID)
		assert.Equal(t, initialCount+1, atomic.LoadInt64(&requestCount), "should hit cache, no additional HTTP request")
	})

	t.Run("redirects are blocked", func(t *testing.T) {
		safeClient := cimd.NewSSRFSafeClient(2*time.Second, true)
		f := cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: true,
			HTTPClient:        safeClient,
		})
		redirectURL := fmt.Sprintf("%s/redirect", server.URL)
		_, err := f.Fetch(context.Background(), redirectURL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirects are not permitted")
	})

	t.Run("oversized response is rejected", func(t *testing.T) {
		f := cimd.NewFetcher(cimd.FetcherConfig{
			AllowInsecureHTTP: true,
			HTTPClient:        server.Client(),
		})
		largeURL := fmt.Sprintf("%s/large.json", server.URL)
		_, err := f.Fetch(context.Background(), largeURL)
		assert.Error(t, err)
	})
}

func TestRedisCache(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{
		Addr:       mr.Addr(),
		MaxRetries: 1,
	})
	defer rdb.Close()

	ctx := context.Background()
	cache := cimd.NewRedisCache(rdb)
	doc := &cimd.Document{
		ClientID:     "https://client.example.com/oauth/client.json",
		ClientName:   "Example Client",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	}

	// 1. Cache miss
	_, ok := cache.Get(ctx, doc.ClientID)
	assert.False(t, ok)

	// 2. Cache set & hit
	err := cache.Set(ctx, doc.ClientID, doc, 10*time.Minute)
	require.NoError(t, err)

	got, ok := cache.Get(ctx, doc.ClientID)
	assert.True(t, ok)
	require.NotNil(t, got)
	assert.Equal(t, doc.ClientID, got.ClientID)
	assert.Equal(t, doc.ClientName, got.ClientName)
	assert.Equal(t, doc.RedirectURIs, got.RedirectURIs)

	// 3. Raw Redis key format verification
	keys := mr.Keys()
	require.Len(t, keys, 1)
	assert.True(t, strings.HasPrefix(keys[0], "mcp:cimd:"))
	assert.False(t, strings.Contains(keys[0], "client.example.com"), "Key must be hashed, not raw URL")

	// 4. TTL check
	ttl, err := cache.TTL(ctx, doc.ClientID)
	require.NoError(t, err)
	assert.Greater(t, ttl, 9*time.Minute)

	// 5. Expiration via FastForward
	mr.FastForward(11 * time.Minute)
	_, ok = cache.Get(ctx, doc.ClientID)
	assert.False(t, ok)

	// 6. Delete
	err = cache.Set(ctx, doc.ClientID, doc, 10*time.Minute)
	require.NoError(t, err)
	err = cache.Delete(ctx, doc.ClientID)
	require.NoError(t, err)
	_, ok = cache.Get(ctx, doc.ClientID)
	assert.False(t, ok)

	// 7. Clear
	err = cache.Set(ctx, "https://client1.example.com/client.json", doc, 10*time.Minute)
	require.NoError(t, err)
	err = cache.Set(ctx, "https://client2.example.com/client.json", doc, 10*time.Minute)
	require.NoError(t, err)
	assert.Len(t, mr.Keys(), 2)

	err = cache.Clear(ctx)
	require.NoError(t, err)
	assert.Empty(t, mr.Keys())

	// 8. Graceful handling when Redis is unreachable
	mr.Close()
	_, ok = cache.Get(ctx, doc.ClientID)
	assert.False(t, ok, "Should gracefully return false on Redis connection error")
	err = cache.Set(ctx, doc.ClientID, doc, 10*time.Minute)
	assert.Error(t, err, "Should return error on failed Set")
}

func TestTwoTierCache(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()
	l1 := cimd.NewMemoryCache()
	l2 := cimd.NewRedisCache(rdb)
	twoTier := cimd.NewTwoTierCache(l1, l2)

	doc := &cimd.Document{
		ClientID:     "https://client.example.com/oauth/client.json",
		ClientName:   "Example Client",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	}

	// 1. Set populates both L1 and L2
	err := twoTier.Set(ctx, doc.ClientID, doc, 1*time.Hour)
	require.NoError(t, err)

	// Verify both tiers have it
	_, inL1 := l1.Get(ctx, doc.ClientID)
	assert.True(t, inL1)
	_, inL2 := l2.Get(ctx, doc.ClientID)
	assert.True(t, inL2)

	// 2. L1 hit
	got, ok := twoTier.Get(ctx, doc.ClientID)
	assert.True(t, ok)
	assert.Equal(t, doc.ClientID, got.ClientID)

	// 3. L1 miss, L2 hit -> backfills L1
	_ = l1.Clear(ctx)
	_, inL1 = l1.Get(ctx, doc.ClientID)
	assert.False(t, inL1, "L1 must be cleared")

	got, ok = twoTier.Get(ctx, doc.ClientID)
	assert.True(t, ok)
	assert.Equal(t, doc.ClientID, got.ClientID)

	// Now L1 should be backfilled
	_, inL1 = l1.Get(ctx, doc.ClientID)
	assert.True(t, inL1, "L1 should be backfilled from L2")

	// 4. Delete evicts from both
	err = twoTier.Delete(ctx, doc.ClientID)
	require.NoError(t, err)
	_, inL1 = l1.Get(ctx, doc.ClientID)
	assert.False(t, inL1)
	_, inL2 = l2.Get(ctx, doc.ClientID)
	assert.False(t, inL2)

	// 5. Clear clears both
	_ = twoTier.Set(ctx, "https://a.com/client.json", doc, 1*time.Hour)
	_ = twoTier.Set(ctx, "https://b.com/client.json", doc, 1*time.Hour)
	err = twoTier.Clear(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, l1.Len())
	assert.Empty(t, mr.Keys())
}

func TestFetcher_WithRedisCache(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	var reqCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		doc := cimd.Document{
			ClientID:     "http://" + r.Host + "/client.json",
			ClientName:   "Redis Test Client",
			RedirectURIs: []string{"http://127.0.0.1/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	redisCache := cimd.NewRedisCache(rdb)
	f := cimd.NewFetcher(cimd.FetcherConfig{
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Cache:             redisCache,
		DefaultTTL:        10 * time.Minute,
	})

	clientURL := fmt.Sprintf("%s/client.json", server.URL)

	// First fetch: hits origin server (reqCount = 1) and stores in Redis
	doc1, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc1.ClientID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&reqCount))

	// Verify it's stored in Redis
	keys := mr.Keys()
	assert.Len(t, keys, 1)

	// Second fetch: served from Redis cache (reqCount remains 1)
	doc2, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc2.ClientID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&reqCount))

	// Fast forward Redis beyond TTL -> cache expires
	mr.FastForward(15 * time.Minute)

	// Third fetch: re-fetches from origin server (reqCount = 2)
	doc3, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc3.ClientID)
	assert.Equal(t, int64(2), atomic.LoadInt64(&reqCount))
}

func TestFetcher_WithTwoTierCache(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	var reqCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		doc := cimd.Document{
			ClientID:     "http://" + r.Host + "/client.json",
			ClientName:   "Two-Tier Test Client",
			RedirectURIs: []string{"http://127.0.0.1/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	l1 := cimd.NewMemoryCache()
	l2 := cimd.NewRedisCache(rdb)
	twoTier := cimd.NewTwoTierCache(l1, l2)

	f := cimd.NewFetcher(cimd.FetcherConfig{
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Cache:             twoTier,
		DefaultTTL:        10 * time.Minute,
	})

	clientURL := fmt.Sprintf("%s/client.json", server.URL)

	// First fetch: hits origin server, populates both L1 and L2
	doc1, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc1.ClientID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&reqCount))
	assert.Equal(t, 1, l1.Len())
	assert.Len(t, mr.Keys(), 1)

	// Second fetch: served from L1 memory (reqCount remains 1)
	doc2, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc2.ClientID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&reqCount))

	// Clear L1 to simulate cache miss in L1 on another pod
	_ = l1.Clear(context.Background())
	assert.Equal(t, 0, l1.Len())

	// Third fetch: L1 miss, served from L2 Redis and backfills L1 (reqCount remains 1)
	doc3, err := f.Fetch(context.Background(), clientURL)
	require.NoError(t, err)
	assert.Equal(t, clientURL, doc3.ClientID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&reqCount))
	assert.Equal(t, 1, l1.Len(), "L1 should be backfilled from L2")
}
