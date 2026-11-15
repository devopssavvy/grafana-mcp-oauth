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
	cache := cimd.NewMemoryCache()
	doc := &cimd.Document{ClientID: "https://example.com/client.json"}

	// Cache miss
	_, ok := cache.Get("https://example.com/client.json")
	assert.False(t, ok)

	// Cache set & hit
	cache.Set("https://example.com/client.json", doc, 100*time.Millisecond)
	got, ok := cache.Get("https://example.com/client.json")
	assert.True(t, ok)
	assert.Equal(t, doc.ClientID, got.ClientID)

	// Cache expiry
	time.Sleep(120 * time.Millisecond)
	_, ok = cache.Get("https://example.com/client.json")
	assert.False(t, ok)

	// Cache delete
	cache.Set("https://example.com/client2.json", doc, 1*time.Hour)
	cache.Delete("https://example.com/client2.json")
	_, ok = cache.Get("https://example.com/client2.json")
	assert.False(t, ok)

	// Cache clear
	cache.Set("https://example.com/client3.json", doc, 1*time.Hour)
	cache.Clear()
	_, ok = cache.Get("https://example.com/client3.json")
	assert.False(t, ok)
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
