package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FetcherConfig configures the CIMD Fetcher.
type FetcherConfig struct {
	AllowInsecureHTTP bool
	DefaultTTL        time.Duration
	HTTPClient        *http.Client
	Cache             *MemoryCache
}

// Fetcher retrieves, parses, and validates Client ID Metadata Documents.
type Fetcher struct {
	cfg        FetcherConfig
	httpClient *http.Client
	cache      *MemoryCache
}

// NewFetcher creates a new CIMD Fetcher.
func NewFetcher(cfg FetcherConfig) *Fetcher {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 1 * time.Hour
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewMemoryCache()
	}
	client := cfg.HTTPClient
	if client == nil {
		client = NewSSRFSafeClient(5*time.Second, cfg.AllowInsecureHTTP)
	}

	return &Fetcher{
		cfg:        cfg,
		httpClient: client,
		cache:      cache,
	}
}

// Fetch retrieves and validates the Client ID Metadata Document from the given client_id URL.
func (f *Fetcher) Fetch(ctx context.Context, clientID string) (*Document, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id cannot be empty")
	}

	// 1. Syntax validation per draft-ietf-oauth-client-id-metadata-document Section 2
	u, err := url.Parse(clientID)
	if err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("client_id must be a valid absolute URL: %w", err)
	}

	if !f.cfg.AllowInsecureHTTP && !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("client_id scheme must be https, got %q", u.Scheme)
	} else if f.cfg.AllowInsecureHTTP && !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return nil, fmt.Errorf("client_id scheme must be http or https, got %q", u.Scheme)
	}

	if u.User != nil {
		return nil, fmt.Errorf("client_id must not contain userinfo")
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("client_id must not contain a URL fragment")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("client_id must have a valid host")
	}

	// 2. Check Cache
	if doc, ok := f.cache.Get(clientID); ok {
		return doc, nil
	}

	// 3. Outbound HTTP GET
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "grafana-mcp-oauth/1.0 (CIMD Validator)")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client metadata document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata server returned HTTP %d", resp.StatusCode)
	}

	// Validate content type contains json if header is present
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(strings.ToLower(ct), "application/json") {
		return nil, fmt.Errorf("invalid Content-Type %q, expected application/json", ct)
	}

	// Limit reader to 64KB to prevent memory exhaustion / decompression bombs
	bodyReader := io.LimitReader(resp.Body, 64*1024)
	var doc Document
	if err := json.NewDecoder(bodyReader).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse client metadata JSON: %w", err)
	}

	// 4. Validate Document consistency
	if err := ValidateDocument(&doc, clientID); err != nil {
		return nil, fmt.Errorf("invalid client metadata document: %w", err)
	}

	// 5. Cache with TTL
	ttl := f.cfg.DefaultTTL
	if maxAge, ok := parseCacheControlMaxAge(resp.Header.Get("Cache-Control")); ok {
		ttl = maxAge
	}
	f.cache.Set(clientID, &doc, ttl)

	return &doc, nil
}

func parseCacheControlMaxAge(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		if strings.HasPrefix(lower, "max-age=") {
			valStr := strings.TrimPrefix(lower, "max-age=")
			valStr = strings.TrimSpace(valStr)
			if sec, err := strconv.Atoi(valStr); err == nil && sec > 0 {
				d := time.Duration(sec) * time.Second
				if d < 1*time.Minute {
					d = 1 * time.Minute
				} else if d > 24*time.Hour {
					d = 24 * time.Hour
				}
				return d, true
			}
		}
	}
	return 0, false
}
