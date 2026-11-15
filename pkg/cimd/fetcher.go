package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	Cache             Cache
	Logger            *slog.Logger
}

// Fetcher retrieves, parses, and validates Client ID Metadata Documents.
type Fetcher struct {
	cfg        FetcherConfig
	httpClient *http.Client
	cache      Cache
	logger     *slog.Logger
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
		logger:     cfg.Logger,
	}
}

// Cache returns the underlying Cache implementation.
func (f *Fetcher) Cache() Cache {
	return f.cache
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
	if port := u.Port(); port != "" {
		if !f.cfg.AllowInsecureHTTP {
			if port != "443" && port != "8443" {
				return nil, fmt.Errorf("client_id port %s is not permitted; must use standard HTTPS ports (443, 8443)", port)
			}
		}
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("client_id must contain a path component")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return nil, fmt.Errorf("client_id path must not contain relative dot-segments")
		}
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("client_id must not contain query parameters")
	}

	// 2. Check Cache
	if f.cache != nil {
		if doc, ok := f.cache.Get(ctx, clientID); ok {
			return doc, nil
		}
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

	// 5. Cache with TTL unless Cache-Control prohibits it
	ccHeader := strings.ToLower(resp.Header.Get("Cache-Control"))
	shouldCache := !strings.Contains(ccHeader, "no-store") && !strings.Contains(ccHeader, "no-cache")

	if shouldCache {
		ttl := f.cfg.DefaultTTL
		if maxAge, ok := parseCacheControlMaxAge(resp.Header.Get("Cache-Control")); ok {
			if maxAge <= 0 {
				shouldCache = false
			} else {
				ttl = maxAge
			}
		}
		if shouldCache && f.cache != nil {
			if err := f.cache.Set(ctx, clientID, &doc, ttl); err != nil && f.logger != nil {
				f.logger.Warn("Failed to cache CIMD document", "client_id", clientID, "error", err)
			}
		}
	}

	return &doc, nil
}

func parseCacheControlMaxAge(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			valStr := strings.TrimPrefix(part, "max-age=")
			valStr = strings.Trim(valStr, "\"")
			seconds, err := strconv.Atoi(valStr)
			if err == nil {
				return time.Duration(seconds) * time.Second, true
			}
		}
	}
	return 0, false
}
