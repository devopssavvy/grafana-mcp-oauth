package cimd

import (
	"sync"
	"time"
)

const defaultMaxEntries = 10000

type cacheEntry struct {
	doc       *Document
	expiresAt time.Time
}

// MemoryCache provides in-memory thread-safe caching of Client ID Metadata Documents
// with bounded capacity and automatic expiration pruning.
type MemoryCache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	maxEntries int
}

// NewMemoryCache creates a new in-memory cache with default maximum capacity.
func NewMemoryCache() *MemoryCache {
	return NewMemoryCacheWithCapacity(defaultMaxEntries)
}

// NewMemoryCacheWithCapacity creates a new in-memory cache with specified maximum capacity.
func NewMemoryCacheWithCapacity(maxEntries int) *MemoryCache {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &MemoryCache{
		entries:    make(map[string]cacheEntry),
		maxEntries: maxEntries,
	}
}

// Get retrieves a document from cache if not expired.
func (c *MemoryCache) Get(clientID string) (*Document, bool) {
	c.mu.RLock()
	entry, ok := c.entries[clientID]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		// Lazily prune expired entry
		c.mu.Lock()
		if current, exists := c.entries[clientID]; exists && time.Now().After(current.expiresAt) {
			delete(c.entries, clientID)
		}
		c.mu.Unlock()
		return nil, false
	}
	return entry.doc, true
}

// Set stores a document with given TTL and enforces capacity limits.
func (c *MemoryCache) Set(clientID string, doc *Document, ttl time.Duration) {
	if doc == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// If capacity reached, prune expired entries first
	if len(c.entries) >= c.maxEntries {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
	}

	// If still at capacity, evict any entry to prevent unbounded growth
	if len(c.entries) >= c.maxEntries {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}

	c.entries[clientID] = cacheEntry{
		doc:       doc,
		expiresAt: time.Now().Add(ttl),
	}
}

// CleanupExpired purges all expired entries from the cache.
func (c *MemoryCache) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// Delete removes an entry from the cache.
func (c *MemoryCache) Delete(clientID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, clientID)
}

// Clear cleans up all entries in the cache.
func (c *MemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]cacheEntry)
}

// Len returns current entry count in cache.
func (c *MemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
