package cimd

import (
	"sync"
	"time"
)

type cacheEntry struct {
	doc       *Document
	expiresAt time.Time
}

// MemoryCache provides in-memory thread-safe caching of Client ID Metadata Documents.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

// NewMemoryCache creates a new in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		entries: make(map[string]cacheEntry),
	}
}

// Get retrieves a document from cache if not expired.
func (c *MemoryCache) Get(clientID string) (*Document, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[clientID]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.doc, true
}

// Set stores a document with given TTL.
func (c *MemoryCache) Set(clientID string, doc *Document, ttl time.Duration) {
	if doc == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[clientID] = cacheEntry{
		doc:       doc,
		expiresAt: time.Now().Add(ttl),
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
