package cimd

import (
	"context"
	"time"
)

var _ Cache = (*TwoTierCache)(nil)

// DefaultL1RefillTTL is the default TTL applied when backfilling L1 from L2.
const DefaultL1RefillTTL = 15 * time.Minute

// TwoTierCache provides a hybrid caching architecture:
// L1 (in-memory MemoryCache) for sub-microsecond local hits without network overhead.
// L2 (distributed Cache, e.g. RedisCache) for cross-pod consistency and persistence across restarts.
type TwoTierCache struct {
	l1          *MemoryCache
	l2          Cache
	l1RefillTTL time.Duration
}

// NewTwoTierCache creates a new two-tier cache with default 15-minute L1 refill TTL.
func NewTwoTierCache(l1 *MemoryCache, l2 Cache) *TwoTierCache {
	return NewTwoTierCacheWithRefillTTL(l1, l2, DefaultL1RefillTTL)
}

// NewTwoTierCacheWithRefillTTL creates a new two-tier cache with specified L1 refill TTL.
func NewTwoTierCacheWithRefillTTL(l1 *MemoryCache, l2 Cache, refillTTL time.Duration) *TwoTierCache {
	if l1 == nil {
		l1 = NewMemoryCache()
	}
	if refillTTL <= 0 {
		refillTTL = DefaultL1RefillTTL
	}
	return &TwoTierCache{
		l1:          l1,
		l2:          l2,
		l1RefillTTL: refillTTL,
	}
}

// Get checks L1 memory cache first. On miss, it queries L2 and backfills L1 on hit.
func (t *TwoTierCache) Get(ctx context.Context, clientID string) (*Document, bool) {
	if doc, ok := t.l1.Get(ctx, clientID); ok {
		return doc, true
	}
	if t.l2 != nil {
		if doc, ok := t.l2.Get(ctx, clientID); ok {
			refillTTL := t.l1RefillTTL
			// Clamp refill TTL if L2 is RedisCache and has shorter remaining TTL
			if rc, isRedis := t.l2.(*RedisCache); isRedis {
				if remTTL, err := rc.TTL(ctx, clientID); err == nil && remTTL > 0 && remTTL < refillTTL {
					refillTTL = remTTL
				}
			}
			_ = t.l1.Set(ctx, clientID, doc, refillTTL)
			return doc, true
		}
	}
	return nil, false
}

// Set stores the document in both L1 and L2 with the given TTL.
func (t *TwoTierCache) Set(ctx context.Context, clientID string, doc *Document, ttl time.Duration) error {
	_ = t.l1.Set(ctx, clientID, doc, ttl)
	if t.l2 != nil {
		return t.l2.Set(ctx, clientID, doc, ttl)
	}
	return nil
}

// Delete evicts the document from both L1 and L2.
func (t *TwoTierCache) Delete(ctx context.Context, clientID string) error {
	_ = t.l1.Delete(ctx, clientID)
	if t.l2 != nil {
		return t.l2.Delete(ctx, clientID)
	}
	return nil
}

// Clear flushes both L1 and L2 caches.
func (t *TwoTierCache) Clear(ctx context.Context) error {
	_ = t.l1.Clear(ctx)
	if t.l2 != nil {
		return t.l2.Clear(ctx)
	}
	return nil
}

// L1 returns the underlying MemoryCache.
func (t *TwoTierCache) L1() *MemoryCache {
	return t.l1
}

// L2 returns the underlying distributed Cache.
func (t *TwoTierCache) L2() Cache {
	return t.l2
}
