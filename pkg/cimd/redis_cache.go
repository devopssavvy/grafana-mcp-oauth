package cimd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var _ Cache = (*RedisCache)(nil)

// DefaultRedisKeyPrefix is the default prefix for CIMD document keys in Redis.
const DefaultRedisKeyPrefix = "mcp:cimd:"

// RedisCache provides distributed caching of Client ID Metadata Documents in Redis.
type RedisCache struct {
	client redis.UniversalClient
	prefix string
}

// NewRedisCache creates a new Redis-backed CIMD cache with the default prefix.
func NewRedisCache(client redis.UniversalClient) *RedisCache {
	return NewRedisCacheWithPrefix(client, DefaultRedisKeyPrefix)
}

// NewRedisCacheWithPrefix creates a new Redis-backed CIMD cache with a custom key prefix.
func NewRedisCacheWithPrefix(client redis.UniversalClient, prefix string) *RedisCache {
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	return &RedisCache{
		client: client,
		prefix: prefix,
	}
}

// Get retrieves a document from Redis if not expired.
func (r *RedisCache) Get(ctx context.Context, clientID string) (*Document, bool) {
	if r.client == nil || clientID == "" {
		return nil, false
	}
	key := r.cacheKey(clientID)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	return &doc, true
}

// Set stores a document with given TTL in Redis.
func (r *RedisCache) Set(ctx context.Context, clientID string, doc *Document, ttl time.Duration) error {
	if r.client == nil || clientID == "" || doc == nil || ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}
	key := r.cacheKey(clientID)
	return r.client.Set(ctx, key, data, ttl).Err()
}

// Delete removes an entry from Redis.
func (r *RedisCache) Delete(ctx context.Context, clientID string) error {
	if r.client == nil || clientID == "" {
		return nil
	}
	key := r.cacheKey(clientID)
	return r.client.Del(ctx, key).Err()
}

// Clear removes all CIMD cache entries from Redis matching the prefix.
func (r *RedisCache) Clear(ctx context.Context) error {
	if r.client == nil {
		return nil
	}
	var cursor uint64
	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, r.prefix+"*", 100).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := r.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

// TTL returns the remaining TTL of a cached document in Redis.
func (r *RedisCache) TTL(ctx context.Context, clientID string) (time.Duration, error) {
	if r.client == nil || clientID == "" {
		return 0, nil
	}
	key := r.cacheKey(clientID)
	return r.client.TTL(ctx, key).Result()
}

// Client returns the underlying redis.UniversalClient.
func (r *RedisCache) Client() redis.UniversalClient {
	return r.client
}

// Prefix returns the key prefix used by this RedisCache.
func (r *RedisCache) Prefix() string {
	return r.prefix
}

func (r *RedisCache) cacheKey(clientID string) string {
	h := sha256.Sum256([]byte(clientID))
	return r.prefix + hex.EncodeToString(h[:])
}
