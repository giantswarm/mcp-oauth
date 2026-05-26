package server

import (
	"context"
	"sync"
	"time"
)

// DPoPReplayCache tracks seen DPoP proof JTIs to prevent replay attacks.
// Implementations must be safe for concurrent use.
type DPoPReplayCache interface {
	// Seen returns true if jti was already seen within the TTL window,
	// and records it for future calls. An error means the cache is
	// unavailable; callers should reject the proof on error.
	Seen(ctx context.Context, jti string, ttl time.Duration) (bool, error)
}

// memoryDPoPReplayCache is an in-memory DPoPReplayCache with TTL eviction.
type memoryDPoPReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti -> expiry
}

// NewMemoryDPoPReplayCache returns an in-memory replay cache.
// Expired entries are evicted lazily on each Seen call.
func NewMemoryDPoPReplayCache() DPoPReplayCache {
	return &memoryDPoPReplayCache{entries: make(map[string]time.Time)}
}

func (c *memoryDPoPReplayCache) Seen(_ context.Context, jti string, ttl time.Duration) (bool, error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}

	if exp, ok := c.entries[jti]; ok && now.Before(exp) {
		return true, nil
	}
	c.entries[jti] = now.Add(ttl)
	return false, nil
}
