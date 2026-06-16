package tokencache

import (
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries is the default maximum number of entries in the cache.
	DefaultMaxEntries = 10000

	// defaultBufferSeconds is the buffer subtracted from token expiry when caching.
	// Tokens are considered expired this many seconds before their actual expiry to
	// account for clock skew and network latency.
	defaultBufferSeconds = 30
)

// Cache is a generic LRU-bounded token cache for short-lived access tokens.
//
// It is provider-neutral: any credential provider that mints tokens with an expiry
// can use it with an arbitrary string key. Keys should be constructed so distinct
// scopes (endpoint, connector, user; or installationID, permissions) get separate
// entries.
//
// Thread-safe. When the cache reaches its maximum size, the least recently used
// entry is evicted. Tokens are considered expired 30 seconds before their actual
// expiry to account for clock skew and network latency.
type Cache struct {
	mu         sync.RWMutex
	tokens     map[string]*list.Element
	lruList    *list.List
	maxEntries int

	totalEvictions int64
}

// cacheEntry holds a cached token with its key for LRU tracking.
type cacheEntry struct {
	key   string
	token *Token
}

// Token holds a cached token with its expiration.
type Token struct {
	// AccessToken is the cached access token value.
	AccessToken string

	// ExpiresAt is when the token expires (after the 30s buffer).
	ExpiresAt time.Time

	// IssuedTokenType is the RFC 8693 token-type URN of the cached token.
	IssuedTokenType string
}

// Stats provides cache statistics for monitoring.
type Stats struct {
	// CurrentEntries is the number of entries currently in the cache.
	CurrentEntries int
	// MaxEntries is the maximum allowed entries (0 = unlimited).
	MaxEntries int
	// TotalEvictions is the number of LRU evictions performed.
	TotalEvictions int64
	// MemoryPressure is the percentage of max capacity used (0-100).
	MemoryPressure float64
}

// New creates a new Cache with the default maximum entry count.
func New() *Cache {
	return NewWithMaxEntries(DefaultMaxEntries)
}

// NewWithMaxEntries creates a new Cache with a custom maximum entry count.
// Pass 0 for unlimited (not recommended in production).
func NewWithMaxEntries(maxEntries int) *Cache {
	return &Cache{
		tokens:     make(map[string]*list.Element),
		lruList:    list.New(),
		maxEntries: maxEntries,
	}
}

// Get retrieves a cached token by key. Returns nil if the token is absent or expired.
// A successful lookup moves the entry to the front of the LRU list.
func (c *Cache) Get(key string) *Token {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.tokens[key]
	if !ok {
		return nil
	}

	entry := elem.Value.(*cacheEntry)

	if time.Now().After(entry.token.ExpiresAt) {
		c.lruList.Remove(elem)
		delete(c.tokens, key)
		return nil
	}

	c.lruList.MoveToFront(elem)
	return entry.token
}

// Set stores a token in the cache. expiresIn is the token lifetime in seconds;
// a 30-second buffer is applied so the cached entry is treated as expired before
// the actual expiry. If the cache is at capacity, the LRU entry is evicted.
func (c *Cache) Set(key, accessToken, issuedTokenType string, expiresIn int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := time.Now().Add(time.Duration(expiresIn)*time.Second - defaultBufferSeconds*time.Second)

	t := &Token{
		AccessToken:     accessToken,
		ExpiresAt:       expiry,
		IssuedTokenType: issuedTokenType,
	}

	if elem, ok := c.tokens[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.token = t
		c.lruList.MoveToFront(elem)
		return
	}

	if c.maxEntries > 0 && len(c.tokens) >= c.maxEntries {
		c.evictLRU()
	}

	entry := &cacheEntry{key: key, token: t}
	elem := c.lruList.PushFront(entry)
	c.tokens[key] = elem
}

// Delete removes a token from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.tokens[key]; ok {
		c.lruList.Remove(elem)
		delete(c.tokens, key)
	}
}

// Clear removes all tokens from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = make(map[string]*list.Element)
	c.lruList = list.New()
}

// Size returns the number of tokens in the cache, including expired ones.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.tokens)
}

// Cleanup removes expired tokens. Call periodically in long-running services to
// prevent memory growth from accumulated expired entries.
func (c *Cache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	var next *list.Element
	for elem := c.lruList.Front(); elem != nil; elem = next {
		next = elem.Next()
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.token.ExpiresAt) {
			c.lruList.Remove(elem)
			delete(c.tokens, entry.key)
			removed++
		}
	}
	return removed
}

// GetStats returns cache statistics.
func (c *Cache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s := Stats{
		CurrentEntries: len(c.tokens),
		MaxEntries:     c.maxEntries,
		TotalEvictions: c.totalEvictions,
	}
	if c.maxEntries > 0 {
		s.MemoryPressure = float64(s.CurrentEntries) / float64(c.maxEntries) * 100.0
	}
	return s
}

// evictLRU removes the least recently used entry. Must be called with mu held.
func (c *Cache) evictLRU() {
	if c.lruList.Len() == 0 {
		return
	}
	elem := c.lruList.Back()
	if elem == nil {
		return
	}
	entry := elem.Value.(*cacheEntry)
	delete(c.tokens, entry.key)
	c.lruList.Remove(elem)
	c.totalEvictions++
}

// GenerateCacheKey creates a cache key from the token endpoint, connector ID, and
// user ID. The key is a SHA-256 hash of the inputs so it is fixed-length and does
// not expose sensitive values if the cache is inspected.
//
// The userID MUST come from validated, trusted claims (e.g. the "sub" claim after
// JWT signature verification), not from raw user input. Untrusted values can cause
// cache poisoning.
func GenerateCacheKey(tokenEndpoint, connectorID, userID string) string {
	// Null-byte separator prevents collisions like ("a:b","c") vs ("a","b:c").
	data := tokenEndpoint + "\x00" + connectorID + "\x00" + userID
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
