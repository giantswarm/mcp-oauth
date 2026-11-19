package server

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// clientMetadataCache implements an in-memory LRU cache for URL-based client
// metadata. It holds only valid documents whose responses allow storing them
// (draft-ietf-oauth-client-id-metadata-document-00 section 4.4).
type clientMetadataCache struct {
	mu         sync.RWMutex
	entries    map[string]*cachedMetadataEntry
	maxEntries int

	// Metrics for monitoring cache performance
	metrics cacheMetrics
}

// cacheMetrics tracks cache performance statistics
type cacheMetrics struct {
	hits       uint64 // Cache hits
	misses     uint64 // Cache misses (including expired entries)
	evictions  uint64 // Number of entries evicted due to capacity
	fetches    uint64 // Number of successful metadata fetches
	fetchFails uint64 // Number of failed metadata fetches
}

// cachedMetadataEntry represents a cached client metadata entry with expiry
type cachedMetadataEntry struct {
	metadata  *ClientMetadata
	client    *storage.Client // Converted client for use in authorization flow
	expiresAt time.Time
	cachedAt  time.Time
}

// DefaultNegativeCacheTTL is unused.
//
// Deprecated: failed client metadata fetches are not cached, as
// draft-ietf-oauth-client-id-metadata-document-00 section 4.4 requires.
const DefaultNegativeCacheTTL = 5 * time.Minute

// DefaultMaxNegativeEntries is unused.
//
// Deprecated: failed client metadata fetches are not cached, as
// draft-ietf-oauth-client-id-metadata-document-00 section 4.4 requires.
const DefaultMaxNegativeEntries = 500

func newClientMetadataCache(maxEntries int) *clientMetadataCache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &clientMetadataCache{
		entries:    make(map[string]*cachedMetadataEntry),
		maxEntries: maxEntries,
	}
}

// Get retrieves metadata from cache if present and not expired
func (c *clientMetadataCache) Get(clientID string) (*storage.Client, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[clientID]
	if !ok {
		c.metrics.misses++
		return nil, false
	}

	// Check if expired
	now := time.Now()
	if now.After(entry.expiresAt) {
		c.metrics.misses++
		return nil, false
	}

	c.metrics.hits++
	return entry.client, true
}

// Set stores metadata for ttl; a ttl of zero or less stores nothing.
func (c *clientMetadataCache) Set(clientID string, metadata *ClientMetadata, client *storage.Client, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply LRU eviction if cache is full
	if len(c.entries) >= c.maxEntries {
		c.evictOldest()
	}

	now := time.Now()
	c.entries[clientID] = &cachedMetadataEntry{
		metadata:  metadata,
		client:    client,
		expiresAt: now.Add(ttl),
		cachedAt:  now,
	}
}

// evictOldest removes the oldest cached entry (by cachedAt time)
// Caller must hold write lock
//
// Note: This is O(n) eviction. For the default max of 1000 entries, this is
// acceptable and keeps the implementation simple. If cache size grows significantly
// or eviction becomes a bottleneck, consider using a proper LRU implementation
// with a doubly-linked list (e.g., container/list or hashicorp/golang-lru).
func (c *clientMetadataCache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// Find oldest entry
	for key, entry := range c.entries {
		if oldestKey == "" || entry.cachedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.cachedAt
		}
	}

	// Remove oldest entry
	if oldestKey != "" {
		delete(c.entries, oldestKey)
		c.metrics.evictions++
	}
}

// CleanupExpired removes all expired entries
func (c *clientMetadataCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			removed++
		}
	}

	return removed
}

// Size returns the current number of cached entries
func (c *clientMetadataCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries
func (c *clientMetadataCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cachedMetadataEntry)
}

// GetMetrics returns a snapshot of cache performance metrics
func (c *clientMetadataCache) GetMetrics() cacheMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// tryGetCachedClient tries to get a client from cache
// Returns (client, true) if found, (nil, false) otherwise
func (s *Server) tryGetCachedClient(ctx context.Context, clientID string) (*storage.Client, bool) {
	cachedClient, ok := s.metadataCache.Get(clientID)
	if !ok {
		return nil, false
	}

	s.recordCIMDCacheMetric(ctx, "hit")
	s.logMetadataFetchEvent(ctx, "client_metadata_cache_hit", clientID, map[string]any{"source": "cache"})
	s.Logger.Debug("Using cached client metadata", paramClientID, clientID)
	return cachedClient, true
}

// checkMetadataFetchRateLimit checks if fetching metadata for this clientID is rate limited
func (s *Server) checkMetadataFetchRateLimit(ctx context.Context, clientID string) error {
	if s.metadataFetchRateLimiter == nil {
		return nil
	}

	u, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid client_id URL: %w", err)
	}
	domain := u.Hostname()

	if !s.metadataFetchRateLimiter.Allow(domain) {
		s.logMetadataFetchEvent(ctx, "client_metadata_rate_limited", clientID, map[string]any{
			"domain": domain, logKeyReason: "rate_limit_exceeded",
		})
		return fmt.Errorf("rate limit exceeded for metadata fetches from domain: %s", domain)
	}
	return nil
}

// getOrFetchClient retrieves a client from cache or fetches metadata if not cached
// This is the main entry point for URL-based client resolution
//
// Security features:
//   - SSRF protection: Enforced at HTTP connection time in createSSRFProtectedTransport()
//     This prevents DNS rebinding attacks by validating IPs when connecting, not just during initial URL validation
//   - Singleflight deduplication: prevents concurrent fetches of the same URL (DoS protection)
//   - Rate limiting: per-domain rate limiting to prevent abuse (default: 10 requests/second per domain, burst 20)
//   - Audit logging: all cache hits and fetches are logged for security monitoring
func (s *Server) getOrFetchClient(ctx context.Context, clientID string) (*storage.Client, error) {
	if !isClientIDMetadataDocumentURL(clientID) {
		return s.clientStore.GetClient(ctx, clientID)
	}

	if !s.Config.EnableClientIDMetadataDocuments {
		return nil, fmt.Errorf("URL-based client_id not supported: client_id_metadata_documents feature is disabled")
	}

	if client, ok := s.preRegisteredClients[clientID]; ok {
		return clonePreRegisteredClient(client), nil
	}

	if err := s.checkClientMetadataAllowed(clientID); err != nil {
		s.recordCIMDFetchMetric(ctx, "blocked", time.Now())
		s.logMetadataFetchEvent(ctx, "client_metadata_fetch_blocked", clientID, map[string]any{
			logKeyReason: "not_allowed",
		})
		return nil, err
	}

	if client, ok := s.tryGetCachedClient(ctx, clientID); ok {
		return client, nil
	}

	if err := s.checkMetadataFetchRateLimit(ctx, clientID); err != nil {
		return nil, err
	}

	// SECURITY: Use singleflight to deduplicate concurrent fetches of the same URL.
	// DoChan + a leader ctx detached from caller cancellation: each caller
	// selects on its own ctx vs the shared result channel. One caller's
	// cancellation cannot poison the others, and the shared fetch completes
	// and caches its result for any caller still listening or future
	// cache readers.
	ch := s.metadataFetchGroup.DoChan(clientID, func() (interface{}, error) {
		return s.fetchClientWithSingleflight(context.WithoutCancel(ctx), clientID)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*storage.Client), nil
	}
}

// fetchClientWithSingleflight performs the actual fetch within singleflight context.
func (s *Server) fetchClientWithSingleflight(ctx context.Context, clientID string) (*storage.Client, error) {
	// Double-check cache (another goroutine might have filled it while we waited)
	if cachedClient, ok := s.metadataCache.Get(clientID); ok {
		s.recordCIMDCacheMetric(ctx, "hit")
		s.Logger.Debug("Using cached client metadata (singleflight)", paramClientID, clientID)
		return cachedClient, nil
	}

	s.recordCIMDCacheMetric(ctx, "miss")
	s.Logger.Debug("Fetching client metadata from URL", paramClientID, clientID)

	metadata, cacheLifetime, fetchErr := s.fetchClientMetadata(ctx, clientID)
	if fetchErr != nil {
		s.handleMetadataFetchFailure(ctx, clientID, fetchErr)
		return nil, fmt.Errorf("failed to fetch client metadata: %w", fetchErr)
	}

	return s.cacheAndReturnClient(clientID, metadata, cacheLifetime), nil
}

// handleMetadataFetchFailure records a failed metadata fetch. The failure is
// not cached: the next request for the client ID fetches the document again.
func (s *Server) handleMetadataFetchFailure(ctx context.Context, clientID string, fetchErr error) {
	s.metadataCache.mu.Lock()
	s.metadataCache.metrics.fetchFails++
	s.metadataCache.mu.Unlock()

	s.logMetadataFetchEvent(ctx, "client_metadata_fetch_failed", clientID, map[string]any{
		logKeyError: fetchErr.Error(),
	})
}

// cacheAndReturnClient converts metadata to a client and caches it for
// cacheLifetime.
func (s *Server) cacheAndReturnClient(clientID string, metadata *ClientMetadata, cacheLifetime time.Duration) *storage.Client {
	s.metadataCache.mu.Lock()
	s.metadataCache.metrics.fetches++
	s.metadataCache.mu.Unlock()

	client := metadataToClient(metadata)
	s.metadataCache.Set(clientID, metadata, client, cacheLifetime)

	return client
}

// metadataToClient converts ClientMetadata to storage.Client
func metadataToClient(metadata *ClientMetadata) *storage.Client {
	// Parse scope string into slice
	var scopes []string
	if metadata.Scope != "" {
		scopes = helpers.SplitScopes(metadata.Scope)
	}

	// Default to public client (token_endpoint_auth_method="none")
	clientType := ClientTypePublic
	if metadata.TokenEndpointAuthMethod != "" && metadata.TokenEndpointAuthMethod != TokenEndpointAuthMethodNone {
		clientType = ClientTypeConfidential
	}

	return &storage.Client{
		ClientID:                metadata.ClientID,
		ClientSecretHash:        "", // URL clients don't have secrets
		ClientType:              clientType,
		RedirectURIs:            metadata.RedirectURIs,
		TokenEndpointAuthMethod: metadata.TokenEndpointAuthMethod,
		GrantTypes:              metadata.GrantTypes,
		ResponseTypes:           metadata.ResponseTypes,
		ClientName:              metadata.ClientName,
		Scopes:                  scopes,
		CreatedAt:               time.Now(),
	}
}

// recordCIMDCacheMetric records CIMD cache metrics.
func (s *Server) recordCIMDCacheMetric(ctx context.Context, operation string) {
	s.Instrumentation.Metrics().RecordCIMDCache(ctx, operation)
}
