package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// clientMetadataCache implements an in-memory LRU cache for URL-based client metadata
// with TTL support and HTTP Cache-Control header respect
type clientMetadataCache struct {
	mu         sync.RWMutex
	entries    map[string]*cachedMetadataEntry
	maxEntries int
	defaultTTL time.Duration
}

// cachedMetadataEntry represents a cached client metadata entry with expiry
type cachedMetadataEntry struct {
	metadata  *ClientMetadata
	client    *storage.Client // Converted client for use in authorization flow
	expiresAt time.Time
	cachedAt  time.Time
}

// newClientMetadataCache creates a new metadata cache
func newClientMetadataCache(defaultTTL time.Duration, maxEntries int) *clientMetadataCache {
	if maxEntries <= 0 {
		maxEntries = 1000 // Default: cache up to 1000 unique URL clients
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute // Default: 5 minute TTL
	}

	return &clientMetadataCache{
		entries:    make(map[string]*cachedMetadataEntry),
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}
}

// Get retrieves metadata from cache if present and not expired
func (c *clientMetadataCache) Get(clientID string) (*storage.Client, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[clientID]
	if !ok {
		return nil, false
	}

	// Check if expired
	now := time.Now()
	if now.After(entry.expiresAt) {
		return nil, false
	}

	return entry.client, true
}

// Set stores metadata in cache with TTL
func (c *clientMetadataCache) Set(clientID string, metadata *ClientMetadata, client *storage.Client, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply LRU eviction if cache is full
	if len(c.entries) >= c.maxEntries {
		c.evictOldest()
	}

	if ttl <= 0 {
		ttl = c.defaultTTL
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
	}
}

// CleanupExpired removes all expired entries from cache
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

// Clear removes all entries from cache
func (c *clientMetadataCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cachedMetadataEntry)
}

// getOrFetchClient retrieves a client from cache or fetches metadata if not cached
// This is the main entry point for URL-based client resolution
//
// Security features:
// - SSRF protection: Enforced at HTTP connection time in createSSRFProtectedTransport()
//   This prevents DNS rebinding attacks by validating IPs when connecting, not just during initial URL validation
// - Singleflight deduplication: prevents concurrent fetches of the same URL (DoS protection)
// - Rate limiting: per-domain rate limiting to prevent abuse (default: 10 req/min per domain)
// - Audit logging: all cache hits and fetches are logged for security monitoring
func (s *Server) getOrFetchClient(ctx context.Context, clientID string) (*storage.Client, error) {
	// Check if URL-based client ID
	if !isURLClientID(clientID) {
		// Not a URL, use normal client lookup
		return s.clientStore.GetClient(ctx, clientID)
	}

	// Check if CIMD is enabled
	if !s.Config.EnableClientIDMetadataDocuments {
		return nil, fmt.Errorf("URL-based client_id not supported: client_id_metadata_documents feature is disabled")
	}

	// Try cache first
	if cachedClient, ok := s.metadataCache.Get(clientID); ok {
		// SECURITY: Audit log cache hits for security monitoring
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "client_metadata_cache_hit",
				ClientID: clientID,
				Details: map[string]any{
					"source": "cache",
				},
			})
		}
		s.Logger.Debug("Using cached client metadata", "client_id", clientID)
		return cachedClient, nil
	}

	// SECURITY: Apply rate limiting per domain to prevent abuse
	// Parse URL to extract domain
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id URL: %w", err)
	}
	domain := u.Hostname()

	// Check rate limit if rate limiter is configured
	if s.metadataFetchRateLimiter != nil {
		if !s.metadataFetchRateLimiter.Allow(domain) {
			if s.Auditor != nil {
				s.Auditor.LogEvent(security.Event{
					Type:     "client_metadata_rate_limited",
					ClientID: clientID,
					Details: map[string]any{
						"domain": domain,
						"reason": "rate_limit_exceeded",
					},
				})
			}
			return nil, fmt.Errorf("rate limit exceeded for metadata fetches from domain: %s", domain)
		}
	}

	// SECURITY: Use singleflight to deduplicate concurrent fetches of the same URL
	// This prevents DoS via multiple simultaneous requests for the same uncached client_id
	result, err, _ := s.metadataFetchGroup.Do(clientID, func() (interface{}, error) {
		// Double-check cache (another goroutine might have filled it while we waited)
		if cachedClient, ok := s.metadataCache.Get(clientID); ok {
			s.Logger.Debug("Using cached client metadata (singleflight)", "client_id", clientID)
			return cachedClient, nil
		}

		// Cache miss - fetch from URL
		s.Logger.Info("Fetching client metadata from URL", "client_id", clientID)

		metadata, suggestedTTL, fetchErr := s.fetchClientMetadata(ctx, clientID)
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch client metadata: %w", fetchErr)
		}

		// NOTE: SSRF protection happens at connection time in createSSRFProtectedTransport(),
		// which validates IPs when the HTTP client connects. This prevents DNS rebinding attacks
		// where DNS resolution changes between validation and connection time.
		// No post-fetch validation is needed here.

		// Convert metadata to storage.Client
		client := metadataToClient(metadata)

		// Determine cache TTL: use Cache-Control if provided, otherwise use config/default
		ttl := s.Config.ClientMetadataCacheTTL
		if suggestedTTL > 0 {
			// Respect HTTP Cache-Control max-age if present
			ttl = suggestedTTL
			s.Logger.Debug("Using Cache-Control TTL",
				"client_id", clientID,
				"ttl", ttl)
		} else if ttl <= 0 {
			// Fall back to default if neither Cache-Control nor config provides TTL
			ttl = 5 * time.Minute
		}
		s.metadataCache.Set(clientID, metadata, client, ttl)

		return client, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*storage.Client), nil
}

// metadataToClient converts ClientMetadata to storage.Client
func metadataToClient(metadata *ClientMetadata) *storage.Client {
	// Parse scope string into slice
	var scopes []string
	if metadata.Scope != "" {
		scopes = parseScopes(metadata.Scope)
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

// parseScopes splits a space-delimited scope string into a slice
// Uses strings.Fields which automatically handles multiple spaces and trimming
func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return nil
	}
	return strings.Fields(scopeStr)
}
