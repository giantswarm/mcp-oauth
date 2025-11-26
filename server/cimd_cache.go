package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

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
		s.Logger.Debug("Using cached client metadata", "client_id", clientID)
		return cachedClient, nil
	}

	// Cache miss - fetch from URL
	s.Logger.Info("Fetching client metadata from URL", "client_id", clientID)

	metadata, err := s.fetchClientMetadata(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client metadata: %w", err)
	}

	// Convert metadata to storage.Client
	client := metadataToClient(metadata)

	// Cache the result
	ttl := s.Config.ClientMetadataCacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default TTL
	}
	s.metadataCache.Set(clientID, metadata, client, ttl)

	return client, nil
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
