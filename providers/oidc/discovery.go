package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DiscoveryDocument represents an OIDC discovery document.
// It contains the OpenID Connect provider metadata as defined in RFC 8414.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	JWKSUri                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// cachedDocument holds a discovery document with its fetch timestamp.
type cachedDocument struct {
	document  *DiscoveryDocument
	fetchedAt time.Time
}

// DiscoveryClient fetches and caches OIDC discovery documents.
// It provides SSRF protection and HTTPS enforcement for all discovered endpoints.
//
// The client is thread-safe and can be used concurrently from multiple goroutines.
type DiscoveryClient struct {
	httpClient       *http.Client
	cache            sync.Map // issuerURL -> *cachedDocument
	cacheTTL         time.Duration
	logger           *slog.Logger
	skipValidation   bool // Internal: skip URL validation for testing only
}

// NewDiscoveryClient creates a new OIDC discovery client with default configuration.
//
// Parameters:
//   - httpClient: HTTP client to use for requests (nil uses default with 10s timeout)
//   - cacheTTL: Time-to-live for cached discovery documents (0 uses default 1 hour)
//   - logger: Logger for debug/info messages (nil uses default logger)
//
// Example:
//
//	client := oidc.NewDiscoveryClient(nil, 1*time.Hour, slog.Default())
//	doc, err := client.Discover(ctx, "https://dex.example.com")
func NewDiscoveryClient(httpClient *http.Client, cacheTTL time.Duration, logger *slog.Logger) *DiscoveryClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &DiscoveryClient{
		httpClient: httpClient,
		cacheTTL:   cacheTTL,
		logger:     logger,
	}
}

// Discover fetches the OIDC discovery document for an issuer.
// It validates the issuer URL for security (SSRF protection) and caches results.
//
// Security Features:
//   - SSRF protection via ValidateIssuerURL
//   - HTTPS enforcement for issuer and all discovered endpoints
//   - Document caching with TTL to reduce attack surface
//
// Example:
//
//	doc, err := client.Discover(ctx, "https://dex.example.com")
//	if err != nil {
//	    return fmt.Errorf("discovery failed: %w", err)
//	}
//	// Use doc.AuthorizationEndpoint, doc.TokenEndpoint, etc.
func (c *DiscoveryClient) Discover(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	// SECURITY: Validate issuer URL before making request
	// Skip validation only in tests (skipValidation is internal and not exported)
	if !c.skipValidation {
		if err := ValidateIssuerURL(issuerURL); err != nil {
			return nil, fmt.Errorf("invalid issuer URL: %w", err)
		}
	}

	// Check cache first
	if cached, ok := c.cache.Load(issuerURL); ok {
		doc := cached.(*cachedDocument)
		if time.Since(doc.fetchedAt) < c.cacheTTL {
			c.logger.Debug("OIDC discovery cache hit", "issuer", issuerURL)
			return doc.document, nil
		}
		c.logger.Debug("OIDC discovery cache expired", "issuer", issuerURL)
	}

	// Fetch discovery document
	discoveryURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	c.logger.Debug("Fetching OIDC discovery document", "url", discoveryURL)

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery failed with status %d", resp.StatusCode)
	}

	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	// SECURITY: Validate all endpoints use HTTPS
	if err := c.validateDocument(&doc); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}

	// Cache the document
	c.cache.Store(issuerURL, &cachedDocument{
		document:  &doc,
		fetchedAt: time.Now(),
	})

	c.logger.Info("OIDC discovery successful",
		"issuer", issuerURL,
		"authorization_endpoint", doc.AuthorizationEndpoint,
		"token_endpoint", doc.TokenEndpoint)

	return &doc, nil
}

// validateDocument validates security properties of discovery document.
// All endpoints must use HTTPS to prevent credential leakage.
func (c *DiscoveryClient) validateDocument(doc *DiscoveryDocument) error {
	// SECURITY: All required endpoints must use HTTPS
	endpoints := []struct {
		name string
		url  string
	}{
		{"issuer", doc.Issuer},
		{"authorization_endpoint", doc.AuthorizationEndpoint},
		{"token_endpoint", doc.TokenEndpoint},
		{"jwks_uri", doc.JWKSUri},
	}

	for _, endpoint := range endpoints {
		if endpoint.url == "" {
			return fmt.Errorf("%s is required but missing", endpoint.name)
		}
		if !strings.HasPrefix(endpoint.url, "https://") {
			return fmt.Errorf("%s must use HTTPS: %s", endpoint.name, endpoint.url)
		}
	}

	// Optional endpoints that must be HTTPS if present
	optionalEndpoints := []struct {
		name string
		url  string
	}{
		{"userinfo_endpoint", doc.UserInfoEndpoint},
		{"revocation_endpoint", doc.RevocationEndpoint},
	}

	for _, endpoint := range optionalEndpoints {
		if endpoint.url != "" && !strings.HasPrefix(endpoint.url, "https://") {
			return fmt.Errorf("%s must use HTTPS if present: %s", endpoint.name, endpoint.url)
		}
	}

	return nil
}

// ClearCache clears the discovery document cache.
// This is useful for forcing a refresh of all cached documents.
//
// Example:
//
//	client.ClearCache() // Force refresh on next Discover() call
func (c *DiscoveryClient) ClearCache() {
	count := 0
	c.cache.Range(func(key, value interface{}) bool {
		c.cache.Delete(key)
		count++
		return true
	})
	c.logger.Debug("OIDC discovery cache cleared", "entries_removed", count)
}
