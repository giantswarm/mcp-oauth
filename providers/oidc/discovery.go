package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// maxDiscoveryDocumentSize is the maximum allowed size for a discovery document response.
	// OIDC discovery documents are typically <10KB. 1MB provides a generous safety margin
	// while preventing memory exhaustion attacks from malicious servers.
	maxDiscoveryDocumentSize = 1024 * 1024 // 1MB

	// maxRedirects is the maximum number of HTTP redirects to follow during discovery.
	// Limited to prevent redirect loops and SSRF via redirect chains.
	maxRedirects = 3
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
// Cold-cache fetches for the same issuer URL are coalesced via singleflight so
// a fleet bounce cannot stampede the IdP.
type DiscoveryClient struct {
	httpClient     *http.Client
	cache          sync.Map // issuerURL -> *cachedDocument
	cacheTTL       time.Duration
	logger         *slog.Logger
	skipValidation bool // Internal: skip URL validation for testing only
	timeProvider   timeProvider
	fetchGroup     singleflight.Group
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
		// SECURITY: Configure HTTP client with redirect validation to prevent
		// SSRF via redirect chains (e.g., redirect to private IP after initial validation)
		httpClient = &http.Client{
			Timeout: DefaultHTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Limit number of redirects to prevent loops
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				// SECURITY: Validate redirect target URL for SSRF protection
				if err := ValidateIssuerURL(req.URL.String()); err != nil {
					return fmt.Errorf("invalid redirect target: %w", err)
				}
				return nil
			},
		}
	}
	if cacheTTL == 0 {
		cacheTTL = DefaultCacheTTL
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &DiscoveryClient{
		httpClient:   httpClient,
		cacheTTL:     cacheTTL,
		logger:       logger,
		timeProvider: realTime{},
	}
}

// WithSkipValidation returns a [DiscoveryOption] that disables SSRF and HTTPS
// validation on the discovery client. Intended exclusively for unit tests that
// spin up httptest servers on loopback addresses. Production callers must not
// use this option — it bypasses all URL security checks.
func WithSkipValidation() DiscoveryOption {
	return func(c *DiscoveryClient) { c.skipValidation = true }
}

// DiscoveryOption is a functional option for [NewDiscoveryClientWithOptions].
type DiscoveryOption func(*DiscoveryClient)

// NewDiscoveryClientWithOptions creates a discovery client applying the given
// options after default initialization. Use [WithSkipValidation] only in tests.
func NewDiscoveryClientWithOptions(httpClient *http.Client, cacheTTL time.Duration, logger *slog.Logger, opts ...DiscoveryOption) *DiscoveryClient {
	client := NewDiscoveryClient(httpClient, cacheTTL, logger)
	for _, opt := range opts {
		opt(client)
	}
	return client
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

	if doc, ok := c.cachedFresh(issuerURL); ok {
		return doc, nil
	}

	// DoChan + a leader ctx detached from caller cancellation: each caller
	// selects on its own ctx vs the shared result channel. One caller's
	// cancellation cannot poison the others, and the shared fetch (bounded
	// by http.Client.Timeout) completes and caches its result for any
	// caller still listening or any future cache reader.
	ch := c.fetchGroup.DoChan(issuerURL, func() (any, error) {
		if doc, ok := c.cachedFresh(issuerURL); ok {
			return doc, nil
		}
		return c.fetchAndCache(context.WithoutCancel(ctx), issuerURL)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*DiscoveryDocument), nil
	}
}

// cachedFresh returns a cached document for issuerURL when its age is within
// cacheTTL; ok is false on cache miss, expiry, or corruption.
func (c *DiscoveryClient) cachedFresh(issuerURL string) (*DiscoveryDocument, bool) {
	cached, ok := c.cache.Load(issuerURL)
	if !ok {
		return nil, false
	}
	doc, ok := cached.(*cachedDocument)
	if !ok {
		c.logger.Error("cache corruption: invalid type", "issuer", issuerURL)
		c.cache.Delete(issuerURL)
		return nil, false
	}
	if c.timeProvider.Since(doc.fetchedAt) >= c.cacheTTL {
		c.logger.Debug("OIDC discovery cache expired", "issuer", issuerURL)
		return nil, false
	}
	c.logger.Debug("OIDC discovery cache hit", "issuer", issuerURL)
	return doc.document, true
}

func (c *DiscoveryClient) fetchAndCache(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	discoveryURL := issuerURL
	if len(discoveryURL) == 0 {
		return nil, fmt.Errorf("issuer URL is empty")
	}
	if discoveryURL[len(discoveryURL)-1] != '/' {
		discoveryURL += "/"
	}
	discoveryURL += ".well-known/openid-configuration"

	c.logger.Debug("Fetching OIDC discovery document", "url", discoveryURL)

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("OIDC discovery failed with status %d", resp.StatusCode)
	}

	// SECURITY: Limit response body size to prevent memory exhaustion attacks
	// Discovery documents are typically <10KB, 1MB is a generous safety margin
	limitedBody := http.MaxBytesReader(nil, resp.Body, maxDiscoveryDocumentSize)
	defer func() {
		_ = limitedBody.Close()
	}()

	var doc DiscoveryDocument
	if err := json.NewDecoder(limitedBody).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	// SECURITY: Validate all endpoints use HTTPS
	if err := c.validateDocument(&doc); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}

	c.cache.Store(issuerURL, &cachedDocument{
		document:  &doc,
		fetchedAt: c.timeProvider.Now(),
	})

	c.logger.Debug("OIDC discovery successful",
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
		if err := ValidateHTTPSURL(endpoint.url, endpoint.name); err != nil {
			return err
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
		if endpoint.url != "" {
			if err := ValidateHTTPSURL(endpoint.url, endpoint.name); err != nil {
				return err
			}
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
	c.cache.Range(func(key, _ any) bool {
		c.cache.Delete(key)
		count++
		return true
	})
	c.logger.Debug("OIDC discovery cache cleared", "entries_removed", count)
}
