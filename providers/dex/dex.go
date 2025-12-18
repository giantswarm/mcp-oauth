// Package dex implements the OAuth provider interface for Dex (https://dexidp.io/).
// It supports OIDC authentication with Dex-specific optimizations including connector_id
// support for bypassing the connector selection UI and proper handling of refresh token rotation.
package dex

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// Provider implements the providers.Provider interface for Dex OAuth.
// It uses OIDC discovery to fetch endpoints dynamically and supports Dex-specific
// features like connector_id parameter and groups claim.
type Provider struct {
	*oauth2.Config
	discoveryClient *oidc.DiscoveryClient
	issuerURL       string
	connectorID     string
	httpClient      *http.Client
	requestTimeout  time.Duration
}

// Config holds Dex OAuth configuration
type Config struct {
	// IssuerURL is the Dex issuer URL (e.g., https://dex.example.com)
	IssuerURL string

	// ClientID is the OAuth client ID
	ClientID string

	// ClientSecret is the OAuth client secret
	ClientSecret string

	// RedirectURL is the OAuth redirect URL
	RedirectURL string

	// ConnectorID is the optional Dex connector to use (e.g., "github", "ldap")
	// When set, bypasses the Dex connector selection UI
	ConnectorID string

	// Scopes are optional custom scopes (defaults to Dex-optimized scopes if empty)
	// Default: ["openid", "profile", "email", "groups", "offline_access"]
	Scopes []string

	// HTTPClient is an optional custom HTTP client
	HTTPClient *http.Client

	// RequestTimeout is the timeout for provider API calls (default: 30s)
	RequestTimeout time.Duration

	// skipValidation skips SSRF protection for issuer URLs
	// INTERNAL USE ONLY: This is for testing with localhost test servers
	// Production code must NEVER set this to true
	skipValidation bool
}

// NewProvider creates a new Dex OAuth provider.
// It performs OIDC discovery to fetch authorization and token endpoints.
func NewProvider(cfg *Config) (*Provider, error) {
	if err := validateRequiredConfig(cfg); err != nil {
		return nil, err
	}

	scopes, err := resolveScopes(cfg.Scopes)
	if err != nil {
		return nil, err
	}

	requestTimeout := resolveTimeout(cfg.RequestTimeout)
	httpClient := resolveHTTPClient(cfg.HTTPClient, requestTimeout)
	discoveryClient := createDiscoveryClient(cfg.skipValidation, httpClient)

	doc, err := performOIDCDiscovery(discoveryClient, cfg.IssuerURL, requestTimeout)
	if err != nil {
		return nil, err
	}

	return &Provider{
		Config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  doc.AuthorizationEndpoint,
				TokenURL: doc.TokenEndpoint,
			},
		},
		discoveryClient: discoveryClient,
		issuerURL:       cfg.IssuerURL,
		connectorID:     cfg.ConnectorID,
		httpClient:      httpClient,
		requestTimeout:  requestTimeout,
	}, nil
}

// validateRequiredConfig validates required configuration fields.
func validateRequiredConfig(cfg *Config) error {
	if cfg.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if cfg.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if cfg.IssuerURL == "" {
		return fmt.Errorf("issuer URL is required")
	}

	// SECURITY: Validate issuer URL with SSRF protection (skip for tests)
	if !cfg.skipValidation {
		if err := oidc.ValidateIssuerURL(cfg.IssuerURL); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
	}

	// SECURITY: Validate connector_id if provided
	if cfg.ConnectorID != "" {
		if err := oidc.ValidateConnectorID(cfg.ConnectorID); err != nil {
			return fmt.Errorf("invalid connector ID: %w", err)
		}
	}

	return nil
}

// defaultDexScopes are the default scopes for Dex providers.
var defaultDexScopes = []string{
	"openid",
	"profile",
	"email",
	"groups",         // Dex-specific: required for group membership
	"offline_access", // Required for refresh tokens
}

// resolveScopes returns validated scopes, using defaults if none provided.
func resolveScopes(configScopes []string) ([]string, error) {
	scopes := configScopes
	if len(scopes) == 0 {
		scopes = defaultDexScopes
	}

	if err := oidc.ValidateScopes(scopes); err != nil {
		return nil, fmt.Errorf("invalid scopes: %w", err)
	}

	return scopes, nil
}

// resolveTimeout returns the timeout, using default if not set.
func resolveTimeout(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return 30 * time.Second
	}
	return timeout
}

// resolveHTTPClient returns the HTTP client, creating one if not provided.
func resolveHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: timeout}
}

// createDiscoveryClient creates an OIDC discovery client.
func createDiscoveryClient(skipValidation bool, httpClient *http.Client) *oidc.DiscoveryClient {
	if skipValidation {
		return oidc.NewTestDiscoveryClient(httpClient, 1*time.Hour, nil)
	}
	return oidc.NewDiscoveryClient(httpClient, 1*time.Hour, nil)
}

// performOIDCDiscovery performs OIDC discovery to fetch endpoints.
func performOIDCDiscovery(client *oidc.DiscoveryClient, issuerURL string, timeout time.Duration) (*oidc.DiscoveryDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	doc, err := client.Discover(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	return doc, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "dex"
}

// DefaultScopes returns the provider's configured default scopes.
// Returns a deep copy to prevent external modification.
func (p *Provider) DefaultScopes() []string {
	if p.Scopes == nil {
		return nil
	}
	scopes := make([]string, len(p.Scopes))
	copy(scopes, p.Scopes)
	return scopes
}

// AuthorizationURL generates the Dex OAuth authorization URL with PKCE support.
// If connector_id is configured, it appends the parameter to bypass Dex's connector selection UI.
// If scopes is empty, the provider's default configured scopes are used.
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string) string {
	var opts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Add connector_id parameter if configured (Dex-specific feature)
	// This bypasses the Dex connector selection screen
	if p.connectorID != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("connector_id", p.connectorID),
		)
	}

	// SECURITY: Create a deep copy of scopes to prevent potential race conditions
	var scopesToUse []string
	if len(scopes) > 0 {
		// Use requested scopes (create deep copy)
		scopesToUse = make([]string, len(scopes))
		copy(scopesToUse, scopes)
	} else {
		// Use provider's default scopes (create deep copy)
		scopesToUse = make([]string, len(p.Scopes))
		copy(scopesToUse, p.Scopes)
	}

	// Create a config with the determined scopes
	config := *p.Config
	config.Scopes = scopesToUse
	return config.AuthCodeURL(state, opts...)
}

// ensureContextTimeout ensures the context has a deadline, adding one if needed.
// Returns a new context with timeout and a cancel function that should be deferred.
// If the context already has a deadline, returns the original context with a no-op cancel.
func (p *Provider) ensureContextTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		// Context already has deadline, return no-op cancel
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, p.requestTimeout)
}

// ExchangeCode exchanges an authorization code for tokens with PKCE verification.
// Returns standard oauth2.Token.
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	var opts []oauth2.AuthCodeOption

	// Add PKCE verifier if provided
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Exchange code for token
	token, err := p.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

// ValidateToken validates an access token by calling Dex's userinfo endpoint.
// It parses user information including groups claim if available.
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Get discovery document to find userinfo endpoint
	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	if doc.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available in discovery document")
	}

	// Use custom HTTP client for tests (trusts test TLS certificates)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Create HTTP client with the token
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	client := p.Client(ctx, token)

	// Call Dex's userinfo endpoint
	resp, err := client.Get(doc.UserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	// Parse Dex's user info response
	var dexUserInfo struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		GivenName     string   `json:"given_name"`
		FamilyName    string   `json:"family_name"`
		Picture       string   `json:"picture"`
		Locale        string   `json:"locale"`
		Groups        []string `json:"groups"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dexUserInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// SECURITY: Validate groups claim
	if len(dexUserInfo.Groups) > 0 {
		if err := oidc.ValidateGroups(dexUserInfo.Groups); err != nil {
			return nil, fmt.Errorf("invalid groups claim: %w", err)
		}
	}

	return &providers.UserInfo{
		ID:            dexUserInfo.Sub,
		Email:         dexUserInfo.Email,
		EmailVerified: dexUserInfo.EmailVerified,
		Name:          dexUserInfo.Name,
		GivenName:     dexUserInfo.GivenName,
		FamilyName:    dexUserInfo.FamilyName,
		Picture:       dexUserInfo.Picture,
		Locale:        dexUserInfo.Locale,
		Groups:        dexUserInfo.Groups,
	}, nil
}

// RefreshToken refreshes an expired token using a refresh token.
// CRITICAL: Dex implements refresh token rotation - it returns a NEW refresh token
// on every refresh operation. The oauth2 library automatically captures this new token.
// Returns standard oauth2.Token with the new refresh token.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Create token source from refresh token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := p.TokenSource(ctx, token)

	// Get fresh token - this automatically handles Dex's refresh token rotation
	// The oauth2 library captures the new refresh token from the response
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// CRITICAL: newToken.RefreshToken contains the NEW refresh token from Dex
	// The server layer will store this new token, replacing the old one
	return newToken, nil
}

// RevokeToken revokes a token at Dex's revocation endpoint if available.
// Gracefully degrades if revocation endpoint is not supported.
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Get discovery document to find revocation endpoint
	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// If revocation endpoint not available, gracefully degrade
	if doc.RevocationEndpoint == "" {
		// Not an error - some OIDC providers don't support revocation
		return nil
	}

	// Prepare revocation request
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, "POST", doc.RevocationEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	// Set content type for form data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client credentials for authentication
	req.SetBasicAuth(p.ClientID, p.ClientSecret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// RFC 7009 Section 2.2: The authorization server responds with HTTP status code 200
	// if the token has been revoked successfully or if the client submitted an invalid token.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	return nil
}

// HealthCheck verifies that the Dex OIDC discovery endpoint is reachable.
// It performs a lightweight check by fetching the OpenID Connect discovery document.
//
// Security Considerations:
//   - This method is designed for server-side health monitoring (k8s probes, monitoring systems)
//   - DO NOT expose the returned error messages directly to untrusted clients
//   - Error messages may contain HTTP status codes that could leak provider state information
//   - For public health endpoints, return generic "healthy/unhealthy" status only
func (p *Provider) HealthCheck(ctx context.Context) error {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Attempt to fetch discovery document
	_, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("dex provider unreachable: %w", err)
	}

	return nil
}
