// Package dex implements the OAuth provider interface for Dex (https://dexidp.io/).
// It supports OIDC authentication with Dex-specific optimizations including connector_id
// support for bypassing the connector selection UI and proper handling of refresh token rotation.
package dex

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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
	maxGroups       int
	logger          *slog.Logger
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

	// MaxGroups is the maximum number of groups to accept from the OIDC groups claim.
	// Groups beyond this limit are truncated (not rejected) and a warning is logged.
	// Default: oidc.DefaultMaxGroups (600). Set higher for enterprise environments
	// with very large group counts (e.g., Active Directory).
	MaxGroups int

	// Logger is an optional structured logger for operational warnings (e.g., group truncation).
	// Default: slog.Default()
	Logger *slog.Logger

	// AllowPrivateIP allows the Dex issuer URL to resolve to a private or
	// loopback IP address during OIDC discovery. Required when Dex is
	// fronted by an internal-only load balancer (e.g. Azure internal LB,
	// air-gapped clusters) where the public hostname resolves to an RFC 1918
	// address. Emits a startup warning when set.
	// WARNING: Reduces SSRF protection. Only enable for private IdP deployments.
	AllowPrivateIP bool

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
	httpClient := resolveHTTPClient(cfg.HTTPClient, cfg.AllowPrivateIP, requestTimeout)
	if cfg.AllowPrivateIP && cfg.HTTPClient == nil {
		slog.Warn("SECURITY WARNING: AllowPrivateIP is enabled for Dex OIDC discovery",
			"risk", "OIDC discovery and token endpoints can resolve to private/internal IP addresses — SSRF possible",
			"recommendation", "Unset for production deployments; use only for private IdP deployments (e.g., internal load balancer fronting Dex)",
			"cwe", "CWE-918",
		)
	}
	discoveryClient := createDiscoveryClient(cfg.skipValidation, httpClient)

	doc, err := performOIDCDiscovery(discoveryClient, cfg.IssuerURL, requestTimeout)
	if err != nil {
		return nil, err
	}

	maxGroups := cfg.MaxGroups
	if maxGroups <= 0 {
		maxGroups = oidc.DefaultMaxGroups
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
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
		maxGroups:       maxGroups,
		logger:          logger,
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

// scopeOpenID is the OpenID Connect scope required by Dex per the OIDC spec.
const scopeOpenID = "openid"

// defaultDexScopes are the default scopes for Dex providers.
var defaultDexScopes = []string{
	scopeOpenID,
	"profile",
	"email",
	"groups",         // Dex-specific: required for group membership
	"offline_access", // Required for refresh tokens
}

// isDexSupportedScope returns true if the scope is recognized by Dex.
// Supported: standard OIDC scopes, Dex-specific scopes, and cross-client audience scopes.
func isDexSupportedScope(scope string) bool {
	switch scope {
	case scopeOpenID, "profile", "email", "offline_access", "groups", "federated:id":
		return true
	default:
		return strings.HasPrefix(scope, AudienceScopePrefix)
	}
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

// resolveHTTPClient returns the HTTP client to use for Dex API calls and OIDC
// discovery. When allowPrivateIP is true and no explicit client is provided, a
// client without SSRF protection is returned so that Dex issuer URLs resolving
// to RFC 1918 addresses (e.g. internal load balancers) are reachable.
func resolveHTTPClient(client *http.Client, allowPrivateIP bool, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	if allowPrivateIP {
		return oidc.NewPrivateIPAllowedHTTPClient(timeout)
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

// DefaultScopes returns a deep copy of the provider's configured default
// scopes so callers cannot mutate the provider's slice.
func (p *Provider) DefaultScopes() []string {
	return providers.CloneScopes(p.Scopes)
}

// AuthorizationURL generates the Dex OAuth authorization URL with PKCE support.
// If connector_id is configured, it appends the parameter to bypass Dex's connector selection UI.
// If scopes is empty, the provider's default configured scopes are used.
// opts contains optional OIDC parameters like prompt, login_hint, max_age (nil for defaults).
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string, authOpts *providers.AuthorizationURLOptions) string {
	var authCodeOpts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		authCodeOpts = append(
			authCodeOpts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Add connector_id parameter if configured (Dex-specific feature)
	// This bypasses the Dex connector selection screen
	if p.connectorID != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("connector_id", p.connectorID))
	}

	// Apply optional OIDC parameters (Dex supports standard OIDC params)
	authCodeOpts = append(authCodeOpts, providers.ApplyAuthorizationURLOptions(authOpts)...)

	// FilterScopes drops scopes Dex would reject ("Unrecognized scope(s)"),
	// deep-copies the input, and force-merges mandatory scopes (openid,
	// audience:server:client_id:*) from defaults via CopyScopes internally.
	scopesToUse := providers.FilterScopes(scopes, p.Scopes, isDexSupportedScope)

	// Create a config with the determined scopes
	config := *p.Config
	config.Scopes = scopesToUse
	return config.AuthCodeURL(state, authCodeOpts...)
}

// ensureOpenIDScope guarantees that "openid" is present in the scope list.
// This is defense-in-depth for OIDC compliance: Dex requires "openid" per spec,
// and this ensures it is always included even if both the client and provider
// defaults somehow omit it.
func ensureOpenIDScope(scopes []string) []string {
	for _, s := range scopes {
		if s == scopeOpenID {
			return scopes
		}
	}
	return append(scopes, scopeOpenID)
}

// ExchangeCode exchanges an authorization code for tokens with PKCE verification.
// Returns standard oauth2.Token.
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	return providers.ExchangeCodeWithPKCE(ctx, p, p.httpClient, code, verifier)
}

// ValidateToken validates an access token by calling Dex's userinfo endpoint.
// It parses user information including groups claim if available.
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
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

	groups := dexUserInfo.Groups
	if len(groups) > 0 {
		validated, truncated, err := oidc.ValidateGroups(groups, p.maxGroups)
		if err != nil {
			return nil, fmt.Errorf("invalid groups claim: %w", err)
		}
		if truncated {
			p.logger.Warn(
				"groups claim truncated for user",
				"user_id", dexUserInfo.Sub,
				"original_count", len(groups),
				"limit", p.maxGroups,
			)
		}
		groups = validated
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
		Groups:        groups,
	}, nil
}

// RefreshToken refreshes an expired token using a refresh token.
// CRITICAL: Dex implements refresh token rotation - it returns a NEW refresh token
// on every refresh operation. The oauth2 library automatically captures this new token.
// Returns standard oauth2.Token with the new refresh token.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
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
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}
	if doc.RevocationEndpoint == "" {
		// Spec-compliant gracefully-degraded path: some OIDC providers don't
		// support revocation.
		return nil
	}
	return oidc.RevokeAtEndpoint(ctx, p.httpClient, doc.RevocationEndpoint, token, p.ClientID, p.ClientSecret)
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
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Attempt to fetch discovery document
	_, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("dex provider unreachable: %w", err)
	}

	return nil
}

// JWKSURI returns the JWKS URI for Dex from the discovery document.
// This implements the JWKSProvider interface for SSO token forwarding.
func (p *Provider) JWKSURI(ctx context.Context) (string, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to discover JWKS URI: %w", err)
	}

	return doc.JWKSUri, nil
}

// IssuerURL returns the Dex issuer URL for JWT validation.
func (p *Provider) IssuerURL() string {
	return p.issuerURL
}
