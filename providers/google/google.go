// Package google implements the OAuth provider interface for Google OAuth 2.0.
// It supports user authentication, token exchange, and access to Google APIs.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/giantswarm/mcp-oauth/providers"
)

// Provider implements the providers.Provider interface for Google OAuth.
// Embeds oauth2.Config directly to avoid duplication.
type Provider struct {
	*oauth2.Config
	httpClient     *http.Client
	requestTimeout time.Duration
	forceConsent   bool
}

// Config holds Google OAuth configuration
type Config struct {
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	Scopes         []string
	HTTPClient     *http.Client  // Optional custom HTTP client
	RequestTimeout time.Duration // Timeout for provider API calls (default: 30s)

	// ForceConsent forces the consent screen on every authorization.
	// This ensures a refresh token is always returned by Google.
	// Google only sends refresh tokens on the first consent, so without this
	// option, subsequent authorizations will not include a refresh token.
	// Default: true (recommended for server applications that need refresh tokens)
	//
	// Set to false only if you don't need refresh tokens or prefer fewer consent prompts.
	// See: https://developers.google.com/identity/protocols/oauth2/web-server#offline
	ForceConsent *bool
}

// NewProvider creates a new Google OAuth provider
func NewProvider(cfg *Config) (*Provider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client secret is required")
	}

	// Default scopes if none provided
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Set request timeout (default: 30 seconds)
	requestTimeout := cfg.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 30 * time.Second
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: requestTimeout,
		}
	}

	// Default ForceConsent to true (recommended for server applications)
	forceConsent := true
	if cfg.ForceConsent != nil {
		forceConsent = *cfg.ForceConsent
	}

	return &Provider{
		Config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
		httpClient:     httpClient,
		requestTimeout: requestTimeout,
		forceConsent:   forceConsent,
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "google"
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

// isGoogleSupportedScope returns true if the scope is recognized by Google's OAuth endpoints.
// Supported scopes:
//   - "openid", "email", "profile": Standard OIDC scopes
//   - Scopes starting with "https://www.googleapis.com/": Google API scopes
//
// Unsupported scopes (filtered out):
//   - "offline_access": Google uses access_type=offline parameter instead
//   - "groups": Dex-specific scope not recognized by Google
//   - Any other non-Google scopes (e.g., "claudeai", custom provider scopes)
func isGoogleSupportedScope(scope string) bool {
	switch scope {
	case "openid", "email", "profile":
		return true
	default:
		return strings.HasPrefix(scope, "https://www.googleapis.com/")
	}
}

// filterGoogleScopes creates a deep copy of scopes and filters out any scopes that
// Google does not support. This prevents authorization failures when clients send
// provider-specific scopes (e.g., Dex's "groups") or non-standard scopes (e.g., "claudeai")
// to a Google provider.
func filterGoogleScopes(requestedScopes, defaultScopes []string) []string {
	sourceScopes := providers.CopyScopes(requestedScopes, defaultScopes)
	filtered := make([]string, 0, len(sourceScopes))
	for _, s := range sourceScopes {
		if isGoogleSupportedScope(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// AuthorizationURL generates the Google OAuth authorization URL with optional PKCE.
// Supports OAuth 2.1 defense-in-depth. See SECURITY_ARCHITECTURE.md for details.
// If scopes is empty, the provider's default configured scopes are used.
// opts contains optional OIDC parameters like prompt, login_hint, max_age (nil for defaults).
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string, authOpts *providers.AuthorizationURLOptions) string {
	var opts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		opts = append(
			opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Request offline access to get refresh token
	opts = append(opts, oauth2.AccessTypeOffline)

	// Force consent screen if configured (default: true)
	// This ensures Google always returns a refresh token, not just on first consent.
	// Note: If authOpts.Prompt is set, it overrides this setting
	if p.forceConsent && (authOpts == nil || authOpts.Prompt == "") {
		opts = append(opts, oauth2.ApprovalForce)
	}

	// Apply optional OIDC parameters
	opts = append(opts, providers.ApplyAuthorizationURLOptions(authOpts)...)

	// Create a config with filtered scopes
	config := *p.Config
	config.Scopes = filterGoogleScopes(scopes, p.Scopes)
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

// ExchangeCode exchanges an authorization code for tokens with optional PKCE verification.
// Returns standard oauth2.Token. See SECURITY_ARCHITECTURE.md for security model details.
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	return providers.ExchangeCodeWithPKCE(ctx, p, p.httpClient, code, verifier)
}

// ValidateToken validates an access token by calling Google's userinfo endpoint
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Create HTTP client with the token using oauth2.Config.Client
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	client := p.Client(ctx, token)

	// Call Google's userinfo endpoint
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	// Parse Google's user info response
	// Note: v2 endpoint uses "id" while OpenID Connect uses "sub"
	var googleUserInfo struct {
		ID            string `json:"id"`  // v2 endpoint field
		Sub           string `json:"sub"` // OpenID Connect field (fallback)
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Locale        string `json:"locale"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUserInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Use ID from v2 endpoint, fall back to Sub from OpenID Connect
	userID := googleUserInfo.ID
	if userID == "" {
		userID = googleUserInfo.Sub
	}

	return &providers.UserInfo{
		ID:            userID,
		Email:         googleUserInfo.Email,
		EmailVerified: googleUserInfo.EmailVerified,
		Name:          googleUserInfo.Name,
		GivenName:     googleUserInfo.GivenName,
		FamilyName:    googleUserInfo.FamilyName,
		Picture:       googleUserInfo.Picture,
		Locale:        googleUserInfo.Locale,
	}, nil
}

// RefreshToken refreshes an expired token
// Returns standard oauth2.Token directly
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

	// Get fresh token - returns oauth2.Token directly
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// RevokeToken revokes a token at Google's revocation endpoint
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	revokeURL := "https://oauth2.googleapis.com/revoke"
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	// Set content type for form data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	return nil
}

// HealthCheck verifies that Google's OAuth endpoints are reachable.
// It performs a lightweight check by fetching the OpenID Connect discovery document.
// Uses the provided context for timeout and cancellation. If context has no deadline,
// uses provider's default request timeout.
//
// Security Considerations:
//   - This method is designed for server-side health monitoring (k8s probes, monitoring systems)
//   - DO NOT expose the returned error messages directly to untrusted clients
//   - Error messages may contain HTTP status codes that could leak provider state information
//   - For public health endpoints, return generic "healthy/unhealthy" status only
//
// Recommended usage:
//
//	// Internal monitoring - detailed errors OK
//	if err := provider.HealthCheck(ctx); err != nil {
//	    log.Error("Provider health check failed", "error", err)
//	    return http.StatusInternalServerError
//	}
//
//	// Public endpoint - hide error details
//	if err := provider.HealthCheck(ctx); err != nil {
//	    w.WriteHeader(http.StatusServiceUnavailable)
//	    json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy"})
//	    return
//	}
func (p *Provider) HealthCheck(ctx context.Context) error {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://accounts.google.com/.well-known/openid-configuration", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("google oauth provider unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("google oauth provider health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// googleJWKSURI is Google's well-known JWKS URI for JWT validation.
const googleJWKSURI = "https://www.googleapis.com/oauth2/v3/certs"

// googleIssuerURL is Google's OIDC issuer URL.
const googleIssuerURL = "https://accounts.google.com"

// JWKSURI returns Google's JWKS URI for JWT signature verification.
// This implements the JWKSProvider interface for SSO token forwarding.
//
// Note: The context parameter is unused for Google because the JWKS URI is a
// static well-known endpoint. Other providers (like Dex) use the context for
// OIDC discovery which may involve network calls.
func (p *Provider) JWKSURI(_ context.Context) (string, error) {
	return googleJWKSURI, nil
}

// IssuerURL returns Google's issuer URL for JWT validation.
func (p *Provider) IssuerURL() string {
	return googleIssuerURL
}
