package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	oauthgithub "golang.org/x/oauth2/github"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// Compile-time check that Provider implements the providers.Provider interface.
var _ providers.Provider = (*Provider)(nil)

// providerName is the name returned by Provider.Name().
const providerName = "github"

// ErrRefreshNotSupported is returned when attempting to refresh a token.
// GitHub OAuth Apps issue non-expiring access tokens and don't support refresh.
var ErrRefreshNotSupported = errors.New("github oauth apps do not support token refresh")

// ErrOrganizationRequired is returned when a user is not a member of any allowed organization.
var ErrOrganizationRequired = errors.New("user is not a member of any allowed organization")

// GitHub API endpoints
const (
	userEndpoint   = "https://api.github.com/user"
	emailsEndpoint = "https://api.github.com/user/emails"
	orgsEndpoint   = "https://api.github.com/user/orgs"
	rateLimitURL   = "https://api.github.com/rate_limit"
)

// maxResponseBodySize is the maximum size of GitHub API response bodies (1MB).
// This prevents potential DoS attacks from malicious or compromised responses.
const maxResponseBodySize = 1 << 20 // 1MB

// Provider implements the providers.Provider interface for GitHub OAuth.
type Provider struct {
	*oauth2.Config
	httpClient           *http.Client
	requestTimeout       time.Duration
	allowedOrganizations []string
	requireVerifiedEmail bool
}

// Config holds GitHub OAuth configuration.
type Config struct {
	// ClientID is the GitHub OAuth App client ID.
	ClientID string

	// ClientSecret is the GitHub OAuth App client secret.
	ClientSecret string

	// RedirectURL is the OAuth callback URL.
	RedirectURL string

	// Scopes are optional custom scopes (defaults to ["user:email", "read:user"]).
	Scopes []string

	// RequireVerifiedEmail requires the user's email to be verified (default: true).
	RequireVerifiedEmail *bool

	// AllowedOrganizations restricts login to members of specific organizations.
	// When set, the "read:org" scope is automatically added if not present.
	AllowedOrganizations []string

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client

	// RequestTimeout is the timeout for GitHub API calls (default: 30s).
	RequestTimeout time.Duration
}

// NewProvider creates a new GitHub OAuth provider.
func NewProvider(cfg *Config) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	scopes, err := normalizeScopes(cfg.Scopes, cfg.AllowedOrganizations)
	if err != nil {
		return nil, err
	}

	allowedOrgs, err := validateOrganizations(cfg.AllowedOrganizations)
	if err != nil {
		return nil, err
	}

	requestTimeout := cfg.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 30 * time.Second
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}

	requireVerifiedEmail := cfg.RequireVerifiedEmail == nil || *cfg.RequireVerifiedEmail

	return &Provider{
		Config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     oauthgithub.Endpoint,
		},
		httpClient:           httpClient,
		requestTimeout:       requestTimeout,
		allowedOrganizations: allowedOrgs,
		requireVerifiedEmail: requireVerifiedEmail,
	}, nil
}

// validateConfig checks that required configuration fields are present.
func validateConfig(cfg *Config) error {
	if cfg.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if cfg.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	return nil
}

// normalizeScopes handles scope defaulting, copying, and adding read:org if needed.
func normalizeScopes(configScopes, allowedOrgs []string) ([]string, error) {
	scopes := configScopes
	if len(scopes) == 0 {
		scopes = []string{"user:email", "read:user"}
	}

	// Deep copy scopes to prevent external modification
	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopes = scopesCopy

	// If organizations are restricted, ensure read:org scope is present
	if len(allowedOrgs) > 0 && !containsScope(scopes, "read:org") {
		scopes = append(scopes, "read:org")
	}

	// SECURITY: Validate scopes
	if err := oidc.ValidateScopes(scopes); err != nil {
		return nil, fmt.Errorf("invalid scopes: %w", err)
	}

	return scopes, nil
}

// containsScope checks if a scope is present in the list.
func containsScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

// validateOrganizations validates and deep copies the allowed organizations list.
func validateOrganizations(orgs []string) ([]string, error) {
	if len(orgs) == 0 {
		return nil, nil
	}

	allowedOrgs := make([]string, len(orgs))
	copy(allowedOrgs, orgs)

	for _, org := range allowedOrgs {
		if org == "" {
			return nil, fmt.Errorf("organization name cannot be empty")
		}
		// GitHub org names: 1-39 chars, alphanumeric and hyphens, no double hyphens
		if len(org) > 39 {
			return nil, fmt.Errorf("organization name %q exceeds maximum length of 39 characters", org)
		}
	}

	return allowedOrgs, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return providerName
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

// AuthorizationURL generates the GitHub OAuth authorization URL with optional PKCE.
// If scopes is empty, the provider's default configured scopes are used.
// GitHub supports PKCE but doesn't require it for confidential clients.
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string) string {
	var opts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided (GitHub supports PKCE)
	if codeChallenge != "" && codeChallengeMethod != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
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
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, p.requestTimeout)
}

// ExchangeCode exchanges an authorization code for tokens with optional PKCE verification.
// Returns standard oauth2.Token. Note: GitHub OAuth Apps don't return refresh tokens.
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	return providers.ExchangeCodeWithPKCE(ctx, p, p.httpClient, code, verifier)
}

// ValidateToken validates an access token by calling GitHub's user endpoint.
// It retrieves user information and optionally validates organization membership.
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	// Fetch user info from GitHub
	userInfo, err := p.fetchUserInfo(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	// If email is empty, try to fetch from /user/emails endpoint
	if userInfo.Email == "" {
		email, verified, emailErr := p.fetchPrimaryEmail(ctx, accessToken)
		if emailErr == nil && email != "" {
			userInfo.Email = email
			userInfo.EmailVerified = verified
		}
	}

	// Validate organization membership if required
	if len(p.allowedOrganizations) > 0 {
		isMember, err := p.validateOrganizationMembership(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to validate organization membership: %w", err)
		}
		if !isMember {
			return nil, ErrOrganizationRequired
		}
	}

	return userInfo, nil
}

// fetchUserInfo fetches user information from GitHub's /user endpoint.
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d", resp.StatusCode)
	}

	// Parse GitHub's user response
	// SECURITY: Limit response body size to prevent DoS from oversized responses
	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		Location  string `json:"location"`
		Bio       string `json:"bio"`
	}

	limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limitedBody).Decode(&ghUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &providers.UserInfo{
		ID:            fmt.Sprintf("%d", ghUser.ID),
		Email:         ghUser.Email,
		EmailVerified: ghUser.Email != "", // Assume verified if email is public
		Name:          ghUser.Name,
		Picture:       ghUser.AvatarURL,
		// GitHub doesn't provide given_name/family_name, locale separately
	}, nil
}

// fetchPrimaryEmail fetches the user's verified primary email from /user/emails.
func (p *Provider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", emailsEndpoint, nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("emails request failed with status %d", resp.StatusCode)
	}

	// SECURITY: Limit response body size to prevent DoS from oversized responses
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limitedBody).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("failed to decode emails: %w", err)
	}

	// Find primary verified email
	for _, email := range emails {
		if email.Primary && (email.Verified || !p.requireVerifiedEmail) {
			return email.Email, email.Verified, nil
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified || !p.requireVerifiedEmail {
			return email.Email, email.Verified, nil
		}
	}

	return "", false, nil
}

// fetchUserOrganizations fetches all organization logins for the user from GitHub API.
// This is the core implementation used by both validateOrganizationMembership and GetUserOrganizations.
func (p *Provider) fetchUserOrganizations(ctx context.Context, accessToken string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", orgsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("orgs request failed with status %d", resp.StatusCode)
	}

	// SECURITY: Limit response body size to prevent DoS from oversized responses
	var orgs []struct {
		Login string `json:"login"`
	}

	limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limitedBody).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode orgs: %w", err)
	}

	result := make([]string, len(orgs))
	for i, org := range orgs {
		result[i] = org.Login
	}

	return result, nil
}

// validateOrganizationMembership checks if the user is a member of any allowed organization.
func (p *Provider) validateOrganizationMembership(ctx context.Context, accessToken string) (bool, error) {
	orgs, err := p.fetchUserOrganizations(ctx, accessToken)
	if err != nil {
		return false, err
	}

	// Check if user is member of any allowed organization (case-insensitive)
	for _, org := range orgs {
		for _, allowedOrg := range p.allowedOrganizations {
			if strings.EqualFold(org, allowedOrg) {
				return true, nil
			}
		}
	}

	return false, nil
}

// RefreshToken attempts to refresh an expired token.
// Returns ErrRefreshNotSupported because GitHub OAuth Apps don't support token refresh.
// Standard GitHub OAuth Apps issue non-expiring access tokens.
func (p *Provider) RefreshToken(_ context.Context, _ string) (*oauth2.Token, error) {
	return nil, ErrRefreshNotSupported
}

// RevokeToken revokes a token at GitHub.
// GitHub doesn't have a public revocation endpoint for OAuth tokens.
// This method returns nil (graceful degradation) since server-side revocation
// isn't supported. Users must revoke tokens through GitHub settings.
func (p *Provider) RevokeToken(_ context.Context, _ string) error {
	// GitHub OAuth doesn't support server-side token revocation
	// Users must revoke access through: Settings -> Applications -> Authorized OAuth Apps
	// Return nil for graceful degradation (same pattern as Dex when endpoint missing)
	return nil
}

// HealthCheck verifies that the GitHub API is reachable.
// It performs a lightweight check by calling the rate limit endpoint.
//
// Security Considerations:
//   - This method is designed for server-side health monitoring
//   - DO NOT expose error details to untrusted clients
//   - For public endpoints, return generic "healthy/unhealthy" status only
func (p *Provider) HealthCheck(ctx context.Context) error {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", rateLimitURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github api unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// GitHub returns 200 for rate limit endpoint even without auth
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetUserOrganizations returns the list of organizations the user belongs to.
// This is useful for applications that want to display org membership or
// implement custom authorization logic beyond simple org validation.
//
// Requires the "read:org" scope.
func (p *Provider) GetUserOrganizations(ctx context.Context, accessToken string) ([]string, error) {
	ctx, cancel := p.ensureContextTimeout(ctx)
	defer cancel()

	return p.fetchUserOrganizations(ctx, accessToken)
}

// GetProviderToken returns a token suitable for making additional GitHub API calls.
// This is useful for applications that need to access GitHub APIs beyond basic auth.
func (p *Provider) GetProviderToken(accessToken string) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
}
