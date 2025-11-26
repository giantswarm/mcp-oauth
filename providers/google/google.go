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
}

// Config holds Google OAuth configuration
type Config struct {
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	Scopes         []string
	HTTPClient     *http.Client  // Optional custom HTTP client
	RequestTimeout time.Duration // Timeout for provider API calls (default: 30s)
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
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "google"
}

// AuthorizationURL generates the Google OAuth authorization URL with optional PKCE.
// Supports OAuth 2.1 defense-in-depth. See SECURITY_ARCHITECTURE.md for details.
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string) string {
	var opts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Request offline access to get refresh token
	opts = append(opts, oauth2.AccessTypeOffline)

	return p.AuthCodeURL(state, opts...)
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
	var googleUserInfo struct {
		Sub           string `json:"sub"`
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

	return &providers.UserInfo{
		ID:            googleUserInfo.Sub,
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
