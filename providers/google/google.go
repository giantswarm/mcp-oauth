// Package google implements the OAuth provider interface for Google OAuth 2.0.
// It supports user authentication, token exchange, and access to Google APIs.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/giantswarm/mcp-oauth/providers"
)

// Provider implements the providers.Provider interface for Google OAuth.
// Embeds oauth2.Config directly to avoid duplication.
type Provider struct {
	*oauth2.Config
	httpClient *http.Client
}

// Config holds Google OAuth configuration
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HTTPClient   *http.Client // Optional custom HTTP client
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

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
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
		httpClient: httpClient,
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "google"
}

// AuthorizationURL generates the Google OAuth authorization URL
// Accepts pre-computed PKCE challenge from client
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string) string {
	var opts []oauth2.AuthCodeOption

	// Add PKCE if challenge provided (already computed by client)
	if codeChallenge != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Request offline access to get refresh token
	opts = append(opts, oauth2.AccessTypeOffline)

	return p.AuthCodeURL(state, opts...)
}

// ExchangeCode exchanges an authorization code for tokens
// Returns standard oauth2.Token directly
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption

	// PKCE code verifier
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Exchange code for token - returns oauth2.Token directly
	token, err := p.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

// ValidateToken validates an access token by calling Google's userinfo endpoint
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
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
func (p *Provider) RevokeToken(_ context.Context, token string) error {
	revokeURL := "https://oauth2.googleapis.com/revoke"
	data := url.Values{}
	data.Set("token", token)

	resp, err := p.httpClient.PostForm(revokeURL, data)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	return nil
}
