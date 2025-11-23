package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Provider implements the providers.Provider interface for Google OAuth.
type Provider struct {
	config     *oauth2.Config
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
		config: &oauth2.Config{
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
func (p *Provider) AuthorizationURL(state string, opts *providers.AuthOptions) string {
	if opts == nil {
		opts = &providers.AuthOptions{}
	}

	// Build OAuth2 options
	var oauth2Opts []oauth2.AuthCodeOption

	// PKCE support
	if opts.CodeChallenge != "" {
		oauth2Opts = append(oauth2Opts,
			oauth2.SetAuthURLParam("code_challenge", opts.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", opts.CodeChallengeMethod),
		)
	}

	// Nonce for OIDC
	if opts.Nonce != "" {
		oauth2Opts = append(oauth2Opts,
			oauth2.SetAuthURLParam("nonce", opts.Nonce),
		)
	}

	// Override redirect URI if provided
	if opts.RedirectURI != "" {
		tempConfig := *p.config
		tempConfig.RedirectURL = opts.RedirectURI
		return tempConfig.AuthCodeURL(state, oauth2Opts...)
	}

	// Override scopes if provided
	if len(opts.Scopes) > 0 {
		tempConfig := *p.config
		tempConfig.Scopes = opts.Scopes
		return tempConfig.AuthCodeURL(state, oauth2Opts...)
	}

	return p.config.AuthCodeURL(state, oauth2Opts...)
}

// ExchangeCode exchanges an authorization code for tokens
func (p *Provider) ExchangeCode(ctx context.Context, code string, opts *providers.ExchangeOptions) (*providers.TokenResponse, error) {
	if opts == nil {
		opts = &providers.ExchangeOptions{}
	}

	// Build exchange options
	var oauth2Opts []oauth2.AuthCodeOption

	// PKCE code verifier
	if opts.CodeVerifier != "" {
		oauth2Opts = append(oauth2Opts,
			oauth2.SetAuthURLParam("code_verifier", opts.CodeVerifier),
		)
	}

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Exchange code for token
	token, err := p.config.Exchange(ctx, code, oauth2Opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return &providers.TokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		TokenType:    token.TokenType,
		// Note: golang.org/x/oauth2 doesn't expose scopes easily
		Scopes: p.config.Scopes,
	}, nil
}

// ValidateToken validates an access token by calling Google's userinfo endpoint
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// Create HTTP client with the token
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	client := p.config.Client(ctx, token)

	// Call Google's userinfo endpoint
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

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
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*providers.TokenResponse, error) {
	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Create token source from refresh token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := p.config.TokenSource(ctx, token)

	// Get fresh token
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return &providers.TokenResponse{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		ExpiresAt:    newToken.Expiry,
		TokenType:    newToken.TokenType,
		Scopes:       p.config.Scopes,
	}, nil
}

// RevokeToken revokes a token at Google's revocation endpoint
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	revokeURL := "https://oauth2.googleapis.com/revoke"
	data := url.Values{}
	data.Set("token", token)

	resp, err := p.httpClient.PostForm(revokeURL, data)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	return nil
}

