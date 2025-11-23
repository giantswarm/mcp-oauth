package providers

import (
	"context"
	"time"
)

// Provider defines the interface for OAuth identity providers.
// This abstraction allows supporting Google, GitHub, Microsoft, and generic OIDC providers.
type Provider interface {
	// Name returns the provider name (e.g., "google", "github", "microsoft")
	Name() string

	// AuthorizationURL generates the URL to redirect users for authentication
	AuthorizationURL(state string, opts *AuthOptions) string

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code string, opts *ExchangeOptions) (*TokenResponse, error)

	// ValidateToken validates an access token and returns user information
	ValidateToken(ctx context.Context, accessToken string) (*UserInfo, error)

	// RefreshToken refreshes an expired token using a refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)

	// RevokeToken revokes a token at the provider
	RevokeToken(ctx context.Context, token string) error
}

// AuthOptions contains options for generating an authorization URL
type AuthOptions struct {
	// Scopes is the list of requested OAuth scopes
	Scopes []string

	// RedirectURI is where the provider should redirect after authentication
	RedirectURI string

	// CodeChallenge is the PKCE code challenge
	CodeChallenge string

	// CodeChallengeMethod is the PKCE method (S256)
	CodeChallengeMethod string

	// Nonce is an optional OIDC nonce for replay protection
	Nonce string
}

// ExchangeOptions contains options for exchanging an authorization code
type ExchangeOptions struct {
	// RedirectURI must match the one used in the authorization request
	RedirectURI string

	// CodeVerifier is the PKCE code verifier
	CodeVerifier string
}

// TokenResponse represents tokens returned by a provider
type TokenResponse struct {
	// AccessToken is the access token
	AccessToken string

	// RefreshToken is the refresh token (may be empty)
	RefreshToken string

	// ExpiresAt is when the access token expires
	ExpiresAt time.Time

	// Scopes are the scopes granted (may differ from requested)
	Scopes []string

	// TokenType is the token type (usually "Bearer")
	TokenType string
}

// UserInfo represents user information from a provider
type UserInfo struct {
	// ID is the unique user identifier from the provider
	ID string

	// Email is the user's email address
	Email string

	// EmailVerified indicates if the email is verified
	EmailVerified bool

	// Name is the user's full name
	Name string

	// GivenName is the user's first name
	GivenName string

	// FamilyName is the user's last name
	FamilyName string

	// Picture is the URL of the user's profile picture
	Picture string

	// Locale is the user's preferred locale
	Locale string
}

