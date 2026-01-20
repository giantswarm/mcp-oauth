// Package providers defines the interface for OAuth identity providers and implements
// provider-specific logic for Google, GitHub, Microsoft, and other OAuth/OIDC providers.
package providers

import (
	"context"

	"golang.org/x/oauth2"
)

// Provider defines the interface for OAuth identity providers.
// This abstraction allows supporting Google, GitHub, Microsoft, and generic OIDC providers.
// Now uses golang.org/x/oauth2.Token directly instead of custom types.
type Provider interface {
	// Name returns the provider name (e.g., "google", "github", "microsoft")
	Name() string

	// DefaultScopes returns the provider's default scopes used when the client doesn't
	// request specific scopes. These are the scopes configured when the provider was created.
	DefaultScopes() []string

	// AuthorizationURL generates the URL to redirect users for authentication
	// codeChallenge and codeChallengeMethod are for PKCE (pass empty strings to disable)
	// scopes is the list of scopes to request (if empty, provider's default scopes are used)
	//
	// OAuth 2.1 Security: PKCE is recommended for ALL client types (public and confidential)
	// to protect against Authorization Code Injection attacks. Providers should support PKCE
	// even when using client_secret authentication for defense-in-depth.
	AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string) string

	// ExchangeCode exchanges an authorization code for tokens
	// codeVerifier is for PKCE verification (pass empty string if not using PKCE)
	// Returns standard oauth2.Token
	//
	// OAuth 2.1 Security: PKCE verification provides cryptographic binding between the
	// authorization request and token exchange, preventing code injection even for
	// confidential clients with client_secret.
	ExchangeCode(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error)

	// ValidateToken validates an access token and returns user information
	ValidateToken(ctx context.Context, accessToken string) (*UserInfo, error)

	// RefreshToken refreshes an expired token using a refresh token
	// Returns standard oauth2.Token
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)

	// RevokeToken revokes a token at the provider
	RevokeToken(ctx context.Context, token string) error

	// HealthCheck verifies that the provider is reachable and functioning correctly.
	// This is useful for readiness/liveness probes and startup validation.
	// Returns nil if the provider is healthy, or an error describing the issue.
	//
	// SECURITY WARNING: Do not expose error messages from this method to untrusted clients.
	// Error details may contain information about provider state (HTTP status codes, network errors)
	// that could be used for reconnaissance. Use this for internal monitoring only.
	HealthCheck(ctx context.Context) error
}

// JWKSProvider is an optional interface for providers that support JWKS-based
// JWT validation. This enables SSO token forwarding where ID tokens from
// upstream servers are validated via JWKS signature verification.
//
// Providers that don't support JWKS validation can omit this interface.
// The server will fall back to userinfo endpoint validation in that case.
type JWKSProvider interface {
	Provider

	// JWKSURI returns the JWKS (JSON Web Key Set) URI for this provider.
	// This is used to fetch public keys for JWT signature verification.
	// Returns empty string if JWKS is not available.
	JWKSURI(ctx context.Context) (string, error)

	// IssuerURL returns the issuer URL for this provider.
	// This is used for JWT issuer validation.
	IssuerURL() string
}

// TokenSource indicates how the user was authenticated.
type TokenSource string

const (
	// TokenSourceOAuth indicates the user was authenticated via normal OAuth flow.
	// The server issued the token and the provider's ID token is stored in the token store.
	TokenSourceOAuth TokenSource = "oauth"

	// TokenSourceSSO indicates the user was authenticated via SSO token forwarding.
	// The Bearer token IS the ID token forwarded from a trusted upstream service.
	// There is no entry in the token store because the server didn't issue the token.
	TokenSourceSSO TokenSource = "sso"
)

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

	// Groups contains group memberships from the identity provider.
	// This is populated from the 'groups' claim in OIDC userinfo responses.
	// Providers that don't support groups will leave this empty.
	Groups []string

	// TokenSource indicates how this user was authenticated.
	// This is set to TokenSourceOAuth for normal OAuth flow tokens
	// (where the ID token is stored in the token store) or TokenSourceSSO
	// for SSO-forwarded tokens (where the Bearer token IS the ID token).
	//
	// Downstream servers can use this to determine whether to look up
	// a stored ID token or use the Bearer token directly for downstream
	// authentication (e.g., Kubernetes API authentication).
	TokenSource TokenSource
}

// IsSSO returns true if this user was authenticated via SSO token forwarding.
// When true, the Bearer token IS the ID token and there is no entry in the
// token store (the server didn't issue the token).
//
// Downstream servers should use the Bearer token directly for downstream
// authentication when this returns true, rather than looking up a stored token.
func (u *UserInfo) IsSSO() bool {
	return u.TokenSource == TokenSourceSSO
}

// IsOAuth returns true if this user was authenticated via normal OAuth flow.
// When true, the server issued the token and the provider's ID token is
// stored in the token store.
//
// Downstream servers should look up the stored ID token from the token store
// when this returns true.
func (u *UserInfo) IsOAuth() bool {
	return u.TokenSource == TokenSourceOAuth || u.TokenSource == ""
}
