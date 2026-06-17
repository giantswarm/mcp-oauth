// Package providers defines the interface for OAuth identity providers and implements
// provider-specific logic for Google, GitHub, Microsoft, and other OAuth/OIDC providers.
package providers

import (
	"context"

	"golang.org/x/oauth2"
)

// AuthorizationURLOptions contains optional OIDC parameters for the authorization request.
// These parameters enable advanced authentication flows like silent re-authentication
// and user hints per OpenID Connect Core 1.0 Section 3.1.2.1.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthorizationURLOptions struct {
	// Prompt controls the authentication UX behavior.
	// Common values:
	//   - "none": Silent authentication - no UI displayed. Returns error if login/consent required.
	//   - "login": Force re-authentication even if session exists.
	//   - "consent": Force consent even if previously granted.
	//   - "select_account": Force account selection even if only one account.
	// Multiple values can be space-separated: "login consent"
	Prompt string

	// LoginHint pre-fills the email/username field at the IdP.
	// Useful for re-authentication when the user's identity is already known.
	// Example: "user@example.com"
	LoginHint string

	// MaxAge specifies the maximum authentication age in seconds.
	// If the user's session is older than this, re-authentication is required.
	// A value of 0 is equivalent to prompt=login.
	MaxAge *int

	// ACRValues requests specific authentication context class references.
	// Space-separated string of acr_values.
	// Example: "urn:mace:incommon:iap:silver"
	ACRValues string

	// IDTokenHint is a previously issued ID token passed as a hint about the user's session.
	// Used with prompt=none to identify the user for silent re-authentication.
	IDTokenHint string

	// Nonce is forwarded to the IdP and must be echoed back in the resulting
	// id_token's `nonce` claim.
	Nonce string

	// Extra allows setting additional custom parameters not covered above.
	// These are added as query parameters to the authorization URL.
	Extra map[string]string
}

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
	// opts contains optional OIDC parameters like prompt, login_hint, max_age (nil for defaults)
	//
	// OAuth 2.1 Security: PKCE is recommended for ALL client types (public and confidential)
	// to protect against Authorization Code Injection attacks. Providers should support PKCE
	// even when using client_secret authentication for defense-in-depth.
	AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string, opts *AuthorizationURLOptions) string

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

	// TokenSourceJWT indicates the user was authenticated via a self-issued
	// JWT access token (RFC 9068). The Bearer token IS a JWT signed by this
	// server's own access-token signing key, with claims (sub, email,
	// groups, etc.) carried in the bearer itself rather than looked up
	// from a token store.
	//
	// Unlike TokenSourceSSO, the JWT was minted by this server, not by an
	// upstream IdP — its signature verifies against this server's published
	// JWKS. Unlike TokenSourceOAuth, there is no entry in the TokenStore
	// keyed by the bearer (the bearer is not a database key).
	//
	// Downstream consumers must NOT pass a TokenSourceJWT bearer to a
	// resource server that expects an upstream-IdP-signed id_token (e.g.
	// the Kubernetes API authenticated against the upstream OIDC issuer).
	// For those flows, fetch the upstream id_token by another path (e.g.
	// the configured TokenRefreshHandler cache).
	TokenSourceJWT TokenSource = "jwt"

	// TokenSourceTrustedIssuer indicates the user was authenticated via a
	// Bearer JWT validated against a WithTrustedIssuers entry. The token
	// was issued by an external IdP (e.g. a Kubernetes cluster's SA issuer)
	// whose JWKS is configured explicitly — it was not issued by this server
	// and is not a Dex-forwarded ID token.
	//
	// Downstream servers should use this to select impersonation rather than
	// bearer passthrough: the token's audience is the muster/broker STS, not
	// the downstream resource server, so direct passthrough would be rejected.
	// Use UserInfo.Issuer to identify the originating issuer.
	TokenSourceTrustedIssuer TokenSource = "trusted-issuer"
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
	//
	// SECURITY: This field is set server-side during token validation and
	// should NOT be trusted if received from external sources (e.g., if
	// UserInfo is deserialized from untrusted input). Always use the server's
	// ValidateToken() method to obtain a trusted UserInfo with correct TokenSource.
	TokenSource TokenSource

	// Issuer is the token issuer URL, populated only when TokenSource is
	// TokenSourceTrustedIssuer. It identifies the external IdP that signed
	// the Bearer token (e.g. the cluster's SA OIDC issuer URL). Empty for
	// Dex-forwarded (TokenSourceSSO) and OAuth-issued (TokenSourceOAuth)
	// tokens; those are issued by this server's own IdP.
	//
	// Downstream servers can use this alongside IsExternalIssuer() to route
	// to an impersonation path rather than bearer passthrough.
	Issuer string

	// ActorIssuer is the iss field from the RFC 8693 §4.4 act claim. Non-empty
	// only when the token was minted via a delegated token exchange with a
	// validated actor_token. Use IsDelegated() as a presence check.
	ActorIssuer string

	// ActorSubject is the sub field from the RFC 8693 §4.4 act claim. Non-empty
	// only when the token was minted via a delegated token exchange with a
	// validated actor_token. Use IsDelegated() as a presence check.
	ActorSubject string
}

// IsSSO returns true if this user was authenticated via SSO token forwarding.
// When true, the Bearer token IS the ID token and there is no entry in the
// token store (the server didn't issue the token).
//
// Returns false for nil receivers, OAuth tokens, empty TokenSource, and
// unknown/invalid TokenSource values.
//
// Downstream servers should use the Bearer token directly for downstream
// authentication when this returns true, rather than looking up a stored token.
func (u *UserInfo) IsSSO() bool {
	return u != nil && u.TokenSource == TokenSourceSSO
}

// IsOAuth returns true if this user was authenticated via normal OAuth flow.
// When true, the server issued the token and the provider's ID token is
// stored in the token store.
//
// Returns true for nil receivers (safe default) and empty TokenSource
// (backward compatibility with existing code). Returns false for SSO tokens
// and unknown/invalid TokenSource values.
//
// Downstream servers should look up the stored ID token from the token store
// when this returns true.
func (u *UserInfo) IsOAuth() bool {
	return u == nil || u.TokenSource == TokenSourceOAuth || u.TokenSource == ""
}

// IsJWT returns true if this user was authenticated via a self-issued JWT
// access token (RFC 9068). When true, the Bearer is a JWT signed by this
// server's own access-token signing key — not the upstream IdP's — and
// there is no entry in the TokenStore keyed by the bearer.
//
// Returns false for nil receivers, OAuth tokens, SSO tokens, empty
// TokenSource, and unknown/invalid TokenSource values.
//
// Downstream consumers MUST NOT pass a TokenSourceJWT bearer to resource
// servers expecting an upstream-IdP-signed id_token (e.g. Kubernetes
// authenticated against the upstream OIDC issuer). The JWT is signed by
// this OAuth server, not the upstream.
func (u *UserInfo) IsJWT() bool {
	return u != nil && u.TokenSource == TokenSourceJWT
}

// IsExternalIssuer returns true if this user was authenticated via a Bearer
// JWT validated against a WithTrustedIssuers entry — i.e. the token was
// issued by an external IdP, not by this server's own Dex/OAuth flow.
//
// Returns false for nil receivers, OAuth tokens, SSO tokens, JWT tokens,
// empty TokenSource, and unknown/invalid TokenSource values.
//
// Downstream servers that receive an external-issuer token MUST NOT pass
// it directly as a Bearer to a resource server (e.g. kube-apiserver) whose
// audience differs from the token's aud claim. Use an impersonation or
// token-exchange path instead. Check UserInfo.Issuer to identify the
// originating cluster/IdP.
func (u *UserInfo) IsExternalIssuer() bool {
	return u != nil && u.TokenSource == TokenSourceTrustedIssuer
}

// IsDelegated returns true when the token was produced by a delegated token
// exchange (RFC 8693 §4.4): it carries an act claim and was validated on the
// trusted-issuer path (TokenSourceTrustedIssuer). When true, ActorSubject and
// ActorIssuer identify the acting party; ID identifies the human subject on
// whose behalf the token was obtained.
//
// Returns false for nil receivers, tokens without an act claim, and tokens
// that were not validated as trusted-issuer tokens (e.g. plain SSO tokens).
func (u *UserInfo) IsDelegated() bool {
	return u != nil && u.ActorSubject != "" && u.TokenSource == TokenSourceTrustedIssuer
}
