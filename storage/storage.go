// Package storage defines interfaces for persisting OAuth tokens, clients, and authorization flows.
// It supports various backend implementations including in-memory, Redis, and databases.
package storage

import (
	"context"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

// TokenStore defines the interface for storing and retrieving tokens.
// This allows using in-memory, Redis, database, or other storage backends.
// Now uses golang.org/x/oauth2.Token directly.
// All methods accept context.Context for tracing and cancellation.
type TokenStore interface {
	// SaveToken saves a token for a user
	SaveToken(ctx context.Context, userID string, token *oauth2.Token) error

	// GetToken retrieves a token for a user
	GetToken(ctx context.Context, userID string) (*oauth2.Token, error)

	// DeleteToken removes a token for a user
	DeleteToken(ctx context.Context, userID string) error

	// SaveUserInfo saves user information
	SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error

	// GetUserInfo retrieves user information
	GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error)

	// SaveRefreshToken saves a refresh token mapping to user ID with expiry
	SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error

	// GetRefreshTokenInfo retrieves the user ID for a refresh token
	GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error)

	// DeleteRefreshToken removes a refresh token
	DeleteRefreshToken(ctx context.Context, refreshToken string) error

	// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
	// This prevents race conditions in refresh token rotation and reuse detection.
	// Returns the userID and provider token if successful, or an error if:
	// - Token not found (may indicate already used/rotated)
	// - Token expired
	// SECURITY: This operation MUST be atomic to prevent concurrent token refresh attacks.
	AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (userID string, providerToken *oauth2.Token, err error)
}

// RefreshTokenFamilyStore tracks a family of refresh tokens for reuse detection (OAuth 2.1).
// This is optional - only implemented by stores that support reuse detection.
// All methods accept context.Context for tracing and cancellation.
type RefreshTokenFamilyStore interface {
	// SaveRefreshTokenWithFamily saves a refresh token with family tracking
	SaveRefreshTokenWithFamily(ctx context.Context, refreshToken, userID, clientID, familyID string, generation int, expiresAt time.Time) error

	// GetRefreshTokenFamily retrieves family metadata for a refresh token
	GetRefreshTokenFamily(ctx context.Context, refreshToken string) (*RefreshTokenFamilyMetadata, error)

	// RevokeRefreshTokenFamily revokes all tokens in a family
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error
}

// RefreshTokenFamilyMetadata contains metadata about a token family
type RefreshTokenFamilyMetadata struct {
	FamilyID   string
	UserID     string
	ClientID   string
	Generation int
	IssuedAt   time.Time
	Revoked    bool
	RevokedAt  time.Time // When this family was revoked (for forensics and cleanup)
}

// TokenRevocationStore supports bulk token revocation operations (OAuth 2.1 security).
// This is optional - only implemented by stores that support token revocation.
// Used for critical security scenarios like authorization code reuse detection.
// All methods accept context.Context for tracing and cancellation.
type TokenRevocationStore interface {
	// RevokeAllTokensForUserClient revokes all tokens (access + refresh) for a specific user+client combination.
	// This is called when authorization code reuse is detected (OAuth 2.1 requirement).
	// Returns the number of tokens revoked and any error encountered.
	RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) (int, error)

	// GetTokensByUserClient retrieves all token IDs for a user+client combination (for testing/debugging).
	GetTokensByUserClient(ctx context.Context, userID, clientID string) ([]string, error)
}

// ClientStore defines the interface for managing OAuth client registrations.
// All methods accept context.Context for tracing and cancellation.
type ClientStore interface {
	// SaveClient saves a registered client
	SaveClient(ctx context.Context, client *Client) error

	// GetClient retrieves a client by ID
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// ValidateClientSecret validates a client's secret
	ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error

	// ListClients lists all registered clients (for admin purposes)
	ListClients(ctx context.Context) ([]*Client, error)

	// CheckIPLimit checks if an IP has reached the client registration limit
	CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) error
}

// FlowStore defines the interface for managing OAuth authorization flows.
//
// # Understanding StateID vs ProviderState
//
// OAuth authorization flows use TWO distinct state parameters for different purposes:
//
// 1. StateID (Client State):
//   - Generated by the client application
//   - Sent by the client in the /authorize request
//   - Used for CSRF protection on the client side
//   - Returned to the client in the redirect URI after successful authorization
//   - Use GetAuthorizationState(stateID) when validating client-initiated requests
//
// 2. ProviderState (Server State):
//   - Generated by THIS OAuth server
//   - Sent to the OAuth provider (Google, GitHub, etc.) during the redirect
//   - Used for CSRF protection on the server side
//   - Returned by the provider in their callback
//   - Use GetAuthorizationStateByProviderState(providerState) when validating provider callbacks
//
// Example Flow:
//  1. Client calls /authorize with state="client_csrf_token_123"
//  2. Server stores both: StateID="client_csrf_token_123", ProviderState="server_csrf_token_xyz"
//  3. Server redirects to Google with state="server_csrf_token_xyz"
//  4. Google redirects back with state="server_csrf_token_xyz"
//  5. Server validates using GetAuthorizationStateByProviderState("server_csrf_token_xyz")
//  6. Server redirects to client with state="client_csrf_token_123"
//  7. Client validates using their original state="client_csrf_token_123"
//
// This two-state system provides defense-in-depth against CSRF attacks at both layers.
// All methods accept context.Context for tracing and cancellation.
type FlowStore interface {
	// SaveAuthorizationState saves the state of an ongoing authorization flow
	SaveAuthorizationState(ctx context.Context, state *AuthorizationState) error

	// GetAuthorizationState retrieves an authorization state by client state (StateID).
	// Use this method when validating client-initiated requests where the client
	// provides their original state parameter for CSRF protection.
	GetAuthorizationState(ctx context.Context, stateID string) (*AuthorizationState, error)

	// GetAuthorizationStateByProviderState retrieves an authorization state by provider state.
	// Use this method during provider callback validation when the OAuth provider
	// (Google, GitHub, etc.) returns with the server-generated state parameter.
	GetAuthorizationStateByProviderState(ctx context.Context, providerState string) (*AuthorizationState, error)

	// DeleteAuthorizationState removes an authorization state
	DeleteAuthorizationState(ctx context.Context, stateID string) error

	// SaveAuthorizationCode saves an issued authorization code
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// GetAuthorizationCode retrieves an authorization code
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// AtomicCheckAndMarkAuthCodeUsed atomically checks if a code is unused and marks it as used.
	// This prevents race conditions in authorization code reuse detection.
	// Returns the auth code if successful, or an error if:
	// - Code not found
	// - Code expired
	// - Code already used (reuse detected)
	// SECURITY: This operation MUST be atomic to prevent concurrent code exchange attacks.
	AtomicCheckAndMarkAuthCodeUsed(ctx context.Context, code string) (*AuthorizationCode, error)

	// DeleteAuthorizationCode removes an authorization code
	DeleteAuthorizationCode(ctx context.Context, code string) error
}

// Client represents a registered OAuth client
type Client struct {
	ClientID                string
	ClientSecretHash        string // bcrypt hash
	ClientType              string // "public" or "confidential"
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	ClientName              string
	Scopes                  []string
	CreatedAt               time.Time
}

// AuthorizationState represents the state of an ongoing authorization flow
type AuthorizationState struct {
	StateID              string // Client's state parameter (for CSRF protection)
	ClientID             string
	RedirectURI          string
	Scope                string
	CodeChallenge        string // Client-to-Server PKCE challenge (from MCP client)
	CodeChallengeMethod  string // Client-to-Server PKCE method (from MCP client)
	ProviderState        string // State parameter sent to the provider (different from StateID)
	ProviderCodeVerifier string // Server-to-Provider PKCE verifier (OAuth 2.1 security enhancement)
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

// AuthorizationCode represents an issued authorization code
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	ProviderToken       *oauth2.Token // Now uses oauth2.Token directly
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Used                bool
}
