// Package storage defines interfaces for persisting OAuth tokens, clients, and authorization flows.
// It supports various backend implementations including in-memory, Redis, and databases.
package storage

import (
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

// TokenStore defines the interface for storing and retrieving tokens.
// This allows using in-memory, Redis, database, or other storage backends.
// Now uses golang.org/x/oauth2.Token directly.
type TokenStore interface {
	// SaveToken saves a token for a user
	SaveToken(userID string, token *oauth2.Token) error

	// GetToken retrieves a token for a user
	GetToken(userID string) (*oauth2.Token, error)

	// DeleteToken removes a token for a user
	DeleteToken(userID string) error

	// SaveUserInfo saves user information
	SaveUserInfo(userID string, info *providers.UserInfo) error

	// GetUserInfo retrieves user information
	GetUserInfo(userID string) (*providers.UserInfo, error)

	// SaveRefreshToken saves a refresh token mapping to user ID with expiry
	SaveRefreshToken(refreshToken, userID string, expiresAt time.Time) error

	// GetRefreshTokenInfo retrieves the user ID for a refresh token
	GetRefreshTokenInfo(refreshToken string) (string, error)

	// DeleteRefreshToken removes a refresh token
	DeleteRefreshToken(refreshToken string) error
}

// RefreshTokenFamilyStore tracks a family of refresh tokens for reuse detection (OAuth 2.1).
// This is optional - only implemented by stores that support reuse detection.
type RefreshTokenFamilyStore interface {
	// SaveRefreshTokenWithFamily saves a refresh token with family tracking
	SaveRefreshTokenWithFamily(refreshToken, userID, clientID, familyID string, generation int, expiresAt time.Time) error

	// GetRefreshTokenFamily retrieves family metadata for a refresh token
	GetRefreshTokenFamily(refreshToken string) (*RefreshTokenFamilyMetadata, error)

	// RevokeRefreshTokenFamily revokes all tokens in a family
	RevokeRefreshTokenFamily(familyID string) error
}

// RefreshTokenFamilyMetadata contains metadata about a token family
type RefreshTokenFamilyMetadata struct {
	FamilyID   string
	UserID     string
	ClientID   string
	Generation int
	IssuedAt   time.Time
	Revoked    bool
}

// ClientStore defines the interface for managing OAuth client registrations.
type ClientStore interface {
	// SaveClient saves a registered client
	SaveClient(client *Client) error

	// GetClient retrieves a client by ID
	GetClient(clientID string) (*Client, error)

	// ValidateClientSecret validates a client's secret
	ValidateClientSecret(clientID, clientSecret string) error

	// ListClients lists all registered clients (for admin purposes)
	ListClients() ([]*Client, error)

	// CheckIPLimit checks if an IP has reached the client registration limit
	CheckIPLimit(ip string, maxClientsPerIP int) error
}

// FlowStore defines the interface for managing OAuth authorization flows.
type FlowStore interface {
	// SaveAuthorizationState saves the state of an ongoing authorization flow
	SaveAuthorizationState(state *AuthorizationState) error

	// GetAuthorizationState retrieves an authorization state by client state
	GetAuthorizationState(stateID string) (*AuthorizationState, error)

	// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
	// This is used during provider callback validation
	GetAuthorizationStateByProviderState(providerState string) (*AuthorizationState, error)

	// DeleteAuthorizationState removes an authorization state
	DeleteAuthorizationState(stateID string) error

	// SaveAuthorizationCode saves an issued authorization code
	SaveAuthorizationCode(code *AuthorizationCode) error

	// GetAuthorizationCode retrieves an authorization code
	GetAuthorizationCode(code string) (*AuthorizationCode, error)

	// DeleteAuthorizationCode removes an authorization code
	DeleteAuthorizationCode(code string) error
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
	StateID             string // Client's state parameter (for CSRF protection)
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ProviderState       string // State parameter sent to the provider (different from StateID)
	CreatedAt           time.Time
	ExpiresAt           time.Time
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
