package storage

import (
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
)

// TokenStore defines the interface for storing and retrieving tokens.
// This allows using in-memory, Redis, database, or other storage backends.
type TokenStore interface {
	// SaveToken saves a token for a user
	SaveToken(userID string, token *providers.TokenResponse) error

	// GetToken retrieves a token for a user
	GetToken(userID string) (*providers.TokenResponse, error)

	// DeleteToken removes a token for a user
	DeleteToken(userID string) error

	// SaveUserInfo saves user information
	SaveUserInfo(userID string, info *providers.UserInfo) error

	// GetUserInfo retrieves user information
	GetUserInfo(userID string) (*providers.UserInfo, error)
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

	// GetAuthorizationState retrieves an authorization state
	GetAuthorizationState(stateID string) (*AuthorizationState, error)

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
	StateID                 string
	ClientID                string
	RedirectURI             string
	Scope                   string
	CodeChallenge           string
	CodeChallengeMethod     string
	Nonce                   string
	ProviderState           string // State parameter sent to the provider
	CreatedAt               time.Time
	ExpiresAt               time.Time
}

// AuthorizationCode represents an issued authorization code
type AuthorizationCode struct {
	Code                    string
	ClientID                string
	RedirectURI             string
	Scope                   string
	CodeChallenge           string
	CodeChallengeMethod     string
	UserID                  string
	ProviderToken           *providers.TokenResponse
	CreatedAt               time.Time
	ExpiresAt               time.Time
	Used                    bool
}

