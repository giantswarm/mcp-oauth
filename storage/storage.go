// Package storage defines interfaces for persisting OAuth tokens, clients, and authorization flows.
// It supports various backend implementations including in-memory, Redis, and databases.
package storage

import (
	"context"
	"errors"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
)

// Client type constants used for ClientType field comparisons.
// Use these instead of bare string literals to avoid silent drift across backends.
const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

// DummyBcryptHash is a pre-computed bcrypt hash used for timing attack mitigation.
// This hash (bcrypt hash of "test") ensures we always perform a bcrypt comparison
// even if a client doesn't exist, preventing timing-based client enumeration attacks.
// Note: Using a constant dummy hash is intentional - the timing attack mitigation
// comes from always performing the bcrypt comparison, not from the hash value.
const DummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// Backend identifiers for the in-tree storage implementations. These are the
// canonical strings emitted as the `storage.backend` OTEL span attribute and
// are exported so consumers can dispatch on a configured backend name without
// re-declaring the same literals (e.g. cmd-line flag parsing, factory funcs).
const (
	BackendMemory = "memory"
	BackendValkey = "valkey"
)

// Common error message strings used across storage implementations.
// These ensure consistent error messages and reduce code duplication.
const (
	// ErrMsgProviderStateRequired is the error message when provider state is missing.
	ErrMsgProviderStateRequired = "provider state is required"

	// ErrMsgInvalidAuthorizationState is the error message for invalid authorization state.
	ErrMsgInvalidAuthorizationState = "invalid authorization state"

	// ErrMsgRefreshTokenNotFoundOrUsed is the error message for refresh token not found or already used.
	ErrMsgRefreshTokenNotFoundOrUsed = "refresh token not found or already used"
)

// Storage error types for distinguishing between different failure modes.
// These allow callers to differentiate between "not found" errors (which may indicate
// reuse in refresh token scenarios) and transient errors (which should not trigger
// security responses).
var (
	// ErrTokenNotFound indicates the token does not exist in storage.
	// In refresh token scenarios, this may indicate the token was already rotated,
	// potentially signaling a reuse attempt if family metadata exists.
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenExpired indicates the token exists but has expired.
	// Expired tokens should be rejected without triggering reuse detection.
	ErrTokenExpired = errors.New("token expired")

	// ErrClientNotFound indicates the client does not exist in storage.
	ErrClientNotFound = errors.New("client not found")

	// ErrAuthorizationCodeNotFound indicates the authorization code does not exist.
	ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

	// ErrAuthorizationCodeUsed indicates the authorization code has already been used.
	// This is a security event that should trigger token revocation per OAuth 2.1.
	ErrAuthorizationCodeUsed = errors.New("authorization code already used")

	// ErrAuthorizationStateNotFound indicates the authorization state does not exist.
	ErrAuthorizationStateNotFound = errors.New("authorization state not found")

	// ErrUserInfoNotFound indicates the user info does not exist in storage.
	ErrUserInfoNotFound = errors.New("user info not found")

	// ErrRefreshTokenFamilyNotFound indicates the refresh token family does not exist.
	// This is normal for tokens created before family tracking was enabled.
	ErrRefreshTokenFamilyNotFound = errors.New("refresh token family not found")

	// ErrRefreshTokenFamilyRevoked indicates the family exists but every
	// member is revoked. Distinct from ErrRefreshTokenFamilyNotFound so
	// callers can produce a better error message — "session was revoked"
	// vs "no such session". The two states converge to NotFound after the
	// revoked-family retention period elapses and the entries are wiped.
	ErrRefreshTokenFamilyRevoked = errors.New("refresh token family is revoked")

	// ErrClientIPLimitExceeded is returned by CheckIPLimit when the IP has reached
	// the maximum number of registered clients.
	ErrClientIPLimitExceeded = errors.New("client registration limit exceeded")
)

// IsNotFoundError checks if an error indicates a "not found" condition.
// This is useful for distinguishing between missing resources (which may indicate
// security issues like token reuse) and transient errors (which should not).
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrTokenNotFound) ||
		errors.Is(err, ErrClientNotFound) ||
		errors.Is(err, ErrAuthorizationCodeNotFound) ||
		errors.Is(err, ErrAuthorizationStateNotFound) ||
		errors.Is(err, ErrUserInfoNotFound) ||
		errors.Is(err, ErrRefreshTokenFamilyNotFound)
}

// IsExpiredError checks if an error indicates an expired token or code.
func IsExpiredError(err error) bool {
	return errors.Is(err, ErrTokenExpired)
}

// IsCodeReuseError checks if an error indicates authorization code reuse.
func IsCodeReuseError(err error) bool {
	return errors.Is(err, ErrAuthorizationCodeUsed)
}

// UserInfo holds identity claims for a user as stored by this server.
// Providers map their own types to this struct before calling SaveUserInfo.
type UserInfo struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	Locale        string
	Groups        []string
}

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
	SaveUserInfo(ctx context.Context, userID string, info *UserInfo) error

	// GetUserInfo retrieves user information
	GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)

	// SaveRefreshToken saves a refresh token mapping to user ID with expiry
	SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error

	// GetRefreshTokenInfo retrieves the user ID for a refresh token
	GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error)

	// DeleteRefreshToken removes a refresh token
	DeleteRefreshToken(ctx context.Context, refreshToken string) error

	// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
	// This prevents race conditions in refresh token rotation and reuse detection.
	// Returns the userID, clientID, and provider token if successful, or an error if:
	// - Token not found (may indicate already used/rotated)
	// - Token expired
	// SECURITY: This operation MUST be atomic to prevent concurrent token refresh attacks.
	// SECURITY: Returns clientID for client binding validation per OAuth 2.1 Section 6.
	AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (userID string, clientID string, providerToken *oauth2.Token, err error)
}

// TokenMetadataStore stores write-side token metadata used for audit
// (which user / client a token was issued to), audience binding
// (RFC 8707), scope validation (MCP 2025-11-25), and refresh-token-family
// bookkeeping (OAuth 2.1 reuse detection). The whole metadata payload
// travels in a single TokenMetadata struct so adding a new field is a
// single-place change rather than a new interface.
//
// Revocation does not flow through this interface — opaque tokens are
// revoked via TokenStore.DeleteToken and self-issued JWTs via
// RevokedTokenStore.RevokeJTI. TokenMetadata is the read-side payload
// for scope validation and audit.
type TokenMetadataStore interface {
	// SaveTokenMetadata persists metadata for the given tokenID.
	// Callers are responsible for setting IssuedAt and ExpiresAt;
	// backends persist them without modification.
	SaveTokenMetadata(ctx context.Context, tokenID string, metadata TokenMetadata) error
}

// TokenMetadataGetter provides read access to token metadata.
// This is used for scope validation and token introspection.
type TokenMetadataGetter interface {
	GetTokenMetadata(tokenID string) (*TokenMetadata, error)
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

// RefreshTokenFamilyByIDStore is an optional extension to
// RefreshTokenFamilyStore that exposes a lookup by family ID. JWT-mode
// access tokens carry family_id in their claims, but they do NOT carry
// the refresh token, so the existing GetRefreshTokenFamily(refreshToken)
// API cannot be reached from a JWT validation hot path. This lookup
// closes that gap.
//
// Implementations must be safe to call concurrently with the rest of the
// storage interface. Memory and Valkey both implement it.
//
// All methods accept context.Context for tracing and cancellation.
type RefreshTokenFamilyByIDStore interface {
	// GetRefreshTokenFamilyByID returns the family metadata for the given
	// family ID. Returns ErrRefreshTokenFamilyNotFound when the family is
	// unknown (also for revoked families that have aged out of retention).
	GetRefreshTokenFamilyByID(ctx context.Context, familyID string) (*RefreshTokenFamilyMetadata, error)
}

// ActiveRefreshTokenByFamilyStore is an optional extension that exposes
// the most recent (highest-generation) non-revoked refresh token for a
// family, looked up by family ID. Required by Server.RefreshSession,
// which otherwise has no way to refresh a session given only the family
// ID — the public refresh-token-grant path needs the refresh token
// itself, which the caller does not have on the in-process refresh path.
//
// The method returns both the refresh token and the owning client ID in
// one call so RefreshSession does not need a second lookup to get the
// client ID for OAuth 2.1 refresh-token client binding validation.
//
// Memory and Valkey both implement this interface. Backends that don't
// will cause Server.RefreshSession to return an error at call time.
type ActiveRefreshTokenByFamilyStore interface {
	// GetActiveRefreshTokenByFamily returns the most recent (highest
	// generation) non-revoked refresh token for the family along with
	// the owning client ID.
	//
	// Returns ErrRefreshTokenFamilyNotFound when no entry for the family
	// exists in storage at all (never created, or aged out of revoked-
	// family retention). Returns ErrRefreshTokenFamilyRevoked when the
	// family exists but every member is revoked — a distinct state so
	// callers can surface "session was revoked" vs "no such session".
	GetActiveRefreshTokenByFamily(ctx context.Context, familyID string) (refreshToken, clientID string, err error)
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

// RevokedTokenStore tracks revoked self-issued JWT access tokens by jti.
//
// Self-issued JWTs (server.AccessTokenFormatJWT mode) are stateless: the
// bearer carries every claim a resource server needs to validate it
// locally. RFC 7009 token revocation must still take effect, however, so
// the issuing server keeps a denylist of revoked jti values with their
// original exp timestamps. Validation consults the denylist and rejects
// matches; entries auto-expire at exp so the list stays bounded.
//
// The interface is optional: implementations are expected to mirror the
// shape of TokenStore (memory + Valkey). Servers operating in opaque mode
// do not require it — opaque revocation continues to use TokenStore
// deletion. Servers operating in JWT mode without a RevokedTokenStore log
// a warning at startup and accept revocation calls but do not enforce
// them on subsequent validations.
//
// All methods accept context.Context for tracing and cancellation.
type RevokedTokenStore interface {
	// RevokeJTI marks the given JTI as revoked until the supplied
	// expiration. Implementations MUST auto-expire the entry at expiresAt
	// so the denylist stays bounded; an entry persisting past exp would
	// only consume storage with no security value.
	RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error

	// IsJTIRevoked returns true if the JTI was previously revoked and the
	// entry has not yet expired. Implementations MUST be safe to call from
	// the validation hot path (no per-call allocation outside the lookup).
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
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

	// DeleteClient removes a registered client by ID. Returns ErrClientNotFound
	// when no client with that ID exists.
	DeleteClient(ctx context.Context, clientID string) error

	// CheckIPLimit checks if an IP has reached the client registration limit
	CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) error
}

// ClientIPTracker is an optional capability implemented by ClientStore
// implementations that can record the most recent client IP per client_id.
type ClientIPTracker interface {
	TrackClientIP(ctx context.Context, clientID, ip string) error
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

// Combined is the convenience union of the three storage interfaces that a
// single backend typically implements together: TokenStore, ClientStore, and
// FlowStore. Both the in-tree memory and valkey backends satisfy it.
//
// It exists so consumers no longer have to pass the same *Store three times to
// [server.NewWithCombined] (the old [server.New] signature took TokenStore,
// ClientStore, and FlowStore as separate arguments for backends that split
// persistence across backing stores). Consumers that still split per-interface
// can keep using the split constructor.
//
// The optional interfaces (RefreshTokenFamilyStore, TokenRevocationStore, the
// TokenMetadata* interfaces) are intentionally NOT embedded here — Combined is
// the minimum every server needs, and backends opt into the extras by
// implementing them. The server uses runtime type assertions (via the Set*
// hooks and gated SessionCreationHandler wiring) to detect the optional ones.
type Combined interface {
	TokenStore
	ClientStore
	FlowStore
}

// Client represents a registered OAuth client
type Client struct {
	ClientID                    string
	ClientSecretHash            string // bcrypt hash
	ClientType                  string // ClientTypePublic or ClientTypeConfidential
	RedirectURIs                []string
	TokenEndpointAuthMethod     string
	GrantTypes                  []string
	ResponseTypes               []string
	ClientName                  string
	Scopes                      []string
	CreatedAt                   time.Time
	UpdatedAt                   time.Time
	RegistrationAccessTokenHash string // bcrypt hash of the per-client registration access token (RFC 7592)
}

// IsPublic reports whether the client is a public client (no secret).
func (c *Client) IsPublic() bool { return c.ClientType == ClientTypePublic }

// IsConfidential reports whether the client is a confidential client (has secret).
func (c *Client) IsConfidential() bool { return c.ClientType == ClientTypeConfidential }

// AuthorizationState represents the state of an ongoing authorization flow
type AuthorizationState struct {
	// StateID is used for internal tracking (may be server-generated if client didn't provide state)
	StateID string
	// OriginalClientState is the state parameter the client provided (empty if client didn't provide one)
	// This is returned to the client in the callback redirect
	OriginalClientState string
	ClientID            string
	RedirectURI         string
	Scope               string
	// Resource is the target resource server identifier (RFC 8707)
	// This binds the authorization to a specific resource server
	Resource string
	// Client-to-Server PKCE challenge from MCP client
	CodeChallenge string
	// Client-to-Server PKCE method from MCP client
	CodeChallengeMethod string
	// State parameter sent to provider (different from StateID)
	ProviderState string
	// Server-to-Provider PKCE verifier (OAuth 2.1)
	ProviderCodeVerifier string
	// Nonce is the OIDC nonce forwarded to the upstream IdP. Empty for non-OIDC flows.
	Nonce     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// HasExpired reports whether the authorization state has expired (with default clock-skew grace).
func (s *AuthorizationState) HasExpired() bool { return security.IsTokenExpired(s.ExpiresAt) }

// AuthorizationCode represents an issued authorization code
type AuthorizationCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Scope       string
	// Resource is the target resource server identifier (RFC 8707)
	// This is carried from the authorization request to bind the token to a specific audience
	Resource string
	// Audience is the intended token audience (resource server identifier)
	// This is used for token validation to prevent token theft across resource servers
	Audience            string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	ProviderToken       *oauth2.Token // Now uses oauth2.Token directly
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Used                bool
}

// HasExpired reports whether the authorization code has expired (with default clock-skew grace).
func (c *AuthorizationCode) HasExpired() bool { return security.IsTokenExpired(c.ExpiresAt) }

// TokenMetadata tracks ownership, audience (RFC 8707), and scope
// (MCP 2025-11-25) information for an issued token. The same struct
// is used for input to TokenMetadataStore.SaveTokenMetadata and for
// output from TokenMetadataGetter.GetTokenMetadata.
//
// Both IssuedAt and ExpiresAt are issuer-set: the caller is responsible
// for populating them from the issuance context before calling
// SaveTokenMetadata. Backends persist the values as-is.
type TokenMetadata struct {
	UserID      string         // User who owns this token
	ClientID    string         // Client who owns this token
	IssuedAt    time.Time      // Issuer-set: the instant the token was issued
	ExpiresAt   time.Time      // Issuer-set: the instant the token expires; zero means unknown
	TokenType   string         // "access", "refresh", or "id"
	Audience    string         // RFC 8707: Intended resource server identifier (for audience validation)
	Scopes      []string       // MCP 2025-11-25: Scopes granted to this token (for scope validation)
	FamilyID    string         // Refresh token family ID for session tracking
	JKT         string         // JWK thumbprint for DPoP-bound tokens (RFC 9449 §6.1); empty = bearer
	ExtraClaims map[string]any // Application-defined claims forwarded verbatim in introspection responses.
}
