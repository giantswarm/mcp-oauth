package valkey

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	// DefaultKeyPrefix is the default prefix for all Valkey keys
	DefaultKeyPrefix = "mcp:"

	// DefaultRevokedFamilyRetentionDays is the default retention period for revoked token families
	DefaultRevokedFamilyRetentionDays = 90

	// tokenIDLogLength is the number of characters to include when logging token IDs
	tokenIDLogLength = 8

	// scanBatchSize is the number of keys to fetch per SCAN iteration
	scanBatchSize = 100

	// connectionVerifyTimeout is the timeout for initial connection verification
	connectionVerifyTimeout = 5 * time.Second

	// MaxTokenLength is the maximum allowed length for token strings (512 bytes)
	// This prevents DoS attacks via excessively large tokens
	MaxTokenLength = 512

	// MaxIDLength is the maximum allowed length for identifiers (userID, clientID, familyID)
	MaxIDLength = 256

	// MaxTokenDataSize is the maximum size of serialized token data (64KB)
	// This prevents memory exhaustion from large token payloads
	MaxTokenDataSize = 64 * 1024
)

// Validation error messages (generic to prevent information leakage)
var (
	errInvalidCredentials = fmt.Errorf("invalid client credentials")
	errRateLimitExceeded  = fmt.Errorf("rate limit exceeded")
	errInputTooLarge      = fmt.Errorf("input exceeds maximum allowed size")
)

// Config holds configuration for the Valkey storage backend.
type Config struct {
	// Address is the Valkey server address (required), e.g., "localhost:6379"
	Address string

	// Password is the optional password for Valkey authentication
	Password string

	// DB is the optional database number (default 0)
	DB int

	// KeyPrefix is the prefix for all keys (default "mcp:")
	KeyPrefix string

	// TLS is the optional TLS configuration for encrypted connections
	TLS *tls.Config

	// Logger is the optional structured logger (default: slog.Default())
	Logger *slog.Logger

	// RevokedFamilyRetentionDays is the retention period for revoked token family metadata
	// Used for security forensics and auditing. Default: 90 days
	RevokedFamilyRetentionDays int
}

// Store is a Valkey-backed implementation of all storage interfaces.
// It implements TokenStore, ClientStore, FlowStore, RefreshTokenFamilyStore, and TokenRevocationStore.
type Store struct {
	client                     valkeygo.Client
	prefix                     string
	logger                     *slog.Logger
	revokedFamilyRetentionDays int

	// encryptor provides optional token encryption at rest
	// Access must be synchronized via encryptorMu
	encryptor   *security.Encryptor
	encryptorMu sync.RWMutex
}

// Compile-time interface checks to ensure Store implements all storage interfaces
var (
	_ storage.TokenStore              = (*Store)(nil)
	_ storage.ClientStore             = (*Store)(nil)
	_ storage.FlowStore               = (*Store)(nil)
	_ storage.RefreshTokenFamilyStore = (*Store)(nil)
	_ storage.TokenRevocationStore    = (*Store)(nil)
)

// New creates a new Valkey-backed storage instance.
// Returns an error if the connection cannot be established.
func New(cfg Config) (*Store, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("valkey address is required")
	}

	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	retentionDays := cfg.RevokedFamilyRetentionDays
	if retentionDays <= 0 {
		retentionDays = DefaultRevokedFamilyRetentionDays
	}

	// Build client options
	opts := valkeygo.ClientOption{
		InitAddress: []string{cfg.Address},
		SelectDB:    cfg.DB,
	}

	if cfg.Password != "" {
		opts.Password = cfg.Password
	}

	if cfg.TLS != nil {
		opts.TLSConfig = cfg.TLS
	}

	client, err := valkeygo.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create valkey client: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), connectionVerifyTimeout)
	defer cancel()

	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to valkey: %w", err)
	}

	logger.Info("Connected to Valkey storage",
		"address", cfg.Address,
		"db", cfg.DB,
		"prefix", prefix)

	return &Store{
		client:                     client,
		prefix:                     prefix,
		logger:                     logger,
		revokedFamilyRetentionDays: retentionDays,
	}, nil
}

// Close closes the Valkey client connection.
func (s *Store) Close() {
	s.client.Close()
	s.logger.Info("Valkey storage connection closed")
}

// SetLogger sets a custom logger for the store.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// SetEncryptor sets the token encryptor for encryption at rest.
// When set, oauth2.Token access and refresh tokens will be encrypted
// before storing in Valkey and decrypted when retrieved.
func (s *Store) SetEncryptor(enc *security.Encryptor) {
	s.encryptorMu.Lock()
	defer s.encryptorMu.Unlock()
	s.encryptor = enc
	if enc != nil && enc.IsEnabled() {
		s.logger.Info("Token encryption at rest enabled for Valkey storage")
	}
}

// getEncryptor returns the current encryptor (thread-safe)
func (s *Store) getEncryptor() *security.Encryptor {
	s.encryptorMu.RLock()
	defer s.encryptorMu.RUnlock()
	return s.encryptor
}

// tokenTransformFuncs contains the functions used to transform token fields.
type tokenTransformFuncs struct {
	transformString func(string) (string, error)
	transformExtra  func(map[string]any, *security.Encryptor) (map[string]any, error)
	accessErrFmt    string
	refreshErrFmt   string
}

// transformTokenFields applies transformation functions to a token's sensitive fields.
// Returns a new token with transformed fields, leaving the original unchanged.
// IMPORTANT: Preserves the Extra field (id_token, scope) which is critical for OIDC flows.
func (s *Store) transformTokenFields(token *oauth2.Token, funcs tokenTransformFuncs) (*oauth2.Token, error) {
	enc := s.getEncryptor()
	if enc == nil || !enc.IsEnabled() {
		return token, nil
	}

	extra := storage.ExtractTokenExtra(token)
	result := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	}

	if result.AccessToken != "" {
		val, err := funcs.transformString(result.AccessToken)
		if err != nil {
			return nil, fmt.Errorf(funcs.accessErrFmt, err)
		}
		result.AccessToken = val
	}

	if result.RefreshToken != "" {
		val, err := funcs.transformString(result.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf(funcs.refreshErrFmt, err)
		}
		result.RefreshToken = val
	}

	if extra != nil {
		transformedExtra, err := funcs.transformExtra(extra, enc)
		if err != nil {
			return nil, err
		}
		result = result.WithExtra(transformedExtra)
	}

	return result, nil
}

// encryptToken encrypts sensitive fields in an oauth2.Token.
// Returns a new token with encrypted fields, leaving the original unchanged.
func (s *Store) encryptToken(token *oauth2.Token) (*oauth2.Token, error) {
	return s.transformTokenFields(token, tokenTransformFuncs{
		transformString: s.getEncryptor().Encrypt,
		transformExtra:  storage.EncryptExtraFields,
		accessErrFmt:    "failed to encrypt access token: %w",
		refreshErrFmt:   "failed to encrypt refresh token: %w",
	})
}

// decryptToken decrypts sensitive fields in an oauth2.Token.
// Returns a new token with decrypted fields, leaving the original unchanged.
func (s *Store) decryptToken(token *oauth2.Token) (*oauth2.Token, error) {
	return s.transformTokenFields(token, tokenTransformFuncs{
		transformString: s.getEncryptor().Decrypt,
		transformExtra:  storage.DecryptExtraFields,
		accessErrFmt:    "failed to decrypt access token: %w",
		refreshErrFmt:   "failed to decrypt refresh token: %w",
	})
}

// validateStringLength checks if a string exceeds the maximum allowed length
func validateStringLength(value string, maxLen int, fieldName string) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d bytes", fieldName, maxLen)
	}
	return nil
}

// ============================================================
// Key Helpers
// ============================================================

// tokenKey returns the key for a user's token: {prefix}:token:{userID}
func (s *Store) tokenKey(userID string) string {
	return fmt.Sprintf("%stoken:%s", s.prefix, userID)
}

// userInfoKey returns the key for user info: {prefix}:userinfo:{userID}
func (s *Store) userInfoKey(userID string) string {
	return fmt.Sprintf("%suserinfo:%s", s.prefix, userID)
}

// refreshTokenKey returns the key for a refresh token: {prefix}:refresh:{token}
func (s *Store) refreshTokenKey(token string) string {
	return fmt.Sprintf("%srefresh:%s", s.prefix, token)
}

// refreshTokenMetaKey returns the key for refresh token metadata: {prefix}:refresh:meta:{token}
func (s *Store) refreshTokenMetaKey(token string) string {
	return fmt.Sprintf("%srefresh:meta:%s", s.prefix, token)
}

// clientKey returns the key for a client: {prefix}:client:{clientID}
func (s *Store) clientKey(clientID string) string {
	return fmt.Sprintf("%sclient:%s", s.prefix, clientID)
}

// clientIPKey returns the key for client IP tracking: {prefix}:client:ip:{ip}
func (s *Store) clientIPKey(ip string) string {
	return fmt.Sprintf("%sclient:ip:%s", s.prefix, ip)
}

// stateKey returns the key for an authorization state: {prefix}:state:{stateID}
func (s *Store) stateKey(stateID string) string {
	return fmt.Sprintf("%sstate:%s", s.prefix, stateID)
}

// providerStateKey returns the key for provider state lookup: {prefix}:state:provider:{state}
func (s *Store) providerStateKey(state string) string {
	return fmt.Sprintf("%sstate:provider:%s", s.prefix, state)
}

// codeKey returns the key for an authorization code: {prefix}:code:{code}
func (s *Store) codeKey(code string) string {
	return fmt.Sprintf("%scode:%s", s.prefix, code)
}

// tokenMetaKey returns the key for token metadata: {prefix}:meta:{tokenID}
func (s *Store) tokenMetaKey(tokenID string) string {
	return fmt.Sprintf("%smeta:%s", s.prefix, tokenID)
}

// userClientKey returns the key for user+client token tracking: {prefix}:userclient:{userID}:{clientID}
func (s *Store) userClientKey(userID, clientID string) string {
	return fmt.Sprintf("%suserclient:%s:%s", s.prefix, userID, clientID)
}

// familyKey returns the key for a token family: {prefix}:family:{familyID}
func (s *Store) familyKey(familyID string) string {
	return fmt.Sprintf("%sfamily:%s", s.prefix, familyID)
}

// ============================================================
// Lua Scripts for Atomic Operations
// ============================================================
//
// These Lua scripts provide atomic operations for security-critical OAuth flows.
// Using Lua scripts ensures atomicity in Valkey/Redis, preventing race conditions
// that could lead to security vulnerabilities like code replay or token reuse attacks.

// luaAtomicCheckAndMarkCodeUsed is a Lua script that atomically checks if an
// authorization code is unused and marks it as used. This prevents authorization
// code replay attacks where an attacker might try to use a code multiple times.
//
// Security: This operation MUST be atomic - only ONE concurrent request can succeed.
// Any concurrent attempts to use the same code will receive "ALREADY_USED" error.
//
// KEYS[1] = code key (e.g., "mcp:code:abc123")
// ARGV[1] = current Unix timestamp in seconds (for expiry check)
//
// Returns:
//   - Original JSON data if code was unused and successfully marked as used
//   - "NOT_FOUND" if the key doesn't exist in Valkey
//   - "EXPIRED" if the code has expired (ARGV[1] > code.expires_at)
//   - "ALREADY_USED:<json>" if code was already used (returns original data for forensics)
//
// Edge cases:
//   - If cjson.decode fails, Lua will raise an error (handled by caller)
//   - Clock skew: caller should account for clock differences between servers
const luaAtomicCheckAndMarkCodeUsed = `
local data = redis.call('GET', KEYS[1])
if not data then
    return 'NOT_FOUND'
end

local code = cjson.decode(data)

-- Check if expired
local now = tonumber(ARGV[1])
local expiresAt = tonumber(code.expires_at)
if expiresAt and now > expiresAt then
    return 'EXPIRED'
end

-- Check if already used
if code.used then
    return 'ALREADY_USED:' .. data
end

-- Mark as used and save
code.used = true
redis.call('SET', KEYS[1], cjson.encode(code), 'KEEPTTL')

return data
`

// luaScriptAtomicGetAndDeleteRefresh is a Lua script that atomically retrieves
// and deletes a refresh token and its associated data. This implements the
// OAuth 2.1 requirement for refresh token rotation with reuse detection.
//
// Security: This operation MUST be atomic - only ONE concurrent request can succeed.
// Once a refresh token is used, it is immediately deleted. Any subsequent attempts
// to use the same token will receive "NOT_FOUND" error, which may indicate token theft.
//
// KEYS[1] = refresh token key - maps refresh token to userID (e.g., "mcp:refresh:xyz789")
// KEYS[2] = token key - stores the provider token (e.g., "mcp:token:xyz789")
// KEYS[3] = token meta key - stores token metadata (e.g., "mcp:meta:xyz789")
// ARGV[1] = current Unix timestamp in seconds (for expiry check)
// ARGV[2] = expiry time in Unix seconds, or -1 if TTL should be relied upon
//
// Returns:
//   - JSON object {"user_id": "...", "token": {...}} on success
//   - "NOT_FOUND" if refresh token key doesn't exist (may indicate already rotated)
//   - "EXPIRED" if token has expired (when ARGV[2] > 0 and now > expiry)
//   - "TOKEN_NOT_FOUND" if provider token doesn't exist
//
// Edge cases:
//   - If any key is missing, appropriate error is returned
//   - All three keys are deleted atomically on success
//   - If cjson operations fail, Lua will raise an error (handled by caller)
const luaScriptAtomicGetAndDeleteRefresh = `
-- Get user ID from refresh token
local userID = redis.call('GET', KEYS[1])
if not userID then
    return 'NOT_FOUND'
end

-- Check expiry if we have stored expiry info
local expiry = tonumber(ARGV[2])
if expiry and expiry > 0 then
    local now = tonumber(ARGV[1])
    if now > expiry then
        return 'EXPIRED'
    end
end

-- Get provider token
local tokenData = redis.call('GET', KEYS[2])
if not tokenData then
    return 'TOKEN_NOT_FOUND'
end

-- Atomically delete all keys
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])

-- Return result as JSON
return cjson.encode({user_id = userID, token = cjson.decode(tokenData)})
`

// ============================================================
// JSON Serialization Helpers
// ============================================================

// authorizationCodeJSON is the JSON representation of an authorization code
type authorizationCodeJSON struct {
	Code                string        `json:"code"`
	ClientID            string        `json:"client_id"`
	RedirectURI         string        `json:"redirect_uri"`
	Scope               string        `json:"scope"`
	Resource            string        `json:"resource,omitempty"`
	Audience            string        `json:"audience,omitempty"`
	CodeChallenge       string        `json:"code_challenge,omitempty"`
	CodeChallengeMethod string        `json:"code_challenge_method,omitempty"`
	UserID              string        `json:"user_id"`
	ProviderToken       *oauth2.Token `json:"provider_token,omitempty"`
	CreatedAt           int64         `json:"created_at"`
	ExpiresAt           int64         `json:"expires_at"`
	Used                bool          `json:"used"`
}

func toAuthorizationCodeJSON(code *storage.AuthorizationCode) *authorizationCodeJSON {
	return &authorizationCodeJSON{
		Code:                code.Code,
		ClientID:            code.ClientID,
		RedirectURI:         code.RedirectURI,
		Scope:               code.Scope,
		Resource:            code.Resource,
		Audience:            code.Audience,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		UserID:              code.UserID,
		ProviderToken:       code.ProviderToken,
		CreatedAt:           code.CreatedAt.Unix(),
		ExpiresAt:           code.ExpiresAt.Unix(),
		Used:                code.Used,
	}
}

func fromAuthorizationCodeJSON(j *authorizationCodeJSON) *storage.AuthorizationCode {
	if j == nil {
		return nil
	}
	return &storage.AuthorizationCode{
		Code:                j.Code,
		ClientID:            j.ClientID,
		RedirectURI:         j.RedirectURI,
		Scope:               j.Scope,
		Resource:            j.Resource,
		Audience:            j.Audience,
		CodeChallenge:       j.CodeChallenge,
		CodeChallengeMethod: j.CodeChallengeMethod,
		UserID:              j.UserID,
		ProviderToken:       j.ProviderToken,
		CreatedAt:           time.Unix(j.CreatedAt, 0),
		ExpiresAt:           time.Unix(j.ExpiresAt, 0),
		Used:                j.Used,
	}
}

// authorizationStateJSON is the JSON representation of an authorization state
type authorizationStateJSON struct {
	StateID              string `json:"state_id"`
	OriginalClientState  string `json:"original_client_state,omitempty"`
	ClientID             string `json:"client_id"`
	RedirectURI          string `json:"redirect_uri"`
	Scope                string `json:"scope"`
	Resource             string `json:"resource,omitempty"`
	CodeChallenge        string `json:"code_challenge,omitempty"`
	CodeChallengeMethod  string `json:"code_challenge_method,omitempty"`
	ProviderState        string `json:"provider_state"`
	ProviderCodeVerifier string `json:"provider_code_verifier,omitempty"`
	CreatedAt            int64  `json:"created_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

func toAuthorizationStateJSON(state *storage.AuthorizationState) *authorizationStateJSON {
	return &authorizationStateJSON{
		StateID:              state.StateID,
		OriginalClientState:  state.OriginalClientState,
		ClientID:             state.ClientID,
		RedirectURI:          state.RedirectURI,
		Scope:                state.Scope,
		Resource:             state.Resource,
		CodeChallenge:        state.CodeChallenge,
		CodeChallengeMethod:  state.CodeChallengeMethod,
		ProviderState:        state.ProviderState,
		ProviderCodeVerifier: state.ProviderCodeVerifier,
		CreatedAt:            state.CreatedAt.Unix(),
		ExpiresAt:            state.ExpiresAt.Unix(),
	}
}

func fromAuthorizationStateJSON(j *authorizationStateJSON) *storage.AuthorizationState {
	if j == nil {
		return nil
	}
	return &storage.AuthorizationState{
		StateID:              j.StateID,
		OriginalClientState:  j.OriginalClientState,
		ClientID:             j.ClientID,
		RedirectURI:          j.RedirectURI,
		Scope:                j.Scope,
		Resource:             j.Resource,
		CodeChallenge:        j.CodeChallenge,
		CodeChallengeMethod:  j.CodeChallengeMethod,
		ProviderState:        j.ProviderState,
		ProviderCodeVerifier: j.ProviderCodeVerifier,
		CreatedAt:            time.Unix(j.CreatedAt, 0),
		ExpiresAt:            time.Unix(j.ExpiresAt, 0),
	}
}

// clientJSON is the JSON representation of an OAuth client
type clientJSON struct {
	ClientID                string   `json:"client_id"`
	ClientSecretHash        string   `json:"client_secret_hash,omitempty"`
	ClientType              string   `json:"client_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	CreatedAt               int64    `json:"created_at"`
}

func toClientJSON(client *storage.Client) *clientJSON {
	return &clientJSON{
		ClientID:                client.ClientID,
		ClientSecretHash:        client.ClientSecretHash,
		ClientType:              client.ClientType,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.ClientName,
		Scopes:                  client.Scopes,
		CreatedAt:               client.CreatedAt.Unix(),
	}
}

func fromClientJSON(j *clientJSON) *storage.Client {
	if j == nil {
		return nil
	}
	return &storage.Client{
		ClientID:                j.ClientID,
		ClientSecretHash:        j.ClientSecretHash,
		ClientType:              j.ClientType,
		RedirectURIs:            j.RedirectURIs,
		TokenEndpointAuthMethod: j.TokenEndpointAuthMethod,
		GrantTypes:              j.GrantTypes,
		ResponseTypes:           j.ResponseTypes,
		ClientName:              j.ClientName,
		Scopes:                  j.Scopes,
		CreatedAt:               time.Unix(j.CreatedAt, 0),
	}
}

// refreshTokenFamilyJSON is the JSON representation of refresh token family metadata
type refreshTokenFamilyJSON struct {
	FamilyID   string `json:"family_id"`
	UserID     string `json:"user_id"`
	ClientID   string `json:"client_id"`
	Generation int    `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	Revoked    bool   `json:"revoked"`
	RevokedAt  int64  `json:"revoked_at,omitempty"`
}

func toRefreshTokenFamilyJSON(meta *storage.RefreshTokenFamilyMetadata) *refreshTokenFamilyJSON {
	j := &refreshTokenFamilyJSON{
		FamilyID:   meta.FamilyID,
		UserID:     meta.UserID,
		ClientID:   meta.ClientID,
		Generation: meta.Generation,
		IssuedAt:   meta.IssuedAt.Unix(),
		Revoked:    meta.Revoked,
	}
	if !meta.RevokedAt.IsZero() {
		j.RevokedAt = meta.RevokedAt.Unix()
	}
	return j
}

func fromRefreshTokenFamilyJSON(j *refreshTokenFamilyJSON) *storage.RefreshTokenFamilyMetadata {
	if j == nil {
		return nil
	}
	meta := &storage.RefreshTokenFamilyMetadata{
		FamilyID:   j.FamilyID,
		UserID:     j.UserID,
		ClientID:   j.ClientID,
		Generation: j.Generation,
		IssuedAt:   time.Unix(j.IssuedAt, 0),
		Revoked:    j.Revoked,
	}
	if j.RevokedAt > 0 {
		meta.RevokedAt = time.Unix(j.RevokedAt, 0)
	}
	return meta
}

// tokenMetadataJSON is the JSON representation of token metadata
type tokenMetadataJSON struct {
	UserID    string   `json:"user_id"`
	ClientID  string   `json:"client_id"`
	IssuedAt  int64    `json:"issued_at"`
	TokenType string   `json:"token_type"`
	Audience  string   `json:"audience,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}

func toTokenMetadataJSON(meta *storage.TokenMetadata) *tokenMetadataJSON {
	return &tokenMetadataJSON{
		UserID:    meta.UserID,
		ClientID:  meta.ClientID,
		IssuedAt:  meta.IssuedAt.Unix(),
		TokenType: meta.TokenType,
		Audience:  meta.Audience,
		Scopes:    meta.Scopes,
	}
}

func fromTokenMetadataJSON(j *tokenMetadataJSON) *storage.TokenMetadata {
	if j == nil {
		return nil
	}
	return &storage.TokenMetadata{
		UserID:    j.UserID,
		ClientID:  j.ClientID,
		IssuedAt:  time.Unix(j.IssuedAt, 0),
		TokenType: j.TokenType,
		Audience:  j.Audience,
		Scopes:    j.Scopes,
	}
}

// ============================================================
// Helper methods
// ============================================================

// getAndUnmarshal is a generic helper for fetching a key from Valkey,
// unmarshalling the JSON data, and converting to the target type.
// This reduces code duplication across GetClient, GetRefreshTokenFamily, etc.
func getAndUnmarshal[J any, T any](
	ctx context.Context,
	s *Store,
	key string,
	notFoundErr error,
	fromJSON func(*J) *T,
) (*T, error) {
	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, notFoundErr
		}
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	var j J
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return fromJSON(&j), nil
}

// safeTruncate safely truncates a string to n characters
func safeTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// calculateTTL calculates the TTL for a key based on expiry time
// Returns 0 if the key has already expired
func calculateTTL(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return 0
	}
	return ttl
}

// userInfoJSON is the JSON representation of user info
type userInfoJSON struct {
	ID            string `json:"id"`
	Email         string `json:"email,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

func toUserInfoJSON(info *providers.UserInfo) *userInfoJSON {
	return &userInfoJSON{
		ID:            info.ID,
		Email:         info.Email,
		Name:          info.Name,
		Picture:       info.Picture,
		EmailVerified: info.EmailVerified,
	}
}

func fromUserInfoJSON(j *userInfoJSON) *providers.UserInfo {
	if j == nil {
		return nil
	}
	return &providers.UserInfo{
		ID:            j.ID,
		Email:         j.Email,
		Name:          j.Name,
		Picture:       j.Picture,
		EmailVerified: j.EmailVerified,
	}
}
