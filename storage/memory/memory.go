// Package memory provides an in-memory implementation of all storage interfaces.
// It is suitable for development, testing, and single-instance deployments.
package memory

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	// tokenIDLogLength is the number of characters to include when logging token IDs
	// This provides enough uniqueness for debugging while keeping logs secure
	tokenIDLogLength = 8
)

// RefreshTokenFamily tracks a family of refresh tokens for reuse detection (OAuth 2.1)
type RefreshTokenFamily struct {
	FamilyID   string    // Unique identifier for this token family
	UserID     string    // User who owns this family
	ClientID   string    // Client who owns this family
	Generation int       // Increments with each rotation
	IssuedAt   time.Time // When this generation was issued
	Revoked    bool      // True if family has been revoked due to reuse detection
}

// TokenMetadata tracks ownership information for a token (for revocation by user+client)
type TokenMetadata struct {
	UserID    string    // User who owns this token
	ClientID  string    // Client who owns this token
	IssuedAt  time.Time // When this token was issued
	TokenType string    // "access" or "refresh"
}

// Store is an in-memory implementation of all storage interfaces.
// It implements TokenStore, ClientStore, FlowStore, RefreshTokenFamilyStore, and TokenRevocationStore.
type Store struct {
	mu sync.RWMutex

	// Token storage (encrypted at rest if encryptor is set)
	// Now uses oauth2.Token directly
	tokens   map[string]*oauth2.Token
	userInfo map[string]*providers.UserInfo

	// Refresh token tracking (for rotation and security)
	refreshTokens        map[string]string              // refresh token -> user ID
	refreshTokenExpiries map[string]time.Time           // refresh token -> expiry time
	refreshTokenFamilies map[string]*RefreshTokenFamily // refresh token -> family metadata

	// Token metadata tracking (for revocation by user+client)
	tokenMetadata map[string]*TokenMetadata // token ID (access or refresh) -> metadata

	// Client storage
	clients      map[string]*storage.Client
	clientsPerIP map[string]int // IP address -> client count (for DoS protection)

	// Flow storage
	authStates map[string]*storage.AuthorizationState
	authCodes  map[string]*storage.AuthorizationCode

	// Security
	encryptor *security.Encryptor // Token encryption at rest (optional)

	// Cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	logger          *slog.Logger
}

// Compile-time interface checks to ensure Store implements all storage interfaces
var (
	_ storage.TokenStore              = (*Store)(nil)
	_ storage.ClientStore             = (*Store)(nil)
	_ storage.FlowStore               = (*Store)(nil)
	_ storage.RefreshTokenFamilyStore = (*Store)(nil)
	_ storage.TokenRevocationStore    = (*Store)(nil)
)

// New creates a new in-memory store with default cleanup interval (1 minute)
func New() *Store {
	return NewWithInterval(time.Minute)
}

// NewWithInterval creates a new in-memory store with custom cleanup interval
func NewWithInterval(cleanupInterval time.Duration) *Store {
	s := &Store{
		tokens:               make(map[string]*oauth2.Token),
		userInfo:             make(map[string]*providers.UserInfo),
		refreshTokens:        make(map[string]string),
		refreshTokenExpiries: make(map[string]time.Time),
		refreshTokenFamilies: make(map[string]*RefreshTokenFamily),
		tokenMetadata:        make(map[string]*TokenMetadata),
		clients:              make(map[string]*storage.Client),
		clientsPerIP:         make(map[string]int),
		authStates:           make(map[string]*storage.AuthorizationState),
		authCodes:            make(map[string]*storage.AuthorizationCode),
		cleanupInterval:      cleanupInterval,
		stopCleanup:          make(chan struct{}),
		logger:               slog.Default(),
	}

	// Start background cleanup
	go s.cleanupLoop()

	return s
}

// SetLogger sets a custom logger
func (s *Store) SetLogger(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger
}

// SetEncryptor sets the token encryptor for encryption at rest
func (s *Store) SetEncryptor(enc *security.Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = enc
	if enc != nil && enc.IsEnabled() {
		s.logger.Info("Token encryption at rest enabled for storage")
	}
}

// Stop gracefully stops the cleanup goroutine
func (s *Store) Stop() {
	close(s.stopCleanup)
}

// ============================================================
// TokenStore Implementation
// ============================================================

// SaveToken saves an oauth2.Token for a user with optional encryption
func (s *Store) SaveToken(userID string, token *oauth2.Token) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt token if encryptor is configured
	storedToken := token
	if s.encryptor != nil && s.encryptor.IsEnabled() {
		encrypted, err := s.encryptToken(token)
		if err != nil {
			return err
		}
		storedToken = encrypted
		s.logger.Debug("Saved encrypted token", "user_id", userID)
	} else {
		s.logger.Debug("Saved token", "user_id", userID)
	}

	s.tokens[userID] = storedToken
	return nil
}

// encryptToken encrypts sensitive fields in an oauth2.Token
// Returns a new token with encrypted fields, leaving the original unchanged
func (s *Store) encryptToken(token *oauth2.Token) (*oauth2.Token, error) {
	// Create a copy to avoid modifying the original
	encrypted := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	}

	// Encrypt access token
	if encrypted.AccessToken != "" {
		enc, err := s.encryptor.Encrypt(encrypted.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt access token: %w", err)
		}
		encrypted.AccessToken = enc
	}

	// Encrypt refresh token
	if encrypted.RefreshToken != "" {
		enc, err := s.encryptor.Encrypt(encrypted.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		encrypted.RefreshToken = enc
	}

	return encrypted, nil
}

// decryptToken decrypts sensitive fields in an oauth2.Token
// Returns a new token with decrypted fields, leaving the original unchanged
func (s *Store) decryptToken(token *oauth2.Token, encryptor *security.Encryptor) (*oauth2.Token, error) {
	// Create a copy to avoid modifying the stored version
	decrypted := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	}

	// Decrypt access token
	if decrypted.AccessToken != "" {
		dec, err := encryptor.Decrypt(decrypted.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}
		decrypted.AccessToken = dec
	}

	// Decrypt refresh token
	if decrypted.RefreshToken != "" {
		dec, err := encryptor.Decrypt(decrypted.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
		decrypted.RefreshToken = dec
	}

	return decrypted, nil
}

// GetToken retrieves an oauth2.Token for a user and decrypts if necessary
func (s *Store) GetToken(userID string) (*oauth2.Token, error) {
	s.mu.RLock()
	encryptor := s.encryptor
	token, ok := s.tokens[userID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("token not found for user: %s", userID)
	}

	// Check if expired with clock skew grace period (and no refresh token)
	// This prevents false expiration errors due to time synchronization issues
	if security.IsTokenExpired(token.Expiry) && token.RefreshToken == "" {
		return nil, fmt.Errorf("token expired for user: %s", userID)
	}

	// Decrypt if encryptor is configured
	if encryptor != nil && encryptor.IsEnabled() {
		return s.decryptToken(token, encryptor)
	}

	return token, nil
}

// DeleteToken removes a token for a user
func (s *Store) DeleteToken(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, userID)
	s.logger.Debug("Deleted token", "user_id", userID)
	return nil
}

// SaveUserInfo saves user information
func (s *Store) SaveUserInfo(userID string, info *providers.UserInfo) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if info == nil {
		return fmt.Errorf("userInfo cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.userInfo[userID] = info
	return nil
}

// GetUserInfo retrieves user information
func (s *Store) GetUserInfo(userID string) (*providers.UserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.userInfo[userID]
	if !ok {
		return nil, fmt.Errorf("user info not found: %s", userID)
	}

	return info, nil
}

// ============================================================
// ClientStore Implementation
// ============================================================

// SaveClient saves a registered client and tracks IP for DoS protection
func (s *Store) SaveClient(client *storage.Client) error {
	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ClientID] = client
	s.logger.Debug("Saved client", "client_id", client.ClientID)
	return nil
}

// CheckIPLimit checks if an IP has reached the client registration limit
func (s *Store) CheckIPLimit(ip string, maxClientsPerIP int) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if maxClientsPerIP <= 0 {
		return nil // No limit
	}

	count := s.clientsPerIP[ip]
	if count >= maxClientsPerIP {
		return fmt.Errorf("client registration limit reached for IP %s (%d/%d clients)", ip, count, maxClientsPerIP)
	}

	return nil
}

// TrackClientIP increments the client count for an IP address
func (s *Store) TrackClientIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientsPerIP[ip]++
}

// ============================================================
// Refresh Token Management (OAuth 2.1 Security)
// ============================================================

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
// For OAuth 2.1 compliance, also tracks token family for reuse detection
func (s *Store) SaveRefreshToken(refreshToken, userID string, expiresAt time.Time) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[refreshToken] = userID
	s.refreshTokenExpiries[refreshToken] = expiresAt
	s.logger.Debug("Saved refresh token", "user_id", userID, "expires_at", expiresAt)
	return nil
}

// SaveRefreshTokenWithFamily saves a refresh token with family tracking for reuse detection
// This is the OAuth 2.1 compliant version that enables token theft detection
func (s *Store) SaveRefreshTokenWithFamily(refreshToken, userID, clientID, familyID string, generation int, expiresAt time.Time) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if familyID == "" {
		return fmt.Errorf("family ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Save basic refresh token info
	s.refreshTokens[refreshToken] = userID
	s.refreshTokenExpiries[refreshToken] = expiresAt

	// Save family metadata for reuse detection
	s.refreshTokenFamilies[refreshToken] = &RefreshTokenFamily{
		FamilyID:   familyID,
		UserID:     userID,
		ClientID:   clientID,
		Generation: generation,
		IssuedAt:   time.Now(),
		Revoked:    false,
	}

	// Save token metadata for revocation tracking (OAuth 2.1 code reuse detection)
	s.tokenMetadata[refreshToken] = &TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: "refresh",
	}

	s.logger.Debug("Saved refresh token with family tracking",
		"user_id", userID,
		"family_id", familyID[:min(8, len(familyID))],
		"generation", generation,
		"expires_at", expiresAt)
	return nil
}

// GetRefreshTokenFamily retrieves family metadata for a refresh token
func (s *Store) GetRefreshTokenFamily(refreshToken string) (*storage.RefreshTokenFamilyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	family, ok := s.refreshTokenFamilies[refreshToken]
	if !ok {
		return nil, fmt.Errorf("refresh token family not found")
	}

	// Convert internal type to interface type
	return &storage.RefreshTokenFamilyMetadata{
		FamilyID:   family.FamilyID,
		UserID:     family.UserID,
		ClientID:   family.ClientID,
		Generation: family.Generation,
		IssuedAt:   family.IssuedAt,
		Revoked:    family.Revoked,
	}, nil
}

// RevokeRefreshTokenFamily revokes all tokens in a family (for reuse detection)
// This is called when token reuse is detected (OAuth 2.1 security requirement)
func (s *Store) RevokeRefreshTokenFamily(familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	revokedCount := 0

	// Find and revoke all tokens in this family
	for token, family := range s.refreshTokenFamilies {
		if family.FamilyID == familyID {
			family.Revoked = true
			// Also delete the token to prevent any further use
			delete(s.refreshTokens, token)
			delete(s.refreshTokenExpiries, token)
			delete(s.tokens, token) // Also delete provider token mapping
			revokedCount++
		}
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked refresh token family due to reuse detection",
			"family_id", familyID[:min(8, len(familyID))],
			"tokens_revoked", revokedCount)
	}

	return nil
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token
// Returns error if token is not found or expired (with clock skew grace)
func (s *Store) GetRefreshTokenInfo(refreshToken string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, ok := s.refreshTokens[refreshToken]
	if !ok {
		return "", fmt.Errorf("refresh token not found")
	}

	// Check if expired with clock skew grace period
	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			return "", fmt.Errorf("refresh token expired")
		}
	}

	return userID, nil
}

// DeleteRefreshToken removes a refresh token (used for rotation)
func (s *Store) DeleteRefreshToken(refreshToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)
	s.logger.Debug("Deleted refresh token (rotation)")
	return nil
}

// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
// This prevents race conditions in refresh token rotation and reuse detection.
// Returns the userID and provider token if successful.
//
// SECURITY: This operation is atomic - only ONE concurrent request can succeed.
// All other concurrent requests will receive a "token not found" error.
func (s *Store) AtomicGetAndDeleteRefreshToken(refreshToken string) (string, *oauth2.Token, error) {
	s.mu.Lock() // MUST use write lock for atomic get-and-delete
	defer s.mu.Unlock()

	// Get user ID
	userID, ok := s.refreshTokens[refreshToken]
	if !ok {
		return "", nil, fmt.Errorf("refresh token not found or already used")
	}

	// Check if expired with clock skew grace period
	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			return "", nil, fmt.Errorf("refresh token expired")
		}
	}

	// Get provider token
	providerToken, ok := s.tokens[refreshToken]
	if !ok {
		return "", nil, fmt.Errorf("provider token not found")
	}

	// ATOMIC DELETE - ensures only one request succeeds
	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)

	s.logger.Debug("Atomically retrieved and deleted refresh token",
		"user_id", userID)

	return userID, providerToken, nil
}

// GetClient retrieves a client by ID
func (s *Store) GetClient(clientID string) (*storage.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	return client, nil
}

// ValidateClientSecret validates a client's secret using bcrypt
// Uses constant-time operations to prevent timing attacks
func (s *Store) ValidateClientSecret(clientID, clientSecret string) error {
	// SECURITY: Always perform the same operations to prevent timing attacks
	// that could reveal whether a client exists or not

	// Pre-computed dummy hash for non-existent clients (bcrypt hash of empty string)
	// This ensures we always perform a bcrypt comparison even if client doesn't exist
	dummyHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

	client, err := s.GetClient(clientID)

	// Determine which hash to use (real or dummy)
	hashToCompare := dummyHash
	isPublicClient := false

	if err == nil {
		if client.ClientType == "public" {
			isPublicClient = true
		} else if client.ClientSecretHash != "" {
			hashToCompare = client.ClientSecretHash
		}
	}

	// ALWAYS perform bcrypt comparison (constant-time by design)
	// This prevents timing attacks based on whether we skip the comparison
	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(clientSecret))

	// For public clients, authentication always succeeds
	if isPublicClient && err == nil {
		return nil
	}

	// If client lookup failed, return error (but only after bcrypt comparison)
	if err != nil {
		return fmt.Errorf("invalid client credentials")
	}

	// If bcrypt comparison failed, return error
	if bcryptErr != nil {
		return fmt.Errorf("invalid client credentials")
	}

	return nil
}

// ListClients lists all registered clients
func (s *Store) ListClients() ([]*storage.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]*storage.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	return clients, nil
}

// ============================================================
// FlowStore Implementation
// ============================================================

// SaveAuthorizationState saves the state of an ongoing authorization flow
// Stores by both client state (StateID) and provider state (ProviderState) for dual lookup
func (s *Store) SaveAuthorizationState(state *storage.AuthorizationState) error {
	if state == nil || state.StateID == "" {
		return fmt.Errorf("invalid authorization state")
	}
	if state.ProviderState == "" {
		return fmt.Errorf("provider state is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store by both StateID and ProviderState for dual lookup
	// StateID is used when validating client requests
	// ProviderState is used when validating provider callbacks
	s.authStates[state.StateID] = state
	s.authStates[state.ProviderState] = state
	s.logger.Debug("Saved authorization state", "state_id", state.StateID, "provider_state_prefix", state.ProviderState[:min(8, len(state.ProviderState))])
	return nil
}

// GetAuthorizationState retrieves an authorization state by client state
func (s *Store) GetAuthorizationState(stateID string) (*storage.AuthorizationState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.authStates[stateID]
	if !ok {
		return nil, fmt.Errorf("authorization state not found: %s", stateID)
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(state.ExpiresAt) {
		return nil, fmt.Errorf("authorization state expired")
	}

	return state, nil
}

// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
// This is used during provider callback validation (separate from client state)
func (s *Store) GetAuthorizationStateByProviderState(providerState string) (*storage.AuthorizationState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.authStates[providerState]
	if !ok {
		return nil, fmt.Errorf("authorization state not found for provider state")
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(state.ExpiresAt) {
		return nil, fmt.Errorf("authorization state expired")
	}

	return state, nil
}

// DeleteAuthorizationState removes an authorization state
// Removes both client state and provider state entries
func (s *Store) DeleteAuthorizationState(stateID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the state first to find both keys
	state, ok := s.authStates[stateID]
	if ok {
		// Delete both the client state and provider state entries
		delete(s.authStates, state.StateID)
		delete(s.authStates, state.ProviderState)
		s.logger.Debug("Deleted authorization state (both entries)", "state_id", state.StateID)
	} else {
		// stateID might be the provider state, try direct delete
		delete(s.authStates, stateID)
		s.logger.Debug("Deleted authorization state", "state_id", stateID)
	}
	return nil
}

// SaveAuthorizationCode saves an issued authorization code
func (s *Store) SaveAuthorizationCode(code *storage.AuthorizationCode) error {
	if code == nil || code.Code == "" {
		return fmt.Errorf("invalid authorization code")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.authCodes[code.Code] = code
	s.logger.Debug("Saved authorization code", "code_prefix", code.Code[:min(8, len(code.Code))])
	return nil
}

// GetAuthorizationCode retrieves an authorization code without modifying it.
// The code is kept marked as "Used" to detect reuse attempts (OAuth 2.1 requirement).
// Expired/used codes are cleaned up by the background cleanup goroutine.
//
// NOTE: For actual code exchange, use AtomicCheckAndMarkAuthCodeUsed instead
// to prevent race conditions.
func (s *Store) GetAuthorizationCode(code string) (*storage.AuthorizationCode, error) {
	s.mu.Lock() // Use write lock to ensure consistent read
	defer s.mu.Unlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, fmt.Errorf("authorization code not found")
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	// Return a COPY to prevent caller from modifying our stored version
	codeCopy := *authCode
	return &codeCopy, nil
}

// AtomicCheckAndMarkAuthCodeUsed atomically checks if a code is unused and marks it as used.
// This prevents race conditions in authorization code reuse detection.
// Returns the auth code if successful, or an error if code is already used.
//
// SECURITY: This operation is atomic - only ONE concurrent request can succeed.
// All other concurrent requests will receive an "already used" error.
func (s *Store) AtomicCheckAndMarkAuthCodeUsed(code string) (*storage.AuthorizationCode, error) {
	s.mu.Lock() // MUST use write lock for atomic check-and-set
	defer s.mu.Unlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, fmt.Errorf("authorization code not found")
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	// ATOMIC check-and-set: Only one thread can pass this check
	if authCode.Used {
		// Code already used - return it for reuse detection handling
		return authCode, fmt.Errorf("authorization code already used")
	}

	// Mark as used atomically
	authCode.Used = true
	s.logger.Debug("Marked authorization code as used",
		"code_prefix", code[:min(8, len(code))])

	// Return the code for token issuance
	return authCode, nil
}

// DeleteAuthorizationCode removes an authorization code
func (s *Store) DeleteAuthorizationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authCodes, code)
	s.logger.Debug("Deleted authorization code")
	return nil
}

// ============================================================
// Cleanup
// ============================================================

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleaned := 0

	// Cleanup expired tokens (with clock skew grace period)
	for userID, token := range s.tokens {
		if security.IsTokenExpired(token.Expiry) && token.RefreshToken == "" {
			delete(s.tokens, userID)
			delete(s.userInfo, userID)
			cleaned++
		}
	}

	// Cleanup expired authorization states (with clock skew grace period)
	for stateID, state := range s.authStates {
		if security.IsTokenExpired(state.ExpiresAt) {
			delete(s.authStates, stateID)
			cleaned++
		}
	}

	// Cleanup expired authorization codes (with clock skew grace period)
	for code, authCode := range s.authCodes {
		if security.IsTokenExpired(authCode.ExpiresAt) {
			delete(s.authCodes, code)
			cleaned++
		}
	}

	// Cleanup expired refresh tokens (with clock skew grace period)
	for refreshToken, expiresAt := range s.refreshTokenExpiries {
		if security.IsTokenExpired(expiresAt) {
			delete(s.refreshTokens, refreshToken)
			delete(s.refreshTokenExpiries, refreshToken)
			delete(s.refreshTokenFamilies, refreshToken) // Also cleanup family metadata
			cleaned++
		}
	}

	// Cleanup revoked token families (keep metadata for a while for forensics, then cleanup)
	// Revoked families older than 7 days can be removed
	revokedFamilyCleanupThreshold := time.Now().Add(-7 * 24 * time.Hour)
	for refreshToken, family := range s.refreshTokenFamilies {
		if family.Revoked && family.IssuedAt.Before(revokedFamilyCleanupThreshold) {
			delete(s.refreshTokenFamilies, refreshToken)
			cleaned++
		}
	}

	// Cleanup orphaned token metadata (tokens that no longer exist)
	for tokenID := range s.tokenMetadata {
		// Check if token still exists (either as a regular token or refresh token)
		if _, existsAsToken := s.tokens[tokenID]; !existsAsToken {
			if _, existsAsRefresh := s.refreshTokens[tokenID]; !existsAsRefresh {
				delete(s.tokenMetadata, tokenID)
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		s.logger.Debug("Cleaned up expired entries", "count", cleaned)
	}
}

// ============================================================
// TokenRevocationStore Implementation (OAuth 2.1 Security)
// ============================================================

// SaveTokenMetadata saves metadata for a token (for revocation tracking)
// This should be called whenever a token is issued to a user for a client
func (s *Store) SaveTokenMetadata(tokenID, userID, clientID, tokenType string) error {
	if tokenID == "" || userID == "" || clientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokenMetadata[tokenID] = &TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: tokenType,
	}

	s.logger.Debug("Saved token metadata",
		"token_type", tokenType,
		"user_id", userID,
		"client_id", clientID)

	return nil
}

// RevokeAllTokensForUserClient revokes all tokens (access + refresh) for a specific user+client combination.
// This implements the OAuth 2.1 requirement for authorization code reuse detection.
// Returns the number of tokens revoked and any error encountered.
func (s *Store) RevokeAllTokensForUserClient(userID, clientID string) (int, error) {
	if userID == "" || clientID == "" {
		return 0, fmt.Errorf("userID and clientID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	revokedCount := 0

	// Step 1: Identify all token families to revoke
	familiesToRevoke := make(map[string]bool)
	tokensToRevoke := make([]string, 0)

	for tokenID, metadata := range s.tokenMetadata {
		if metadata.UserID == userID && metadata.ClientID == clientID {
			tokensToRevoke = append(tokensToRevoke, tokenID)

			// Track family IDs that need complete revocation
			if family, hasFam := s.refreshTokenFamilies[tokenID]; hasFam {
				familiesToRevoke[family.FamilyID] = true
			}
		}
	}

	// Step 2: Revoke ENTIRE token families (finds ALL family members, not just tracked ones)
	for familyID := range familiesToRevoke {
		familyRevokedCount := 0
		for tokenID, family := range s.refreshTokenFamilies {
			if family.FamilyID == familyID {
				// Mark family as revoked (keeps metadata for forensics/detection)
				family.Revoked = true

				// Delete the actual tokens
				delete(s.refreshTokens, tokenID)
				delete(s.refreshTokenExpiries, tokenID)
				delete(s.tokens, tokenID)
				delete(s.tokenMetadata, tokenID)

				revokedCount++
				familyRevokedCount++

				s.logger.Debug("Revoked token from family",
					"user_id", userID,
					"client_id", clientID,
					"token_id", tokenID[:min(tokenIDLogLength, len(tokenID))],
					"family_id", familyID[:min(tokenIDLogLength, len(familyID))],
					"generation", family.Generation)
			}
		}

		if familyRevokedCount > 0 {
			s.logger.Info("Revoked entire refresh token family",
				"user_id", userID,
				"client_id", clientID,
				"family_id", familyID[:min(tokenIDLogLength, len(familyID))],
				"tokens_revoked", familyRevokedCount,
				"reason", "authorization_code_reuse_detected")
		}
	}

	// Step 3: Revoke remaining tokens (access tokens, tokens without families)
	for _, tokenID := range tokensToRevoke {
		// Skip if already deleted as part of family revocation
		if _, exists := s.tokens[tokenID]; !exists {
			continue
		}

		// Delete the token itself
		delete(s.tokens, tokenID)
		delete(s.tokenMetadata, tokenID)
		revokedCount++

		s.logger.Debug("Revoked access token",
			"user_id", userID,
			"client_id", clientID,
			"token_id", tokenID[:min(tokenIDLogLength, len(tokenID))])
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked all tokens for user+client",
			"user_id", userID,
			"client_id", clientID,
			"tokens_revoked", revokedCount,
			"reason", "authorization_code_reuse_detected")
	}

	return revokedCount, nil
}

// GetTokensByUserClient retrieves all token IDs for a user+client combination.
// This is primarily for testing and debugging purposes.
func (s *Store) GetTokensByUserClient(userID, clientID string) ([]string, error) {
	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("userID and clientID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens := make([]string, 0)
	for tokenID, metadata := range s.tokenMetadata {
		if metadata.UserID == userID && metadata.ClientID == clientID {
			tokens = append(tokens, tokenID)
		}
	}

	return tokens, nil
}
