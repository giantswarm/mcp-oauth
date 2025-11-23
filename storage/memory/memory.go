package memory

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"golang.org/x/crypto/bcrypt"
)

// Store is an in-memory implementation of all storage interfaces.
// It implements TokenStore, ClientStore, and FlowStore.
type Store struct {
	mu sync.RWMutex

	// Token storage (encrypted at rest if encryptor is set)
	tokens   map[string]*providers.TokenResponse
	userInfo map[string]*providers.UserInfo

	// Refresh token tracking (for rotation and security)
	refreshTokens        map[string]string    // refresh token -> user ID
	refreshTokenExpiries map[string]time.Time // refresh token -> expiry time

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

// New creates a new in-memory store with default cleanup interval (1 minute)
func New() *Store {
	return NewWithInterval(time.Minute)
}

// NewWithInterval creates a new in-memory store with custom cleanup interval
func NewWithInterval(cleanupInterval time.Duration) *Store {
	s := &Store{
		tokens:               make(map[string]*providers.TokenResponse),
		userInfo:             make(map[string]*providers.UserInfo),
		refreshTokens:        make(map[string]string),
		refreshTokenExpiries: make(map[string]time.Time),
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

// SaveToken saves a token for a user with optional encryption
func (s *Store) SaveToken(userID string, token *providers.TokenResponse) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt sensitive token fields if encryptor is configured
	if s.encryptor != nil && s.encryptor.IsEnabled() {
		// Create a copy to avoid modifying the original
		encryptedToken := &providers.TokenResponse{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.ExpiresAt,
			Scopes:       token.Scopes,
			TokenType:    token.TokenType,
		}

		// Encrypt access token
		if encryptedToken.AccessToken != "" {
			encrypted, err := s.encryptor.Encrypt(encryptedToken.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt access token: %w", err)
			}
			encryptedToken.AccessToken = encrypted
		}

		// Encrypt refresh token
		if encryptedToken.RefreshToken != "" {
			encrypted, err := s.encryptor.Encrypt(encryptedToken.RefreshToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt refresh token: %w", err)
			}
			encryptedToken.RefreshToken = encrypted
		}

		s.tokens[userID] = encryptedToken
		s.logger.Debug("Saved encrypted token", "user_id", userID)
	} else {
		s.tokens[userID] = token
		s.logger.Debug("Saved token", "user_id", userID)
	}

	return nil
}

// GetToken retrieves a token for a user and decrypts if necessary
func (s *Store) GetToken(userID string) (*providers.TokenResponse, error) {
	s.mu.RLock()
	encryptor := s.encryptor
	s.mu.RUnlock()

	s.mu.RLock()
	token, ok := s.tokens[userID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("token not found for user: %s", userID)
	}

	// Check if expired with clock skew grace period (and no refresh token)
	// This prevents false expiration errors due to time synchronization issues
	if security.IsTokenExpired(token.ExpiresAt) && token.RefreshToken == "" {
		return nil, fmt.Errorf("token expired for user: %s", userID)
	}

	// Decrypt if encryptor is configured
	if encryptor != nil && encryptor.IsEnabled() {
		// Create a copy to avoid modifying the stored version
		decryptedToken := &providers.TokenResponse{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.ExpiresAt,
			Scopes:       token.Scopes,
			TokenType:    token.TokenType,
		}

		// Decrypt access token
		if decryptedToken.AccessToken != "" {
			decrypted, err := encryptor.Decrypt(decryptedToken.AccessToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt access token: %w", err)
			}
			decryptedToken.AccessToken = decrypted
		}

		// Decrypt refresh token
		if decryptedToken.RefreshToken != "" {
			decrypted, err := encryptor.Decrypt(decryptedToken.RefreshToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
			}
			decryptedToken.RefreshToken = decrypted
		}

		return decryptedToken, nil
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
func (s *Store) ValidateClientSecret(clientID, clientSecret string) error {
	client, err := s.GetClient(clientID)
	if err != nil {
		return err
	}

	// For public clients, no secret validation needed
	if client.ClientType == "public" {
		return nil
	}

	// For confidential clients, validate the secret hash with bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		return fmt.Errorf("invalid client secret")
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
func (s *Store) SaveAuthorizationState(state *storage.AuthorizationState) error {
	if state == nil || state.StateID == "" {
		return fmt.Errorf("invalid authorization state")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.authStates[state.StateID] = state
	s.logger.Debug("Saved authorization state", "state_id", state.StateID)
	return nil
}

// GetAuthorizationState retrieves an authorization state
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

// DeleteAuthorizationState removes an authorization state
func (s *Store) DeleteAuthorizationState(stateID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authStates, stateID)
	s.logger.Debug("Deleted authorization state", "state_id", stateID)
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

// GetAuthorizationCode retrieves and atomically deletes an authorization code
// This prevents replay attacks by ensuring codes can only be used once
func (s *Store) GetAuthorizationCode(code string) (*storage.AuthorizationCode, error) {
	s.mu.Lock()  // Use write lock for atomic delete
	defer s.mu.Unlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, fmt.Errorf("authorization code not found")
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(authCode.ExpiresAt) {
		delete(s.authCodes, code) // Delete expired code
		return nil, fmt.Errorf("authorization code expired")
	}

	// Check if already used
	if authCode.Used {
		delete(s.authCodes, code) // Delete used code
		return nil, fmt.Errorf("authorization code already used")
	}

	// Atomically delete the code to prevent replay attacks
	// This eliminates the race condition window between check and use
	delete(s.authCodes, code)
	s.logger.Debug("Authorization code consumed (one-time use)", "code_prefix", code[:min(8, len(code))])

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
		if security.IsTokenExpired(token.ExpiresAt) && token.RefreshToken == "" {
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
			cleaned++
		}
	}

	if cleaned > 0 {
		s.logger.Debug("Cleaned up expired entries", "count", cleaned)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

