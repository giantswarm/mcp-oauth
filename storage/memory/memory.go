package memory

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Store is an in-memory implementation of all storage interfaces.
// It implements TokenStore, ClientStore, and FlowStore.
type Store struct {
	mu sync.RWMutex

	// Token storage
	tokens   map[string]*providers.TokenResponse
	userInfo map[string]*providers.UserInfo

	// Client storage
	clients map[string]*storage.Client

	// Flow storage
	authStates map[string]*storage.AuthorizationState
	authCodes  map[string]*storage.AuthorizationCode

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
		tokens:          make(map[string]*providers.TokenResponse),
		userInfo:        make(map[string]*providers.UserInfo),
		clients:         make(map[string]*storage.Client),
		authStates:      make(map[string]*storage.AuthorizationState),
		authCodes:       make(map[string]*storage.AuthorizationCode),
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
		logger:          slog.Default(),
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

// Stop gracefully stops the cleanup goroutine
func (s *Store) Stop() {
	close(s.stopCleanup)
}

// ============================================================
// TokenStore Implementation
// ============================================================

// SaveToken saves a token for a user
func (s *Store) SaveToken(userID string, token *providers.TokenResponse) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[userID] = token
	s.logger.Debug("Saved token", "user_id", userID)
	return nil
}

// GetToken retrieves a token for a user
func (s *Store) GetToken(userID string) (*providers.TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.tokens[userID]
	if !ok {
		return nil, fmt.Errorf("token not found for user: %s", userID)
	}

	// Check if expired (and no refresh token)
	if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(time.Now()) && token.RefreshToken == "" {
		return nil, fmt.Errorf("token expired for user: %s", userID)
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

// SaveClient saves a registered client
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

// ValidateClientSecret validates a client's secret
func (s *Store) ValidateClientSecret(clientID, clientSecret string) error {
	client, err := s.GetClient(clientID)
	if err != nil {
		return err
	}

	// For public clients, no secret validation needed
	if client.ClientType == "public" {
		return nil
	}

	// For confidential clients, validate the secret hash
	// Note: In production, use bcrypt.CompareHashAndPassword
	if client.ClientSecretHash != clientSecret {
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

	// Check if expired
	if !state.ExpiresAt.IsZero() && state.ExpiresAt.Before(time.Now()) {
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

// GetAuthorizationCode retrieves an authorization code
func (s *Store) GetAuthorizationCode(code string) (*storage.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, fmt.Errorf("authorization code not found")
	}

	// Check if expired
	if !authCode.ExpiresAt.IsZero() && authCode.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("authorization code expired")
	}

	// Check if already used
	if authCode.Used {
		return nil, fmt.Errorf("authorization code already used")
	}

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

	now := time.Now()
	cleaned := 0

	// Cleanup expired tokens
	for userID, token := range s.tokens {
		if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(now) && token.RefreshToken == "" {
			delete(s.tokens, userID)
			delete(s.userInfo, userID)
			cleaned++
		}
	}

	// Cleanup expired authorization states
	for stateID, state := range s.authStates {
		if !state.ExpiresAt.IsZero() && state.ExpiresAt.Before(now) {
			delete(s.authStates, stateID)
			cleaned++
		}
	}

	// Cleanup expired authorization codes
	for code, authCode := range s.authCodes {
		if !authCode.ExpiresAt.IsZero() && authCode.ExpiresAt.Before(now) {
			delete(s.authCodes, code)
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

