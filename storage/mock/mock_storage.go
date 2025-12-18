// Package mock provides mock implementations of storage interfaces for testing.
package mock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// TokenStore is a mock implementation of storage.TokenStore for testing
type TokenStore struct {
	mu                sync.RWMutex
	tokens            map[string]*oauth2.Token
	userInfo          map[string]*providers.UserInfo
	refreshTokens     map[string]refreshTokenInfo
	SaveTokenFunc     func(ctx context.Context, userID string, token *oauth2.Token) error
	GetTokenFunc      func(ctx context.Context, userID string) (*oauth2.Token, error)
	DeleteTokenFunc   func(ctx context.Context, userID string) error
	SaveUserInfoFunc  func(ctx context.Context, userID string, info *providers.UserInfo) error
	GetUserInfoFunc   func(ctx context.Context, userID string) (*providers.UserInfo, error)
	SaveRefreshFunc   func(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error
	GetRefreshFunc    func(ctx context.Context, refreshToken string) (string, error)
	DeleteRefreshFunc func(ctx context.Context, refreshToken string) error
	CallCounts        map[string]int
}

type refreshTokenInfo struct {
	userID    string
	expiresAt time.Time
}

// MockTokenStore is an alias for TokenStore for backward compatibility.
//
// Deprecated: Use TokenStore instead.
type MockTokenStore = TokenStore

// NewMockTokenStore creates a new mock token store.
//
// Deprecated: Use NewTokenStore instead.
func NewMockTokenStore() *TokenStore {
	return NewTokenStore()
}

// NewTokenStore creates a new mock token store
func NewTokenStore() *TokenStore {
	m := &TokenStore{
		tokens:        make(map[string]*oauth2.Token),
		userInfo:      make(map[string]*providers.UserInfo),
		refreshTokens: make(map[string]refreshTokenInfo),
		CallCounts:    make(map[string]int),
	}

	// Set default implementations
	m.SaveTokenFunc = func(_ context.Context, userID string, token *oauth2.Token) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tokens[userID] = token
		return nil
	}

	m.GetTokenFunc = func(_ context.Context, userID string) (*oauth2.Token, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		token, ok := m.tokens[userID]
		if !ok {
			return nil, storage.ErrTokenNotFound
		}
		return token, nil
	}

	m.DeleteTokenFunc = func(_ context.Context, userID string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.tokens, userID)
		return nil
	}

	m.SaveUserInfoFunc = func(_ context.Context, userID string, info *providers.UserInfo) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.userInfo[userID] = info
		return nil
	}

	m.GetUserInfoFunc = func(_ context.Context, userID string) (*providers.UserInfo, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		info, ok := m.userInfo[userID]
		if !ok {
			return nil, storage.ErrUserInfoNotFound
		}
		return info, nil
	}

	m.SaveRefreshFunc = func(_ context.Context, refreshToken, userID string, expiresAt time.Time) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.refreshTokens[refreshToken] = refreshTokenInfo{
			userID:    userID,
			expiresAt: expiresAt,
		}
		return nil
	}

	m.GetRefreshFunc = func(_ context.Context, refreshToken string) (string, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		info, ok := m.refreshTokens[refreshToken]
		if !ok {
			return "", storage.ErrTokenNotFound
		}
		if !info.expiresAt.IsZero() && time.Now().After(info.expiresAt) {
			return "", storage.ErrTokenExpired
		}
		return info.userID, nil
	}

	m.DeleteRefreshFunc = func(_ context.Context, refreshToken string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.refreshTokens, refreshToken)
		return nil
	}

	return m
}

// SaveToken saves a token for a user
func (m *TokenStore) SaveToken(ctx context.Context, userID string, token *oauth2.Token) error {
	m.CallCounts["SaveToken"]++
	return m.SaveTokenFunc(ctx, userID, token)
}

// GetToken retrieves a token for a user
func (m *TokenStore) GetToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	m.CallCounts["GetToken"]++
	return m.GetTokenFunc(ctx, userID)
}

// DeleteToken removes a token for a user
func (m *TokenStore) DeleteToken(ctx context.Context, userID string) error {
	m.CallCounts["DeleteToken"]++
	return m.DeleteTokenFunc(ctx, userID)
}

// SaveUserInfo saves user information
func (m *TokenStore) SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error {
	m.CallCounts["SaveUserInfo"]++
	return m.SaveUserInfoFunc(ctx, userID, info)
}

// GetUserInfo retrieves user information
func (m *TokenStore) GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error) {
	m.CallCounts["GetUserInfo"]++
	return m.GetUserInfoFunc(ctx, userID)
}

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
func (m *TokenStore) SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error {
	m.CallCounts["SaveRefreshToken"]++
	return m.SaveRefreshFunc(ctx, refreshToken, userID, expiresAt)
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token
func (m *TokenStore) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error) {
	m.CallCounts["GetRefreshTokenInfo"]++
	return m.GetRefreshFunc(ctx, refreshToken)
}

// DeleteRefreshToken removes a refresh token
func (m *TokenStore) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	m.CallCounts["DeleteRefreshToken"]++
	return m.DeleteRefreshFunc(ctx, refreshToken)
}

// ResetCallCounts resets all call counters
func (m *TokenStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// ClientStore is a mock implementation of storage.ClientStore for testing
type ClientStore struct {
	mu                 sync.RWMutex
	clients            map[string]*storage.Client
	ipRegistrations    map[string]int
	SaveClientFunc     func(ctx context.Context, client *storage.Client) error
	GetClientFunc      func(ctx context.Context, clientID string) (*storage.Client, error)
	ValidateSecretFunc func(ctx context.Context, clientID, clientSecret string) error
	ListClientsFunc    func(ctx context.Context) ([]*storage.Client, error)
	CheckIPLimitFunc   func(ctx context.Context, ip string, maxClientsPerIP int) error
	CallCounts         map[string]int
}

// MockClientStore is an alias for ClientStore for backward compatibility.
//
// Deprecated: Use ClientStore instead.
type MockClientStore = ClientStore

// NewMockClientStore creates a new mock client store.
//
// Deprecated: Use NewClientStore instead.
func NewMockClientStore() *ClientStore {
	return NewClientStore()
}

// NewClientStore creates a new mock client store
func NewClientStore() *ClientStore {
	m := &ClientStore{
		clients:         make(map[string]*storage.Client),
		ipRegistrations: make(map[string]int),
		CallCounts:      make(map[string]int),
	}

	// Set default implementations
	m.SaveClientFunc = func(_ context.Context, client *storage.Client) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.clients[client.ClientID] = client
		return nil
	}

	m.GetClientFunc = func(_ context.Context, clientID string) (*storage.Client, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		client, ok := m.clients[clientID]
		if !ok {
			return nil, storage.ErrClientNotFound
		}
		return client, nil
	}

	m.ValidateSecretFunc = func(_ context.Context, clientID, clientSecret string) error {
		// SECURITY: Always perform constant-time operations to prevent timing attacks
		// that could reveal whether a client ID exists or not

		// Pre-computed dummy hash for non-existent clients (bcrypt hash of "test")
		// This ensures we always perform a bcrypt comparison even if client doesn't exist
		dummyHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

		m.mu.RLock()
		client, ok := m.clients[clientID]
		m.mu.RUnlock()

		// Determine which hash to use (real or dummy)
		hashToCompare := dummyHash
		isPublicClient := false

		if ok {
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
		if isPublicClient && ok {
			return nil
		}

		// If client lookup failed, return error (but only after bcrypt comparison)
		if !ok {
			return fmt.Errorf("invalid client credentials")
		}

		// If bcrypt comparison failed, return error
		if bcryptErr != nil {
			return fmt.Errorf("invalid client credentials")
		}

		return nil
	}

	m.ListClientsFunc = func(_ context.Context) ([]*storage.Client, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		clients := make([]*storage.Client, 0, len(m.clients))
		for _, client := range m.clients {
			clients = append(clients, client)
		}
		return clients, nil
	}

	m.CheckIPLimitFunc = func(_ context.Context, ip string, maxClientsPerIP int) error {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if count := m.ipRegistrations[ip]; count >= maxClientsPerIP {
			return fmt.Errorf("IP registration limit exceeded")
		}
		return nil
	}

	return m
}

// SaveClient saves a registered client
func (m *ClientStore) SaveClient(ctx context.Context, client *storage.Client) error {
	m.CallCounts["SaveClient"]++
	return m.SaveClientFunc(ctx, client)
}

// GetClient retrieves a client by ID
func (m *ClientStore) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	m.CallCounts["GetClient"]++
	return m.GetClientFunc(ctx, clientID)
}

// ValidateClientSecret validates a client's secret
func (m *ClientStore) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error {
	m.CallCounts["ValidateClientSecret"]++
	return m.ValidateSecretFunc(ctx, clientID, clientSecret)
}

// ListClients lists all registered clients
func (m *ClientStore) ListClients(ctx context.Context) ([]*storage.Client, error) {
	m.CallCounts["ListClients"]++
	return m.ListClientsFunc(ctx)
}

// CheckIPLimit checks if an IP has reached the client registration limit
func (m *ClientStore) CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) error {
	m.CallCounts["CheckIPLimit"]++
	return m.CheckIPLimitFunc(ctx, ip, maxClientsPerIP)
}

// ResetCallCounts resets all call counters
func (m *ClientStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// FlowStore is a mock implementation of storage.FlowStore for testing
type FlowStore struct {
	mu                             sync.RWMutex
	authStates                     map[string]*storage.AuthorizationState
	authStatesByProvider           map[string]*storage.AuthorizationState
	authCodes                      map[string]*storage.AuthorizationCode
	SaveAuthStateFunc              func(ctx context.Context, state *storage.AuthorizationState) error
	GetAuthStateFunc               func(ctx context.Context, stateID string) (*storage.AuthorizationState, error)
	GetAuthStateByProviderFunc     func(ctx context.Context, providerState string) (*storage.AuthorizationState, error)
	DeleteAuthStateFunc            func(ctx context.Context, stateID string) error
	SaveAuthCodeFunc               func(ctx context.Context, code *storage.AuthorizationCode) error
	GetAuthCodeFunc                func(ctx context.Context, code string) (*storage.AuthorizationCode, error)
	DeleteAuthCodeFunc             func(ctx context.Context, code string) error
	AtomicCheckAndMarkCodeUsedFunc func(ctx context.Context, code string) (*storage.AuthorizationCode, error)
	CallCounts                     map[string]int
}

// MockFlowStore is an alias for FlowStore for backward compatibility.
//
// Deprecated: Use FlowStore instead.
type MockFlowStore = FlowStore

// NewMockFlowStore creates a new mock flow store.
//
// Deprecated: Use NewFlowStore instead.
func NewMockFlowStore() *FlowStore {
	return NewFlowStore()
}

// NewFlowStore creates a new mock flow store
func NewFlowStore() *FlowStore {
	m := &FlowStore{
		authStates:           make(map[string]*storage.AuthorizationState),
		authStatesByProvider: make(map[string]*storage.AuthorizationState),
		authCodes:            make(map[string]*storage.AuthorizationCode),
		CallCounts:           make(map[string]int),
	}

	// Set default implementations
	m.SaveAuthStateFunc = func(_ context.Context, state *storage.AuthorizationState) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.authStates[state.StateID] = state
		m.authStatesByProvider[state.ProviderState] = state
		return nil
	}

	m.GetAuthStateFunc = func(_ context.Context, stateID string) (*storage.AuthorizationState, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		state, ok := m.authStates[stateID]
		if !ok {
			return nil, storage.ErrAuthorizationStateNotFound
		}
		if !state.ExpiresAt.IsZero() && time.Now().After(state.ExpiresAt) {
			return nil, storage.ErrTokenExpired
		}
		return state, nil
	}

	m.GetAuthStateByProviderFunc = func(_ context.Context, providerState string) (*storage.AuthorizationState, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		state, ok := m.authStatesByProvider[providerState]
		if !ok {
			return nil, storage.ErrAuthorizationStateNotFound
		}
		return state, nil
	}

	m.DeleteAuthStateFunc = func(_ context.Context, stateID string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if state, ok := m.authStates[stateID]; ok {
			delete(m.authStatesByProvider, state.ProviderState)
		}
		delete(m.authStates, stateID)
		return nil
	}

	m.SaveAuthCodeFunc = func(_ context.Context, code *storage.AuthorizationCode) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.authCodes[code.Code] = code
		return nil
	}

	m.GetAuthCodeFunc = func(_ context.Context, code string) (*storage.AuthorizationCode, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		authCode, ok := m.authCodes[code]
		if !ok {
			return nil, storage.ErrAuthorizationCodeNotFound
		}
		if !authCode.ExpiresAt.IsZero() && time.Now().After(authCode.ExpiresAt) {
			return nil, storage.ErrTokenExpired
		}
		return authCode, nil
	}

	m.DeleteAuthCodeFunc = func(_ context.Context, code string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.authCodes, code)
		return nil
	}

	m.AtomicCheckAndMarkCodeUsedFunc = func(_ context.Context, code string) (*storage.AuthorizationCode, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		authCode, ok := m.authCodes[code]
		if !ok {
			return nil, storage.ErrAuthorizationCodeNotFound
		}
		if !authCode.ExpiresAt.IsZero() && time.Now().After(authCode.ExpiresAt) {
			return nil, storage.ErrTokenExpired
		}
		if authCode.Used {
			return authCode, storage.ErrAuthorizationCodeUsed
		}
		authCode.Used = true
		return authCode, nil
	}

	return m
}

// SaveAuthorizationState saves the state of an ongoing authorization flow
func (m *FlowStore) SaveAuthorizationState(ctx context.Context, state *storage.AuthorizationState) error {
	m.CallCounts["SaveAuthorizationState"]++
	return m.SaveAuthStateFunc(ctx, state)
}

// GetAuthorizationState retrieves an authorization state by client state
func (m *FlowStore) GetAuthorizationState(ctx context.Context, stateID string) (*storage.AuthorizationState, error) {
	m.CallCounts["GetAuthorizationState"]++
	return m.GetAuthStateFunc(ctx, stateID)
}

// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
func (m *FlowStore) GetAuthorizationStateByProviderState(ctx context.Context, providerState string) (*storage.AuthorizationState, error) {
	m.CallCounts["GetAuthorizationStateByProviderState"]++
	return m.GetAuthStateByProviderFunc(ctx, providerState)
}

// DeleteAuthorizationState removes an authorization state
func (m *FlowStore) DeleteAuthorizationState(ctx context.Context, stateID string) error {
	m.CallCounts["DeleteAuthorizationState"]++
	return m.DeleteAuthStateFunc(ctx, stateID)
}

// SaveAuthorizationCode saves an issued authorization code
func (m *FlowStore) SaveAuthorizationCode(ctx context.Context, code *storage.AuthorizationCode) error {
	m.CallCounts["SaveAuthorizationCode"]++
	return m.SaveAuthCodeFunc(ctx, code)
}

// GetAuthorizationCode retrieves an authorization code
func (m *FlowStore) GetAuthorizationCode(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	m.CallCounts["GetAuthorizationCode"]++
	return m.GetAuthCodeFunc(ctx, code)
}

// DeleteAuthorizationCode removes an authorization code
func (m *FlowStore) DeleteAuthorizationCode(ctx context.Context, code string) error {
	m.CallCounts["DeleteAuthorizationCode"]++
	return m.DeleteAuthCodeFunc(ctx, code)
}

// AtomicCheckAndMarkAuthCodeUsed atomically checks if a code is unused and marks it as used
func (m *FlowStore) AtomicCheckAndMarkAuthCodeUsed(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	m.CallCounts["AtomicCheckAndMarkAuthCodeUsed"]++
	return m.AtomicCheckAndMarkCodeUsedFunc(ctx, code)
}

// ResetCallCounts resets all call counters
func (m *FlowStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}
