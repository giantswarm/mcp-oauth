// Package mock provides mock implementations of storage interfaces for testing.
package mock

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// MockTokenStore is a mock implementation of TokenStore for testing
type MockTokenStore struct {
	mu                sync.RWMutex
	tokens            map[string]*oauth2.Token
	userInfo          map[string]*providers.UserInfo
	refreshTokens     map[string]refreshTokenInfo
	SaveTokenFunc     func(userID string, token *oauth2.Token) error
	GetTokenFunc      func(userID string) (*oauth2.Token, error)
	DeleteTokenFunc   func(userID string) error
	SaveUserInfoFunc  func(userID string, info *providers.UserInfo) error
	GetUserInfoFunc   func(userID string) (*providers.UserInfo, error)
	SaveRefreshFunc   func(refreshToken, userID string, expiresAt time.Time) error
	GetRefreshFunc    func(refreshToken string) (string, error)
	DeleteRefreshFunc func(refreshToken string) error
	CallCounts        map[string]int
}

type refreshTokenInfo struct {
	userID    string
	expiresAt time.Time
}

// NewMockTokenStore creates a new mock token store
func NewMockTokenStore() *MockTokenStore {
	m := &MockTokenStore{
		tokens:        make(map[string]*oauth2.Token),
		userInfo:      make(map[string]*providers.UserInfo),
		refreshTokens: make(map[string]refreshTokenInfo),
		CallCounts:    make(map[string]int),
	}

	// Set default implementations
	m.SaveTokenFunc = func(userID string, token *oauth2.Token) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tokens[userID] = token
		return nil
	}

	m.GetTokenFunc = func(userID string) (*oauth2.Token, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		token, ok := m.tokens[userID]
		if !ok {
			return nil, fmt.Errorf("token not found")
		}
		return token, nil
	}

	m.DeleteTokenFunc = func(userID string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.tokens, userID)
		return nil
	}

	m.SaveUserInfoFunc = func(userID string, info *providers.UserInfo) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.userInfo[userID] = info
		return nil
	}

	m.GetUserInfoFunc = func(userID string) (*providers.UserInfo, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		info, ok := m.userInfo[userID]
		if !ok {
			return nil, fmt.Errorf("user info not found")
		}
		return info, nil
	}

	m.SaveRefreshFunc = func(refreshToken, userID string, expiresAt time.Time) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.refreshTokens[refreshToken] = refreshTokenInfo{
			userID:    userID,
			expiresAt: expiresAt,
		}
		return nil
	}

	m.GetRefreshFunc = func(refreshToken string) (string, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		info, ok := m.refreshTokens[refreshToken]
		if !ok {
			return "", fmt.Errorf("refresh token not found")
		}
		if !info.expiresAt.IsZero() && time.Now().After(info.expiresAt) {
			return "", fmt.Errorf("refresh token expired")
		}
		return info.userID, nil
	}

	m.DeleteRefreshFunc = func(refreshToken string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.refreshTokens, refreshToken)
		return nil
	}

	return m
}

// SaveToken saves a token for a user
func (m *MockTokenStore) SaveToken(userID string, token *oauth2.Token) error {
	m.CallCounts["SaveToken"]++
	return m.SaveTokenFunc(userID, token)
}

// GetToken retrieves a token for a user
func (m *MockTokenStore) GetToken(userID string) (*oauth2.Token, error) {
	m.CallCounts["GetToken"]++
	return m.GetTokenFunc(userID)
}

// DeleteToken removes a token for a user
func (m *MockTokenStore) DeleteToken(userID string) error {
	m.CallCounts["DeleteToken"]++
	return m.DeleteTokenFunc(userID)
}

// SaveUserInfo saves user information
func (m *MockTokenStore) SaveUserInfo(userID string, info *providers.UserInfo) error {
	m.CallCounts["SaveUserInfo"]++
	return m.SaveUserInfoFunc(userID, info)
}

// GetUserInfo retrieves user information
func (m *MockTokenStore) GetUserInfo(userID string) (*providers.UserInfo, error) {
	m.CallCounts["GetUserInfo"]++
	return m.GetUserInfoFunc(userID)
}

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
func (m *MockTokenStore) SaveRefreshToken(refreshToken, userID string, expiresAt time.Time) error {
	m.CallCounts["SaveRefreshToken"]++
	return m.SaveRefreshFunc(refreshToken, userID, expiresAt)
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token
func (m *MockTokenStore) GetRefreshTokenInfo(refreshToken string) (string, error) {
	m.CallCounts["GetRefreshTokenInfo"]++
	return m.GetRefreshFunc(refreshToken)
}

// DeleteRefreshToken removes a refresh token
func (m *MockTokenStore) DeleteRefreshToken(refreshToken string) error {
	m.CallCounts["DeleteRefreshToken"]++
	return m.DeleteRefreshFunc(refreshToken)
}

// ResetCallCounts resets all call counters
func (m *MockTokenStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// MockClientStore is a mock implementation of ClientStore for testing
type MockClientStore struct {
	mu                 sync.RWMutex
	clients            map[string]*storage.Client
	ipRegistrations    map[string]int
	SaveClientFunc     func(client *storage.Client) error
	GetClientFunc      func(clientID string) (*storage.Client, error)
	ValidateSecretFunc func(clientID, clientSecret string) error
	ListClientsFunc    func() ([]*storage.Client, error)
	CheckIPLimitFunc   func(ip string, maxClientsPerIP int) error
	CallCounts         map[string]int
}

// NewMockClientStore creates a new mock client store
func NewMockClientStore() *MockClientStore {
	m := &MockClientStore{
		clients:         make(map[string]*storage.Client),
		ipRegistrations: make(map[string]int),
		CallCounts:      make(map[string]int),
	}

	// Set default implementations
	m.SaveClientFunc = func(client *storage.Client) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.clients[client.ClientID] = client
		return nil
	}

	m.GetClientFunc = func(clientID string) (*storage.Client, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		client, ok := m.clients[clientID]
		if !ok {
			return nil, fmt.Errorf("client not found")
		}
		return client, nil
	}

	m.ValidateSecretFunc = func(clientID, clientSecret string) error {
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

	m.ListClientsFunc = func() ([]*storage.Client, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		clients := make([]*storage.Client, 0, len(m.clients))
		for _, client := range m.clients {
			clients = append(clients, client)
		}
		return clients, nil
	}

	m.CheckIPLimitFunc = func(ip string, maxClientsPerIP int) error {
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
func (m *MockClientStore) SaveClient(client *storage.Client) error {
	m.CallCounts["SaveClient"]++
	return m.SaveClientFunc(client)
}

// GetClient retrieves a client by ID
func (m *MockClientStore) GetClient(clientID string) (*storage.Client, error) {
	m.CallCounts["GetClient"]++
	return m.GetClientFunc(clientID)
}

// ValidateClientSecret validates a client's secret
func (m *MockClientStore) ValidateClientSecret(clientID, clientSecret string) error {
	m.CallCounts["ValidateClientSecret"]++
	return m.ValidateSecretFunc(clientID, clientSecret)
}

// ListClients lists all registered clients
func (m *MockClientStore) ListClients() ([]*storage.Client, error) {
	m.CallCounts["ListClients"]++
	return m.ListClientsFunc()
}

// CheckIPLimit checks if an IP has reached the client registration limit
func (m *MockClientStore) CheckIPLimit(ip string, maxClientsPerIP int) error {
	m.CallCounts["CheckIPLimit"]++
	return m.CheckIPLimitFunc(ip, maxClientsPerIP)
}

// ResetCallCounts resets all call counters
func (m *MockClientStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// MockFlowStore is a mock implementation of FlowStore for testing
type MockFlowStore struct {
	mu                         sync.RWMutex
	authStates                 map[string]*storage.AuthorizationState
	authStatesByProvider       map[string]*storage.AuthorizationState
	authCodes                  map[string]*storage.AuthorizationCode
	SaveAuthStateFunc          func(state *storage.AuthorizationState) error
	GetAuthStateFunc           func(stateID string) (*storage.AuthorizationState, error)
	GetAuthStateByProviderFunc func(providerState string) (*storage.AuthorizationState, error)
	DeleteAuthStateFunc        func(stateID string) error
	SaveAuthCodeFunc           func(code *storage.AuthorizationCode) error
	GetAuthCodeFunc            func(code string) (*storage.AuthorizationCode, error)
	DeleteAuthCodeFunc         func(code string) error
	CallCounts                 map[string]int
}

// NewMockFlowStore creates a new mock flow store
func NewMockFlowStore() *MockFlowStore {
	m := &MockFlowStore{
		authStates:           make(map[string]*storage.AuthorizationState),
		authStatesByProvider: make(map[string]*storage.AuthorizationState),
		authCodes:            make(map[string]*storage.AuthorizationCode),
		CallCounts:           make(map[string]int),
	}

	// Set default implementations
	m.SaveAuthStateFunc = func(state *storage.AuthorizationState) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.authStates[state.StateID] = state
		m.authStatesByProvider[state.ProviderState] = state
		return nil
	}

	m.GetAuthStateFunc = func(stateID string) (*storage.AuthorizationState, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		state, ok := m.authStates[stateID]
		if !ok {
			return nil, fmt.Errorf("authorization state not found")
		}
		if !state.ExpiresAt.IsZero() && time.Now().After(state.ExpiresAt) {
			return nil, fmt.Errorf("authorization state expired")
		}
		return state, nil
	}

	m.GetAuthStateByProviderFunc = func(providerState string) (*storage.AuthorizationState, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		state, ok := m.authStatesByProvider[providerState]
		if !ok {
			return nil, fmt.Errorf("authorization state not found")
		}
		return state, nil
	}

	m.DeleteAuthStateFunc = func(stateID string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if state, ok := m.authStates[stateID]; ok {
			delete(m.authStatesByProvider, state.ProviderState)
		}
		delete(m.authStates, stateID)
		return nil
	}

	m.SaveAuthCodeFunc = func(code *storage.AuthorizationCode) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.authCodes[code.Code] = code
		return nil
	}

	m.GetAuthCodeFunc = func(code string) (*storage.AuthorizationCode, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		authCode, ok := m.authCodes[code]
		if !ok {
			return nil, fmt.Errorf("authorization code not found")
		}
		if !authCode.ExpiresAt.IsZero() && time.Now().After(authCode.ExpiresAt) {
			return nil, fmt.Errorf("authorization code expired")
		}
		return authCode, nil
	}

	m.DeleteAuthCodeFunc = func(code string) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.authCodes, code)
		return nil
	}

	return m
}

// SaveAuthorizationState saves the state of an ongoing authorization flow
func (m *MockFlowStore) SaveAuthorizationState(state *storage.AuthorizationState) error {
	m.CallCounts["SaveAuthorizationState"]++
	return m.SaveAuthStateFunc(state)
}

// GetAuthorizationState retrieves an authorization state by client state
func (m *MockFlowStore) GetAuthorizationState(stateID string) (*storage.AuthorizationState, error) {
	m.CallCounts["GetAuthorizationState"]++
	return m.GetAuthStateFunc(stateID)
}

// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
func (m *MockFlowStore) GetAuthorizationStateByProviderState(providerState string) (*storage.AuthorizationState, error) {
	m.CallCounts["GetAuthorizationStateByProviderState"]++
	return m.GetAuthStateByProviderFunc(providerState)
}

// DeleteAuthorizationState removes an authorization state
func (m *MockFlowStore) DeleteAuthorizationState(stateID string) error {
	m.CallCounts["DeleteAuthorizationState"]++
	return m.DeleteAuthStateFunc(stateID)
}

// SaveAuthorizationCode saves an issued authorization code
func (m *MockFlowStore) SaveAuthorizationCode(code *storage.AuthorizationCode) error {
	m.CallCounts["SaveAuthorizationCode"]++
	return m.SaveAuthCodeFunc(code)
}

// GetAuthorizationCode retrieves an authorization code
func (m *MockFlowStore) GetAuthorizationCode(code string) (*storage.AuthorizationCode, error) {
	m.CallCounts["GetAuthorizationCode"]++
	return m.GetAuthCodeFunc(code)
}

// DeleteAuthorizationCode removes an authorization code
func (m *MockFlowStore) DeleteAuthorizationCode(code string) error {
	m.CallCounts["DeleteAuthorizationCode"]++
	return m.DeleteAuthCodeFunc(code)
}

// ResetCallCounts resets all call counters
func (m *MockFlowStore) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}
