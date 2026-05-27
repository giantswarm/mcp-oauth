// Package mock provides mock implementations of storage interfaces for testing.
package mock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TokenStore is a mock implementation of storage.TokenStore for testing
type TokenStore struct {
	mu                     sync.RWMutex
	tokens                 map[string]*oauth2.Token
	userInfo               map[string]*storage.UserInfo
	refreshTokens          map[string]refreshTokenInfo
	SaveTokenFunc          func(ctx context.Context, userID string, token *oauth2.Token) error
	GetTokenFunc           func(ctx context.Context, userID string) (*oauth2.Token, error)
	DeleteTokenFunc        func(ctx context.Context, userID string) error
	SaveUserInfoFunc       func(ctx context.Context, userID string, info *storage.UserInfo) error
	GetUserInfoFunc        func(ctx context.Context, userID string) (*storage.UserInfo, error)
	SaveRefreshFunc        func(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error
	GetRefreshFunc         func(ctx context.Context, refreshToken string) (string, error)
	DeleteRefreshFunc      func(ctx context.Context, refreshToken string) error
	AtomicGetAndDeleteFunc func(ctx context.Context, refreshToken string) (string, string, *oauth2.Token, error)
	CallCounts             map[string]int
}

type refreshTokenInfo struct {
	userID    string
	clientID  string
	expiresAt time.Time
}

// NewTokenStore creates a new mock token store
func NewTokenStore() *TokenStore {
	m := &TokenStore{
		tokens:        make(map[string]*oauth2.Token),
		userInfo:      make(map[string]*storage.UserInfo),
		refreshTokens: make(map[string]refreshTokenInfo),
		CallCounts:    make(map[string]int),
	}

	m.initDefaultFuncs()
	return m
}

// initDefaultFuncs initializes the default function implementations for TokenStore.
func (m *TokenStore) initDefaultFuncs() {
	m.SaveTokenFunc = m.defaultSaveToken
	m.GetTokenFunc = m.defaultGetToken
	m.DeleteTokenFunc = m.defaultDeleteToken
	m.SaveUserInfoFunc = m.defaultSaveUserInfo
	m.GetUserInfoFunc = m.defaultGetUserInfo
	m.SaveRefreshFunc = m.defaultSaveRefresh
	m.GetRefreshFunc = m.defaultGetRefresh
	m.DeleteRefreshFunc = m.defaultDeleteRefresh
	m.AtomicGetAndDeleteFunc = m.defaultAtomicGetAndDelete
}

func (m *TokenStore) defaultSaveToken(_ context.Context, userID string, token *oauth2.Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[userID] = token
	return nil
}

func (m *TokenStore) defaultGetToken(_ context.Context, userID string) (*oauth2.Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, ok := m.tokens[userID]
	if !ok {
		return nil, storage.ErrTokenNotFound
	}
	return token, nil
}

func (m *TokenStore) defaultDeleteToken(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, userID)
	return nil
}

func (m *TokenStore) defaultSaveUserInfo(_ context.Context, userID string, info *storage.UserInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userInfo[userID] = info
	return nil
}

func (m *TokenStore) defaultGetUserInfo(_ context.Context, userID string) (*storage.UserInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.userInfo[userID]
	if !ok {
		return nil, storage.ErrUserInfoNotFound
	}
	return info, nil
}

func (m *TokenStore) defaultSaveRefresh(_ context.Context, refreshToken, userID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[refreshToken] = refreshTokenInfo{
		userID:    userID,
		expiresAt: expiresAt,
	}
	return nil
}

func (m *TokenStore) defaultGetRefresh(_ context.Context, refreshToken string) (string, error) {
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

func (m *TokenStore) defaultDeleteRefresh(_ context.Context, refreshToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, refreshToken)
	return nil
}

func (m *TokenStore) defaultAtomicGetAndDelete(_ context.Context, refreshToken string) (string, string, *oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.refreshTokens[refreshToken]
	if !ok {
		return "", "", nil, fmt.Errorf("%w: "+storage.ErrMsgRefreshTokenNotFoundOrUsed, storage.ErrTokenNotFound)
	}

	if !info.expiresAt.IsZero() && time.Now().After(info.expiresAt) {
		return "", "", nil, fmt.Errorf("%w: refresh token expired", storage.ErrTokenExpired)
	}

	token, ok := m.tokens[refreshToken]
	if !ok {
		return "", "", nil, fmt.Errorf("%w: provider token not found", storage.ErrTokenNotFound)
	}

	// Atomic delete
	delete(m.refreshTokens, refreshToken)
	delete(m.tokens, refreshToken)

	return info.userID, info.clientID, token, nil
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
func (m *TokenStore) SaveUserInfo(ctx context.Context, userID string, info *storage.UserInfo) error {
	m.CallCounts["SaveUserInfo"]++
	return m.SaveUserInfoFunc(ctx, userID, info)
}

// GetUserInfo retrieves user information
func (m *TokenStore) GetUserInfo(ctx context.Context, userID string) (*storage.UserInfo, error) {
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

// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
// This prevents race conditions in refresh token rotation and reuse detection.
// Returns the userID, clientID, and provider token if successful.
//
// SECURITY: This operation is atomic - only ONE concurrent request can succeed.
// SECURITY: Returns clientID for client binding validation per OAuth 2.1 Section 6.
func (m *TokenStore) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (string, string, *oauth2.Token, error) {
	m.CallCounts["AtomicGetAndDeleteRefreshToken"]++
	return m.AtomicGetAndDeleteFunc(ctx, refreshToken)
}

// SetRefreshTokenClientID sets the clientID for a refresh token.
// This is a test helper for setting up refresh tokens with client binding.
func (m *TokenStore) SetRefreshTokenClientID(refreshToken, clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.refreshTokens[refreshToken]; ok {
		info.clientID = clientID
		m.refreshTokens[refreshToken] = info
	}
}

// SaveRefreshTokenWithClientID saves a refresh token with client binding.
// This is a test helper that combines SaveRefreshToken with client ID.
func (m *TokenStore) SaveRefreshTokenWithClientID(_ context.Context, refreshToken, userID, clientID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[refreshToken] = refreshTokenInfo{
		userID:    userID,
		clientID:  clientID,
		expiresAt: expiresAt,
	}
	return nil
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
	DeleteClientFunc   func(ctx context.Context, clientID string) error
	ListClientsFunc    func(ctx context.Context) ([]*storage.Client, error)
	CheckIPLimitFunc   func(ctx context.Context, ip string, maxClientsPerIP int) error
	CallCounts         map[string]int
}

// NewClientStore creates a new mock client store
func NewClientStore() *ClientStore {
	m := &ClientStore{
		clients:         make(map[string]*storage.Client),
		ipRegistrations: make(map[string]int),
		CallCounts:      make(map[string]int),
	}

	m.initDefaultFuncs()
	return m
}

// initDefaultFuncs initializes the default function implementations for ClientStore.
func (m *ClientStore) initDefaultFuncs() {
	m.SaveClientFunc = m.defaultSaveClient
	m.GetClientFunc = m.defaultGetClient
	m.ValidateSecretFunc = m.defaultValidateSecret
	m.DeleteClientFunc = m.defaultDeleteClient
	m.ListClientsFunc = m.defaultListClients
	m.CheckIPLimitFunc = m.defaultCheckIPLimit
}

func (m *ClientStore) defaultSaveClient(_ context.Context, client *storage.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.ClientID] = client
	return nil
}

func (m *ClientStore) defaultGetClient(_ context.Context, clientID string) (*storage.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[clientID]
	if !ok {
		return nil, storage.ErrClientNotFound
	}
	return client, nil
}

// dummyHash is a pre-computed bcrypt hash for non-existent clients (bcrypt hash of "test").
// This ensures we always perform a bcrypt comparison even if client doesn't exist.
const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func (m *ClientStore) defaultValidateSecret(_ context.Context, clientID, clientSecret string) error {
	// SECURITY: Always perform constant-time operations to prevent timing attacks
	// that could reveal whether a client ID exists or not
	m.mu.RLock()
	client, ok := m.clients[clientID]
	m.mu.RUnlock()

	hashToCompare, isPublicClient := m.getHashAndClientType(client, ok)

	// ALWAYS perform bcrypt comparison (constant-time by design)
	// This prevents timing attacks based on whether we skip the comparison
	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(clientSecret))

	return m.evaluateValidation(ok, isPublicClient, bcryptErr)
}

func (m *ClientStore) getHashAndClientType(client *storage.Client, found bool) (string, bool) {
	if !found {
		return dummyHash, false
	}
	if client.IsPublic() {
		return dummyHash, true
	}
	if client.ClientSecretHash != "" {
		return client.ClientSecretHash, false
	}
	return dummyHash, false
}

func (m *ClientStore) evaluateValidation(clientFound, isPublicClient bool, bcryptErr error) error {
	// For public clients, authentication always succeeds
	if isPublicClient && clientFound {
		return nil
	}
	// If client lookup failed, return error (but only after bcrypt comparison)
	if !clientFound {
		return fmt.Errorf("invalid client credentials")
	}
	// If bcrypt comparison failed, return error
	if bcryptErr != nil {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

func (m *ClientStore) defaultDeleteClient(_ context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[clientID]; !ok {
		return storage.ErrClientNotFound
	}
	delete(m.clients, clientID)
	return nil
}

func (m *ClientStore) defaultListClients(_ context.Context) ([]*storage.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clients := make([]*storage.Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (m *ClientStore) defaultCheckIPLimit(_ context.Context, ip string, maxClientsPerIP int) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if count := m.ipRegistrations[ip]; count >= maxClientsPerIP {
		return fmt.Errorf("IP registration limit exceeded")
	}
	return nil
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

// DeleteClient removes a registered client by ID.
func (m *ClientStore) DeleteClient(ctx context.Context, clientID string) error {
	m.CallCounts["DeleteClient"]++
	return m.DeleteClientFunc(ctx, clientID)
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

// NewFlowStore creates a new mock flow store
func NewFlowStore() *FlowStore {
	m := &FlowStore{
		authStates:           make(map[string]*storage.AuthorizationState),
		authStatesByProvider: make(map[string]*storage.AuthorizationState),
		authCodes:            make(map[string]*storage.AuthorizationCode),
		CallCounts:           make(map[string]int),
	}

	m.initDefaultFlowFuncs()
	return m
}

// initDefaultFlowFuncs initializes the default function implementations for FlowStore.
func (m *FlowStore) initDefaultFlowFuncs() {
	m.SaveAuthStateFunc = m.defaultSaveAuthState
	m.GetAuthStateFunc = m.defaultGetAuthState
	m.GetAuthStateByProviderFunc = m.defaultGetAuthStateByProvider
	m.DeleteAuthStateFunc = m.defaultDeleteAuthState
	m.SaveAuthCodeFunc = m.defaultSaveAuthCode
	m.GetAuthCodeFunc = m.defaultGetAuthCode
	m.DeleteAuthCodeFunc = m.defaultDeleteAuthCode
	m.AtomicCheckAndMarkCodeUsedFunc = m.defaultAtomicCheckAndMarkCodeUsed
}

func (m *FlowStore) defaultSaveAuthState(_ context.Context, state *storage.AuthorizationState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authStates[state.StateID] = state
	m.authStatesByProvider[state.ProviderState] = state
	return nil
}

func (m *FlowStore) defaultGetAuthState(_ context.Context, stateID string) (*storage.AuthorizationState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.authStates[stateID]
	if !ok {
		return nil, storage.ErrAuthorizationStateNotFound
	}
	if state.HasExpired() {
		return nil, storage.ErrTokenExpired
	}
	return state, nil
}

func (m *FlowStore) defaultGetAuthStateByProvider(_ context.Context, providerState string) (*storage.AuthorizationState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.authStatesByProvider[providerState]
	if !ok {
		return nil, storage.ErrAuthorizationStateNotFound
	}
	return state, nil
}

func (m *FlowStore) defaultDeleteAuthState(_ context.Context, stateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.authStates[stateID]; ok {
		delete(m.authStatesByProvider, state.ProviderState)
	}
	delete(m.authStates, stateID)
	return nil
}

func (m *FlowStore) defaultSaveAuthCode(_ context.Context, code *storage.AuthorizationCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[code.Code] = code
	return nil
}

func (m *FlowStore) defaultGetAuthCode(_ context.Context, code string) (*storage.AuthorizationCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	authCode, ok := m.authCodes[code]
	if !ok {
		return nil, storage.ErrAuthorizationCodeNotFound
	}
	if authCode.HasExpired() {
		return nil, storage.ErrTokenExpired
	}
	return authCode, nil
}

func (m *FlowStore) defaultDeleteAuthCode(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.authCodes, code)
	return nil
}

func (m *FlowStore) defaultAtomicCheckAndMarkCodeUsed(_ context.Context, code string) (*storage.AuthorizationCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	authCode, ok := m.authCodes[code]
	if !ok {
		return nil, storage.ErrAuthorizationCodeNotFound
	}
	if authCode.HasExpired() {
		return nil, storage.ErrTokenExpired
	}
	if authCode.Used {
		return authCode, storage.ErrAuthorizationCodeUsed
	}
	authCode.Used = true
	return authCode, nil
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
