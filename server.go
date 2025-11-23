package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"golang.org/x/crypto/bcrypt"
)

// Server implements the OAuth 2.1 server logic (provider-agnostic).
// It coordinates the OAuth flow using a Provider and storage backends.
type Server struct {
	provider    providers.Provider
	tokenStore  storage.TokenStore
	clientStore storage.ClientStore
	flowStore   storage.FlowStore
	encryptor   *security.Encryptor
	auditor     *security.Auditor
	rateLimiter *security.RateLimiter
	logger      *slog.Logger
	config      *ServerConfig
}

// ServerConfig holds OAuth server configuration
type ServerConfig struct {
	// Issuer is the server's issuer identifier (base URL)
	Issuer string

	// AuthorizationCodeTTL is how long authorization codes are valid
	AuthorizationCodeTTL int64 // seconds, default: 600 (10 minutes)

	// AccessTokenTTL is how long access tokens are valid
	AccessTokenTTL int64 // seconds, default: 3600 (1 hour)

	// RefreshTokenTTL is how long refresh tokens are valid
	RefreshTokenTTL int64 // seconds, default: 7776000 (90 days)

	// RequirePKCE enforces PKCE for all clients
	RequirePKCE bool // default: true

	// AllowRefreshTokenRotation enables refresh token rotation (OAuth 2.1)
	AllowRefreshTokenRotation bool // default: true
}

// NewServer creates a new OAuth server
func NewServer(
	provider providers.Provider,
	tokenStore storage.TokenStore,
	clientStore storage.ClientStore,
	flowStore storage.FlowStore,
	config *ServerConfig,
	logger *slog.Logger,
) (*Server, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if tokenStore == nil {
		return nil, fmt.Errorf("token store is required")
	}
	if clientStore == nil {
		return nil, fmt.Errorf("client store is required")
	}
	if flowStore == nil {
		return nil, fmt.Errorf("flow store is required")
	}
	if config == nil {
		config = &ServerConfig{}
	}

	// Set defaults
	if config.AuthorizationCodeTTL == 0 {
		config.AuthorizationCodeTTL = 600 // 10 minutes
	}
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 3600 // 1 hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7776000 // 90 days
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		provider:    provider,
		tokenStore:  tokenStore,
		clientStore: clientStore,
		flowStore:   flowStore,
		config:      config,
		logger:      logger,
	}, nil
}

// SetEncryptor sets the token encryptor
func (s *Server) SetEncryptor(enc *security.Encryptor) {
	s.encryptor = enc
}

// SetAuditor sets the security auditor
func (s *Server) SetAuditor(aud *security.Auditor) {
	s.auditor = aud
}

// SetRateLimiter sets the rate limiter
func (s *Server) SetRateLimiter(rl *security.RateLimiter) {
	s.rateLimiter = rl
}

// ValidateToken validates an access token with the provider
func (s *Server) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// Check rate limit
	if s.rateLimiter != nil && !s.rateLimiter.Allow(accessToken) {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Validate with provider
	userInfo, err := s.provider.ValidateToken(ctx, accessToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", "", "", err.Error())
		}
		return nil, err
	}

	// Store user info
	if err := s.tokenStore.SaveUserInfo(userInfo.ID, userInfo); err != nil {
		s.logger.Warn("Failed to save user info", "error", err)
	}

	return userInfo, nil
}

// StartAuthorizationFlow starts a new OAuth authorization flow
func (s *Server) StartAuthorizationFlow(clientID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (string, error) {
	// Validate client
	client, err := s.clientStore.GetClient(clientID)
	if err != nil {
		return "", fmt.Errorf("invalid client: %w", err)
	}

	// Validate redirect URI
	if err := s.validateRedirectURI(client, redirectURI); err != nil {
		return "", err
	}

	// Generate state
	state, err := generateToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Generate provider state
	providerState, err := generateToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate provider state: %w", err)
	}

	// Save authorization state
	authState := &storage.AuthorizationState{
		StateID:             state,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ProviderState:       providerState,
	}
	if err := s.flowStore.SaveAuthorizationState(authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Generate authorization URL with provider
	authURL := s.provider.AuthorizationURL(providerState, &providers.AuthOptions{
		Scopes:              parseScopes(scope),
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})

	return authURL, nil
}

// validateRedirectURI validates that a redirect URI is registered for the client
func (s *Server) validateRedirectURI(client *storage.Client, redirectURI string) error {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return fmt.Errorf("redirect URI not registered for client")
}

// generateToken generates a cryptographically secure random token
func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// parseScopes parses a space-separated scope string into a slice
func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	// Simple split by space
	var scopes []string
	current := ""
	for _, ch := range scope {
		if ch == ' ' {
			if current != "" {
				scopes = append(scopes, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		scopes = append(scopes, current)
	}
	return scopes
}

// HandleProviderCallback handles the callback from the OAuth provider
func (s *Server) HandleProviderCallback(ctx context.Context, providerState, code string) (*storage.AuthorizationCode, error) {
	// Get authorization state
	authState, err := s.flowStore.GetAuthorizationState(providerState)
	if err != nil {
		return nil, fmt.Errorf("invalid state: %w", err)
	}

	// Delete authorization state (one-time use)
	s.flowStore.DeleteAuthorizationState(providerState)

	// Exchange code with provider
	providerToken, err := s.provider.ExchangeCode(ctx, code, &providers.ExchangeOptions{
		RedirectURI:  authState.RedirectURI,
		CodeVerifier: "", // PKCE verification happens at token endpoint
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code with provider: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.provider.ValidateToken(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Save user info and token
	if err := s.tokenStore.SaveUserInfo(userInfo.ID, userInfo); err != nil {
		s.logger.Warn("Failed to save user info", "error", err)
	}
	if err := s.tokenStore.SaveToken(userInfo.ID, providerToken); err != nil {
		s.logger.Warn("Failed to save provider token", "error", err)
	}

	// Generate authorization code
	authCode, err := generateToken(48)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Create authorization code object
	authCodeObj := &storage.AuthorizationCode{
		Code:                authCode,
		ClientID:            authState.ClientID,
		RedirectURI:         authState.RedirectURI,
		Scope:               authState.Scope,
		CodeChallenge:       authState.CodeChallenge,
		CodeChallengeMethod: authState.CodeChallengeMethod,
		UserID:              userInfo.ID,
		ProviderToken:       providerToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(s.config.AuthorizationCodeTTL) * time.Second),
		Used:                false,
	}

	// Save authorization code
	if err := s.flowStore.SaveAuthorizationCode(authCodeObj); err != nil {
		return nil, fmt.Errorf("failed to save authorization code: %w", err)
	}

	if s.auditor != nil {
		s.auditor.LogEvent(security.Event{
			Type:     "authorization_code_issued",
			UserID:   userInfo.ID,
			ClientID: authState.ClientID,
			Details: map[string]any{
				"scope": authState.Scope,
			},
		})
	}

	return authCodeObj, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*providers.TokenResponse, string, error) {
	// Get authorization code
	authCode, err := s.flowStore.GetAuthorizationCode(code)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "invalid_authorization_code")
		}
		return nil, "", fmt.Errorf("invalid authorization code")
	}

	// Validate authorization code hasn't been used
	if authCode.Used {
		if s.auditor != nil {
			s.auditor.LogAuthFailure(authCode.UserID, clientID, "", "authorization_code_reuse")
		}
		// Delete the code and revoke associated tokens (security measure)
		s.flowStore.DeleteAuthorizationCode(code)
		return nil, "", fmt.Errorf("authorization code already used")
	}

	// Validate client ID matches
	if authCode.ClientID != clientID {
		return nil, "", fmt.Errorf("client ID mismatch")
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		return nil, "", fmt.Errorf("redirect URI mismatch")
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if err := s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier); err != nil {
			if s.auditor != nil {
				s.auditor.LogAuthFailure(authCode.UserID, clientID, "", fmt.Sprintf("pkce_validation_failed: %v", err))
			}
			return nil, "", fmt.Errorf("PKCE validation failed: %w", err)
		}
	}

	// Mark code as used
	authCode.Used = true
	s.flowStore.SaveAuthorizationCode(authCode)

	// Generate new access token
	accessToken, err := generateToken(48)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := generateToken(48)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create token response
	tokenResponse := &providers.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.AccessTokenTTL) * time.Second),
		Scopes:       parseScopes(authCode.Scope),
		TokenType:    "Bearer",
	}

	// Store access token -> provider token mapping
	if err := s.tokenStore.SaveToken(accessToken, authCode.ProviderToken); err != nil {
		s.logger.Warn("Failed to save access token mapping", "error", err)
	}

	// Store refresh token -> user mapping (for refresh flow)
	if err := s.tokenStore.SaveToken(refreshToken, authCode.ProviderToken); err != nil {
		s.logger.Warn("Failed to save refresh token", "error", err)
	}

	// Delete authorization code (one-time use)
	s.flowStore.DeleteAuthorizationCode(code)

	if s.auditor != nil {
		s.auditor.LogTokenIssued(authCode.UserID, clientID, "", authCode.Scope)
	}

	return tokenResponse, authCode.Scope, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken, clientID string) (*providers.TokenResponse, error) {
	// Get provider token using refresh token
	providerToken, err := s.tokenStore.GetToken(refreshToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "invalid_refresh_token")
		}
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Refresh token with provider
	newProviderToken, err := s.provider.RefreshToken(ctx, providerToken.RefreshToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("provider_refresh_failed: %v", err))
		}
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// Generate new access token
	newAccessToken, err := generateToken(48)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token (rotation per OAuth 2.1)
	var newRefreshToken string
	if s.config.AllowRefreshTokenRotation {
		newRefreshToken, err = generateToken(48)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
		// Invalidate old refresh token
		s.tokenStore.DeleteToken(refreshToken)
	} else {
		newRefreshToken = refreshToken
	}

	// Create token response
	tokenResponse := &providers.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.AccessTokenTTL) * time.Second),
		Scopes:       newProviderToken.Scopes,
		TokenType:    "Bearer",
	}

	// Store new tokens
	if err := s.tokenStore.SaveToken(newAccessToken, newProviderToken); err != nil {
		s.logger.Warn("Failed to save new access token", "error", err)
	}
	if err := s.tokenStore.SaveToken(newRefreshToken, newProviderToken); err != nil {
		s.logger.Warn("Failed to save new refresh token", "error", err)
	}

	if s.auditor != nil {
		s.auditor.LogTokenRefreshed("", clientID, "", s.config.AllowRefreshTokenRotation)
	}

	return tokenResponse, nil
}

// RevokeToken revokes a token (access or refresh)
func (s *Server) RevokeToken(ctx context.Context, token, clientID string) error {
	// Get provider token
	providerToken, err := s.tokenStore.GetToken(token)
	if err != nil {
		// Token not found, but revocation should succeed per RFC 7009
		return nil
	}

	// Revoke at provider
	if providerToken.AccessToken != "" {
		if err := s.provider.RevokeToken(ctx, providerToken.AccessToken); err != nil {
			s.logger.Warn("Failed to revoke token at provider", "error", err)
			// Continue with local deletion even if provider revocation fails
		}
	}

	// Delete locally
	if err := s.tokenStore.DeleteToken(token); err != nil {
		s.logger.Warn("Failed to delete token locally", "error", err)
	}

	if s.auditor != nil {
		s.auditor.LogTokenRevoked("", clientID, "", "access_or_refresh")
	}

	return nil
}

// validatePKCE validates the PKCE code verifier against the challenge
func (s *Server) validatePKCE(challenge, method, verifier string) error {
	if challenge == "" {
		// No PKCE required for this flow
		return nil
	}

	if verifier == "" {
		return fmt.Errorf("code_verifier is required when code_challenge is present")
	}

	// Validate verifier length (43-128 chars per RFC 7636)
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be between 43 and 128 characters")
	}

	// Compute challenge from verifier
	var computedChallenge string
	if method == "S256" {
		hash := sha256.Sum256([]byte(verifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
	} else {
		return fmt.Errorf("unsupported code_challenge_method: %s (only S256 is supported)", method)
	}

	// Compare challenges
	if computedChallenge != challenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

// RegisterClient registers a new OAuth client
func (s *Server) RegisterClient(clientName, clientType string, redirectURIs []string, scopes []string) (*storage.Client, string, error) {
	// Generate client ID
	clientID, err := generateToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate client ID: %w", err)
	}

	// Generate client secret for confidential clients
	var clientSecret string
	var clientSecretHash string
	
	if clientType == "" {
		clientType = "confidential"
	}

	if clientType == "confidential" {
		clientSecret, err = generateToken(48)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate client secret: %w", err)
		}
		
		// Hash the secret for storage
		hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
		}
		clientSecretHash = string(hash)
	}

	// Create client object
	client := &storage.Client{
		ClientID:                clientID,
		ClientSecretHash:        clientSecretHash,
		ClientType:              clientType,
		RedirectURIs:            redirectURIs,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scopes:                  scopes,
		CreatedAt:               time.Now(),
	}

	// Public clients use "none" auth method
	if clientType == "public" {
		client.TokenEndpointAuthMethod = "none"
	}

	// Save client
	if err := s.clientStore.SaveClient(client); err != nil {
		return nil, "", fmt.Errorf("failed to save client: %w", err)
	}

	if s.auditor != nil {
		s.auditor.LogClientRegistered(clientID, clientType, "")
	}

	s.logger.Info("Registered new OAuth client",
		"client_id", clientID,
		"client_name", clientName,
		"client_type", clientType)

	return client, clientSecret, nil
}

// ValidateClientCredentials validates client credentials for token endpoint
func (s *Server) ValidateClientCredentials(clientID, clientSecret string) error {
	return s.clientStore.ValidateClientSecret(clientID, clientSecret)
}

