package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
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

	// TrustProxy enables trusting X-Forwarded-For and X-Real-IP headers
	// Only enable if behind a trusted reverse proxy
	TrustProxy bool // default: false

	// MaxClientsPerIP limits client registrations per IP address
	MaxClientsPerIP int // default: 10
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
// Note: Rate limiting should be done at the HTTP layer with IP address, not here with token
func (s *Server) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
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

// validateRedirectURI validates that a redirect URI is registered and secure
func (s *Server) validateRedirectURI(client *storage.Client, redirectURI string) error {
	// First check if URI is registered
	found := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("redirect URI not registered for client")
	}

	// Perform security validation on the URI
	return validateRedirectURISecurity(redirectURI, s.config.Issuer)
}

// validateRedirectURISecurity performs comprehensive security validation on redirect URIs
// per OAuth 2.0 Security Best Current Practice (BCP)
func validateRedirectURISecurity(redirectURI, serverIssuer string) error {
	// Parse the redirect URI
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %w", err)
	}

	// OAuth 2.0 Security BCP Section 4.1.3: redirect_uri MUST NOT contain fragments
	if parsed.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain fragments (security risk)")
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Reject dangerous schemes that could lead to XSS or other attacks
	dangerousSchemes := []string{"javascript", "data", "file", "vbscript", "about"}
	for _, dangerous := range dangerousSchemes {
		if scheme == dangerous {
			return fmt.Errorf("redirect_uri scheme '%s' is not allowed (security risk)", scheme)
		}
	}

	// Check if it's an HTTP(S) scheme
	isHTTP := scheme == "http" || scheme == "https"

	if isHTTP {
		hostname := strings.ToLower(parsed.Hostname())

		// Check if it's a loopback address (allowed for development)
		isLoopback := hostname == "localhost" || hostname == "127.0.0.1" || 
			hostname == "::1" || hostname == "[::1]"

		// For production (non-loopback), require HTTPS
		if !isLoopback && scheme != "https" {
			// Check if server itself is HTTPS
			if serverParsed, err := url.Parse(serverIssuer); err == nil {
				if serverParsed.Scheme == "https" {
					return fmt.Errorf("redirect_uri must use HTTPS in production (got %s://)", scheme)
				}
			}
		}
	}
	// Custom schemes (myapp://, etc.) are allowed for native/mobile apps

	return nil
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

// validatePKCE validates the PKCE code verifier against the challenge per RFC 7636
func (s *Server) validatePKCE(challenge, method, verifier string) error {
	if challenge == "" {
		// No PKCE required for this flow
		return nil
	}

	if verifier == "" {
		return fmt.Errorf("code_verifier is required when code_challenge is present")
	}

	// RFC 7636: code_verifier must be 43-128 characters
	if len(verifier) < 43 {
		return fmt.Errorf("code_verifier must be at least 43 characters (RFC 7636)")
	}
	if len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be at most 128 characters (RFC 7636)")
	}

	// RFC 7636: code_verifier can only contain [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	// This prevents injection attacks and ensures cryptographic quality
	for _, ch := range verifier {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || 
			ch == '-' || ch == '.' || ch == '_' || ch == '~') {
			return fmt.Errorf("code_verifier contains invalid characters (must be [A-Za-z0-9-._~])")
		}
	}

	// Only S256 method is allowed (plain method is insecure per OAuth 2.1)
	if method != "S256" {
		return fmt.Errorf("unsupported code_challenge_method: %s (only S256 is supported per OAuth 2.1)", method)
	}

	// Compute challenge from verifier using SHA256
	hash := sha256.Sum256([]byte(verifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Constant-time comparison to prevent timing attacks
	if computedChallenge != challenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

// RegisterClient registers a new OAuth client with IP-based DoS protection
func (s *Server) RegisterClient(clientName, clientType string, redirectURIs []string, scopes []string, clientIP string, maxClientsPerIP int) (*storage.Client, string, error) {
	// Check IP limit to prevent DoS via mass client registration
	if err := s.clientStore.CheckIPLimit(clientIP, maxClientsPerIP); err != nil {
		return nil, "", err
	}
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

	// Track IP for DoS protection
	if memStore, ok := s.clientStore.(*memory.Store); ok {
		memStore.TrackClientIP(clientIP)
	}

	if s.auditor != nil {
		s.auditor.LogClientRegistered(clientID, clientType, clientIP)
	}

	s.logger.Info("Registered new OAuth client",
		"client_id", clientID,
		"client_name", clientName,
		"client_type", clientType,
		"client_ip", clientIP)

	return client, clientSecret, nil
}

// ValidateClientCredentials validates client credentials for token endpoint
func (s *Server) ValidateClientCredentials(clientID, clientSecret string) error {
	return s.clientStore.ValidateClientSecret(clientID, clientSecret)
}

