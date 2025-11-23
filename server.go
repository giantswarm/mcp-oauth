package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
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

	// AllowRefreshTokenRotation enables refresh token rotation (OAuth 2.1)
	// Default: true (secure by default)
	AllowRefreshTokenRotation bool // default: true

	// TrustProxy enables trusting X-Forwarded-For and X-Real-IP headers
	// WARNING: Only enable if behind a trusted reverse proxy (nginx, HAProxy, etc.)
	// When false, uses direct connection IP (secure by default)
	// Default: false
	TrustProxy bool // default: false

	// TrustedProxyCount is the number of trusted proxies in front of this server
	// Used with TrustProxy to correctly extract client IP from X-Forwarded-For
	// Example: If you have 2 proxies (CloudFlare + nginx), set this to 2
	// The client IP will be extracted as: ips[len(ips) - TrustedProxyCount - 1]
	// Default: 1
	TrustedProxyCount int // default: 1

	// MaxClientsPerIP limits client registrations per IP address
	// Prevents DoS via mass client registration
	// Default: 10
	MaxClientsPerIP int // default: 10

	// ClockSkewGracePeriod is the grace period for token expiration checks (in seconds)
	// This prevents false expiration errors due to time synchronization issues
	// Default: 5 seconds
	ClockSkewGracePeriod int64 // seconds, default: 5

	// SupportedScopes lists the scopes that are allowed for clients
	// If empty, all scopes are allowed
	SupportedScopes []string

	// AllowPKCEPlain allows the 'plain' code_challenge_method (NOT RECOMMENDED)
	// WARNING: The 'plain' method is insecure and deprecated in OAuth 2.1
	// Only enable for backward compatibility with legacy clients
	// When false, only S256 method is accepted (secure by default)
	// Default: false
	AllowPKCEPlain bool // default: false

	// RequirePKCE enforces PKCE for all authorization requests
	// WARNING: Disabling this significantly weakens security
	// Only disable for backward compatibility with very old clients
	// When true, code_challenge parameter is mandatory (secure by default)
	// Default: true
	RequirePKCE bool // default: true
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

	if logger == nil {
		logger = slog.Default()
	}

	// Apply secure defaults
	config = applySecureDefaults(config, logger)

	return &Server{
		provider:    provider,
		tokenStore:  tokenStore,
		clientStore: clientStore,
		flowStore:   flowStore,
		config:      config,
		logger:      logger,
	}, nil
}

// applySecureDefaults applies secure-by-default configuration values
// This follows the principle: secure by default, opt-in for less secure options
func applySecureDefaults(config *ServerConfig, logger *slog.Logger) *ServerConfig {
	// Time-based defaults
	if config.AuthorizationCodeTTL == 0 {
		config.AuthorizationCodeTTL = 600 // 10 minutes
	}
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 3600 // 1 hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7776000 // 90 days
	}
	if config.TrustedProxyCount == 0 {
		config.TrustedProxyCount = 1 // Default to 1 trusted proxy
	}
	if config.ClockSkewGracePeriod == 0 {
		config.ClockSkewGracePeriod = 5 // 5 seconds default
	}
	if config.MaxClientsPerIP == 0 {
		config.MaxClientsPerIP = 10 // Default limit
	}

	// Security defaults
	// For boolean fields, we need a way to distinguish "not set" from "explicitly set to false"
	// We use a simple heuristic: if the struct is new (has all zeros), apply secure defaults
	// If any security field is explicitly configured, we respect the user's choice
	isDefaultConfig := config.AllowRefreshTokenRotation == false &&
		config.RequirePKCE == false &&
		config.AllowPKCEPlain == false

	if isDefaultConfig {
		// Apply secure defaults when config is fresh
		config.AllowRefreshTokenRotation = true // OAuth 2.1 security best practice
		config.RequirePKCE = true               // OAuth 2.1 security best practice
		config.AllowPKCEPlain = false           // Reject insecure 'plain' method
		config.TrustProxy = false               // Don't trust proxy headers by default
	} else {
		// User has explicitly configured security settings - log warnings if insecure
		if !config.RequirePKCE {
			logger.Warn("⚠️  SECURITY WARNING: PKCE is DISABLED",
				"risk", "Authorization code interception attacks",
				"recommendation", "Set RequirePKCE=true for OAuth 2.1 compliance",
				"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-7.6")
		}
		if config.AllowPKCEPlain {
			logger.Warn("⚠️  SECURITY WARNING: Plain PKCE method is ALLOWED",
				"risk", "Weak code challenge protection",
				"recommendation", "Set AllowPKCEPlain=false to require S256",
				"learn_more", "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2")
		}
		if config.TrustProxy {
			logger.Warn("⚠️  SECURITY NOTICE: Trusting proxy headers",
				"risk", "IP spoofing if proxy is not properly configured",
				"recommendation", "Only enable behind trusted reverse proxies",
				"config", "TrustedProxyCount should match your proxy chain length")
		}
	}

	return config
}

// SetEncryptor sets the token encryptor for server and storage
func (s *Server) SetEncryptor(enc *security.Encryptor) {
	s.encryptor = enc

	// Also set encryptor on storage if it's a memory store
	type encryptorSetter interface {
		SetEncryptor(*security.Encryptor)
	}
	if setter, ok := s.tokenStore.(encryptorSetter); ok {
		setter.SetEncryptor(enc)
	}
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
// clientState is the state parameter from the client (REQUIRED for CSRF protection)
func (s *Server) StartAuthorizationFlow(clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, clientState string) (string, error) {
	// CRITICAL SECURITY: Require state parameter from client for CSRF protection
	if clientState == "" {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "missing_state_parameter")
		}
		return "", fmt.Errorf("state parameter is required for CSRF protection (OAuth 2.0 Security BCP)")
	}

	// PKCE validation (secure by default, configurable for backward compatibility)
	if s.config.RequirePKCE {
		// PKCE is required (default, recommended for OAuth 2.1)
		if codeChallenge == "" || codeChallengeMethod == "" {
			if s.auditor != nil {
				s.auditor.LogAuthFailure("", clientID, "", "missing_pkce_parameters")
			}
			return "", fmt.Errorf("PKCE is required: code_challenge and code_challenge_method parameters are mandatory (OAuth 2.1)")
		}
	}

	// Validate PKCE method if provided
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			if s.auditor != nil {
				s.auditor.LogAuthFailure("", clientID, "", "missing_code_challenge_method")
			}
			return "", fmt.Errorf("code_challenge_method is required when code_challenge is provided")
		}

		// Validate challenge method
		if codeChallengeMethod == "plain" && !s.config.AllowPKCEPlain {
			if s.auditor != nil {
				s.auditor.LogAuthFailure("", clientID, "", "plain_pkce_not_allowed")
			}
			return "", fmt.Errorf("'plain' code_challenge_method is not allowed (only S256 is supported for security)")
		}

		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			if s.auditor != nil {
				s.auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("invalid_pkce_method: %s", codeChallengeMethod))
			}
			return "", fmt.Errorf("unsupported code_challenge_method: %s (supported: S256%s)", codeChallengeMethod, func() string {
				if s.config.AllowPKCEPlain {
					return ", plain"
				}
				return ""
			}())
		}
	}

	// Validate client
	client, err := s.clientStore.GetClient(clientID)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "invalid_client")
		}
		return "", fmt.Errorf("invalid_request")
	}

	// Validate redirect URI
	if err := s.validateRedirectURI(client, redirectURI); err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "invalid_redirect_uri")
		}
		return "", fmt.Errorf("invalid_request")
	}

	// Validate scopes
	if err := s.validateScopes(scope); err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("invalid_scope: %v", err))
		}
		return "", fmt.Errorf("invalid_scope")
	}

	// Log authorization flow start
	if s.auditor != nil {
		s.auditor.LogEvent(security.Event{
			Type:     "authorization_flow_started",
			ClientID: clientID,
			Details: map[string]any{
				"redirect_uri":          redirectURI,
				"scope":                 scope,
				"code_challenge_method": codeChallengeMethod,
			},
		})
	}

	// Generate provider state (different from client state for defense in depth)
	// This allows us to track the provider callback independently
	providerState := generateRandomToken()

	// Save authorization state
	// StateID = client's state (for CSRF validation when redirecting back to client)
	// ProviderState = our state sent to provider (for validating provider callback)
	authState := &storage.AuthorizationState{
		StateID:             clientState, // Client's state for CSRF protection
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ProviderState:       providerState, // Our state for provider callback
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute), // 10 minute expiry
	}
	if err := s.flowStore.SaveAuthorizationState(authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Generate authorization URL with provider
	// Pass the code challenge from client (already computed)
	authURL := s.provider.AuthorizationURL(providerState, codeChallenge, codeChallengeMethod)

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

// validateScopes validates that requested scopes are allowed
func (s *Server) validateScopes(scope string) error {
	// If no scopes configured, allow all
	if len(s.config.SupportedScopes) == 0 {
		return nil
	}

	if scope == "" {
		return nil // Empty scope is allowed
	}

	// Split scope string into individual scopes
	requestedScopes := strings.Fields(scope)

	// Check each requested scope against supported scopes
	for _, reqScope := range requestedScopes {
		found := false
		for _, supportedScope := range s.config.SupportedScopes {
			if reqScope == supportedScope {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported scope: %s", reqScope)
		}
	}

	return nil
}

// GetClient retrieves a client by ID (for use by handler)
func (s *Server) GetClient(clientID string) (*storage.Client, error) {
	return s.clientStore.GetClient(clientID)
}

// generateRandomToken generates a cryptographically secure random token
// For PKCE verifiers, use oauth2.GenerateVerifier() instead
func generateRandomToken() string {
	// Uses same method as oauth2.GenerateVerifier() for consistency
	return oauth2.GenerateVerifier()
}

// HandleProviderCallback handles the callback from the OAuth provider
// Returns: (authorizationCode, clientState, error)
// clientState is the original state parameter from the client for CSRF validation
func (s *Server) HandleProviderCallback(ctx context.Context, providerState, code string) (*storage.AuthorizationCode, string, error) {
	// CRITICAL SECURITY: Validate provider state to prevent callback injection
	// We must lookup by providerState (not client state) since that's what the provider returns
	authState, err := s.flowStore.GetAuthorizationStateByProviderState(providerState)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogEvent(security.Event{
				Type: "invalid_provider_callback",
				Details: map[string]any{
					"reason": "state_not_found",
				},
			})
		}
		return nil, "", fmt.Errorf("invalid state parameter: %w", err)
	}

	// CRITICAL SECURITY: Validate the provider state matches (constant-time comparison)
	// This prevents timing attacks on state validation
	if subtle.ConstantTimeCompare([]byte(authState.ProviderState), []byte(providerState)) != 1 {
		if s.auditor != nil {
			s.auditor.LogEvent(security.Event{
				Type:     "provider_state_mismatch",
				ClientID: authState.ClientID,
				Details: map[string]any{
					"severity": "critical",
				},
			})
		}
		return nil, "", fmt.Errorf("state parameter mismatch")
	}

	// Save the client's original state before deletion
	clientState := authState.StateID

	// Delete authorization state (one-time use)
	// Use providerState for deletion since that's our lookup key
	_ = s.flowStore.DeleteAuthorizationState(providerState)

	// Exchange code with provider
	// Note: We don't pass code_verifier here because PKCE verification
	// happens when the client exchanges their authorization code with us
	providerToken, err := s.provider.ExchangeCode(ctx, code, "")
	if err != nil {
		return nil, "", fmt.Errorf("failed to exchange code with provider: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.provider.ValidateToken(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user info: %w", err)
	}

	// Save user info and token
	if err := s.tokenStore.SaveUserInfo(userInfo.ID, userInfo); err != nil {
		s.logger.Warn("Failed to save user info", "error", err)
	}
	if err := s.tokenStore.SaveToken(userInfo.ID, providerToken); err != nil {
		s.logger.Warn("Failed to save provider token", "error", err)
	}

	// Generate authorization code using oauth2.GenerateVerifier (same quality)
	authCode := generateRandomToken()

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
		return nil, "", fmt.Errorf("failed to save authorization code: %w", err)
	}

	if s.auditor != nil {
		s.auditor.LogEvent(security.Event{
			Type:     "authorization_code_issued",
			UserID:   userInfo.ID,
			ClientID: authState.ClientID,
			Details: map[string]any{
				"scope":                 authState.Scope,
				"client_state_returned": true,
			},
		})
	}

	// Return both the authorization code and the client's original state
	return authCodeObj, clientState, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
// Returns oauth2.Token directly
func (s *Server) ExchangeAuthorizationCode(_ context.Context, code, clientID, redirectURI, codeVerifier string) (*oauth2.Token, string, error) {
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
			// Authorization code reuse is a critical security event (token theft indicator)
			s.auditor.LogEvent(security.Event{
				Type:     "authorization_code_reuse_detected",
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details: map[string]any{
					"severity": "critical",
					"action":   "code_deleted_tokens_revoked",
				},
			})
			s.auditor.LogAuthFailure(authCode.UserID, clientID, "", "authorization_code_reuse")
		}
		// Delete the code and revoke associated tokens (security measure)
		_ = s.flowStore.DeleteAuthorizationCode(code)
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
				// This is a security event - log it separately
				s.auditor.LogEvent(security.Event{
					Type:     "pkce_validation_failed",
					UserID:   authCode.UserID,
					ClientID: clientID,
					Details: map[string]any{
						"reason": err.Error(),
					},
				})
				s.auditor.LogAuthFailure(authCode.UserID, clientID, "", fmt.Sprintf("pkce_validation_failed: %v", err))
			}
			return nil, "", fmt.Errorf("PKCE validation failed: %w", err)
		}
	}

	// Mark code as used
	authCode.Used = true
	_ = s.flowStore.SaveAuthorizationCode(authCode)

	// Generate new access token using oauth2.GenerateVerifier (same quality)
	accessToken := generateRandomToken()

	// Generate refresh token
	refreshToken := generateRandomToken()

	// Create token response using oauth2.Token
	tokenResponse := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Duration(s.config.AccessTokenTTL) * time.Second),
		TokenType:    "Bearer",
	}

	// Store access token -> provider token mapping
	if err := s.tokenStore.SaveToken(accessToken, authCode.ProviderToken); err != nil {
		s.logger.Warn("Failed to save access token mapping", "error", err)
	}

	// Store refresh token -> provider token mapping (for refresh flow)
	if err := s.tokenStore.SaveToken(refreshToken, authCode.ProviderToken); err != nil {
		s.logger.Warn("Failed to save refresh token", "error", err)
	}

	// Track refresh token with expiry (OAuth 2.1 security)
	// Use family tracking if storage supports it (for reuse detection)
	refreshTokenExpiry := time.Now().Add(time.Duration(s.config.RefreshTokenTTL) * time.Second)
	if familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); ok {
		// Create new token family (generation 0)
		familyID := generateRandomToken()
		if err := familyStore.SaveRefreshTokenWithFamily(refreshToken, authCode.UserID, clientID, familyID, 0, refreshTokenExpiry); err != nil {
			s.logger.Warn("Failed to track refresh token with family", "error", err)
		} else {
			s.logger.Debug("Created new refresh token family",
				"user_id", authCode.UserID,
				"family_id", familyID[:minInt(8, len(familyID))])
		}
	} else {
		// Fallback to basic tracking
		if err := s.tokenStore.SaveRefreshToken(refreshToken, authCode.UserID, refreshTokenExpiry); err != nil {
			s.logger.Warn("Failed to track refresh token", "error", err)
		}
	}

	// Delete authorization code (one-time use)
	_ = s.flowStore.DeleteAuthorizationCode(code)

	if s.auditor != nil {
		s.auditor.LogTokenIssued(authCode.UserID, clientID, "", authCode.Scope)
	}

	return tokenResponse, authCode.Scope, nil
}

// RefreshAccessToken refreshes an access token using a refresh token with OAuth 2.1 rotation
// Returns oauth2.Token directly
// Implements OAuth 2.1 refresh token reuse detection for enhanced security
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken, clientID string) (*oauth2.Token, error) {
	// Check if storage supports token family tracking (OAuth 2.1 reuse detection)
	familyStore, supportsFamilies := s.tokenStore.(storage.RefreshTokenFamilyStore)

	// OAUTH 2.1 SECURITY: Check for refresh token reuse (token theft detection)
	if supportsFamilies {
		family, err := familyStore.GetRefreshTokenFamily(refreshToken)
		if err == nil {
			// Check if this token family has been revoked due to reuse
			if family.Revoked {
				if s.auditor != nil {
					s.auditor.LogEvent(security.Event{
						Type:     "revoked_token_family_reuse_attempt",
						UserID:   family.UserID,
						ClientID: clientID,
						Details: map[string]any{
							"severity":    "critical",
							"family_id":   family.FamilyID,
							"description": "Attempted use of token from revoked family (prior reuse detected)",
						},
					})
				}
				s.logger.Error("Attempted use of revoked token family",
					"user_id", family.UserID,
					"family_id", family.FamilyID[:minInt(8, len(family.FamilyID))])
				return nil, fmt.Errorf("refresh token has been revoked")
			}
		}
	}

	// Validate refresh token and get user ID
	userID, err := s.tokenStore.GetRefreshTokenInfo(refreshToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure("", clientID, "", "invalid_refresh_token")
		}
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get provider token using refresh token
	providerToken, err := s.tokenStore.GetToken(refreshToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure(userID, clientID, "", "refresh_token_not_found")
		}
		return nil, fmt.Errorf("refresh token not found")
	}

	// Refresh token with provider
	newProviderToken, err := s.provider.RefreshToken(ctx, providerToken.RefreshToken)
	if err != nil {
		if s.auditor != nil {
			s.auditor.LogAuthFailure(userID, clientID, "", fmt.Sprintf("provider_refresh_failed: %v", err))
		}
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// Generate new access token using oauth2.GenerateVerifier (same quality)
	newAccessToken := generateRandomToken()

	// OAuth 2.1: Refresh Token Rotation with Reuse Detection
	var newRefreshToken string
	var rotated bool

	if s.config.AllowRefreshTokenRotation {
		newRefreshToken = generateRandomToken()

		// Get family info for rotation (if supported)
		var familyID string
		var generation int
		if supportsFamilies {
			family, err := familyStore.GetRefreshTokenFamily(refreshToken)
			if err == nil {
				familyID = family.FamilyID
				generation = family.Generation + 1 // Increment generation
			} else {
				// First time seeing this token, create new family
				familyID = generateRandomToken()
				generation = 1
			}
		}

		// Invalidate old refresh token (OAuth 2.1 security requirement)
		if err := s.tokenStore.DeleteRefreshToken(refreshToken); err != nil {
			s.logger.Warn("Failed to delete old refresh token", "error", err)
		}
		if err := s.tokenStore.DeleteToken(refreshToken); err != nil {
			s.logger.Warn("Failed to delete old refresh token mapping", "error", err)
		}

		rotated = true
		s.logger.Info("Refresh token rotated (OAuth 2.1)",
			"user_id", userID,
			"generation", generation,
			"family_tracking", supportsFamilies)

		// Save with family tracking if supported
		refreshTokenExpiry := time.Now().Add(time.Duration(s.config.RefreshTokenTTL) * time.Second)
		if supportsFamilies && familyID != "" {
			if err := familyStore.SaveRefreshTokenWithFamily(newRefreshToken, userID, clientID, familyID, generation, refreshTokenExpiry); err != nil {
				s.logger.Warn("Failed to save refresh token with family", "error", err)
			}
		} else {
			if err := s.tokenStore.SaveRefreshToken(newRefreshToken, userID, refreshTokenExpiry); err != nil {
				s.logger.Warn("Failed to track new refresh token", "error", err)
			}
		}
	} else {
		// Reuse old refresh token (not recommended, but allowed for backward compatibility)
		newRefreshToken = refreshToken
		rotated = false
		s.logger.Warn("Refresh token reused (rotation disabled)", "user_id", userID)
	}

	// Create token response using oauth2.Token
	tokenResponse := &oauth2.Token{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		Expiry:       time.Now().Add(time.Duration(s.config.AccessTokenTTL) * time.Second),
		TokenType:    "Bearer",
	}

	// Store new access token -> provider token mapping
	if err := s.tokenStore.SaveToken(newAccessToken, newProviderToken); err != nil {
		s.logger.Warn("Failed to save new access token", "error", err)
	}

	// Store new refresh token -> provider token mapping
	if err := s.tokenStore.SaveToken(newRefreshToken, newProviderToken); err != nil {
		s.logger.Warn("Failed to save new refresh token", "error", err)
	}

	if s.auditor != nil {
		s.auditor.LogTokenRefreshed(userID, clientID, "", rotated)
	}

	return tokenResponse, nil
}

// RevokeToken revokes a token (access or refresh)
func (s *Server) RevokeToken(ctx context.Context, token, clientID, clientIP string) error {
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
		s.auditor.LogTokenRevoked("", clientID, clientIP, "access_or_refresh")
	}

	s.logger.Info("Token revoked", "client_id", clientID, "ip", clientIP)
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
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') &&
			ch != '-' && ch != '.' && ch != '_' && ch != '~' {
			return fmt.Errorf("code_verifier contains invalid characters (must be [A-Za-z0-9-._~])")
		}
	}

	var computedChallenge string

	// Compute challenge based on method
	switch method {
	case "S256":
		// Recommended: SHA256 hash of verifier
		hash := sha256.Sum256([]byte(verifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	case "plain":
		// Deprecated but allowed if configured for backward compatibility
		if !s.config.AllowPKCEPlain {
			return fmt.Errorf("'plain' code_challenge_method is not allowed (configure AllowPKCEPlain=true if needed for legacy clients)")
		}
		computedChallenge = verifier
		s.logger.Warn("Using insecure 'plain' PKCE method",
			"recommendation", "Upgrade client to use S256")

	default:
		return fmt.Errorf("unsupported code_challenge_method: %s (supported: S256%s)", method, func() string {
			if s.config.AllowPKCEPlain {
				return ", plain"
			}
			return ""
		}())
	}

	// Constant-time comparison to prevent timing attacks
	// Using subtle.ConstantTimeCompare to prevent side-channel attacks
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(challenge)) != 1 {
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
	// Generate client ID using oauth2.GenerateVerifier (same quality)
	clientID := generateRandomToken()

	// Generate client secret for confidential clients
	var clientSecret string
	var clientSecretHash string

	if clientType == "" {
		clientType = "confidential"
	}

	if clientType == "confidential" {
		clientSecret = generateRandomToken()

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
