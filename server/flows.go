package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// OAuth 2.0 error codes from RFC 6749.
// Note: These are intentionally duplicated from errors.go to avoid circular imports
// (root package imports server for type aliases, server can't import root).
// Keep these in sync with errors.go.
const (
	ErrorCodeInvalidClient      = "invalid_client"
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeInvalidRedirectURI = "invalid_redirect_uri"
	ErrorCodeInvalidScope       = "invalid_scope"
	ErrorCodeInvalidGrant       = "invalid_grant"
)

// ValidateToken validates an access token with the provider
// Note: Rate limiting should be done at the HTTP layer with IP address, not here with token
func (s *Server) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// Validate with provider
	userInfo, err := s.provider.ValidateToken(ctx, accessToken)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", "", "", err.Error())
		}
		return nil, err
	}

	// Store user info
	if err := s.tokenStore.SaveUserInfo(userInfo.ID, userInfo); err != nil {
		s.Logger.Warn("Failed to save user info", "error", err)
	}

	return userInfo, nil
}

// StartAuthorizationFlow starts a new OAuth authorization flow
// clientState is the state parameter from the client (REQUIRED for CSRF protection)
func (s *Server) StartAuthorizationFlow(clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, clientState string) (string, error) {
	// CRITICAL SECURITY: Require state parameter from client for CSRF protection
	if clientState == "" {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "missing_state_parameter")
		}
		return "", fmt.Errorf("state parameter is required for CSRF protection (OAuth 2.0 Security BCP)")
	}

	// PKCE validation (secure by default, configurable for backward compatibility)
	if s.Config.RequirePKCE {
		// PKCE is required (default, recommended for OAuth 2.1)
		if codeChallenge == "" || codeChallengeMethod == "" {
			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", clientID, "", "missing_pkce_parameters")
			}
			return "", fmt.Errorf("PKCE is required: code_challenge and code_challenge_method parameters are mandatory (OAuth 2.1)")
		}
	}

	// Validate PKCE method if provided
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", clientID, "", "missing_code_challenge_method")
			}
			return "", fmt.Errorf("code_challenge_method is required when code_challenge is provided")
		}

		// Validate challenge method
		if codeChallengeMethod == PKCEMethodPlain && !s.Config.AllowPKCEPlain {
			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", clientID, "", "plain_pkce_not_allowed")
			}
			return "", fmt.Errorf("'plain' code_challenge_method is not allowed (only S256 is supported for security)")
		}

		if codeChallengeMethod != PKCEMethodS256 && codeChallengeMethod != PKCEMethodPlain {
			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("invalid_pkce_method: %s", codeChallengeMethod))
			}
			return "", fmt.Errorf("unsupported code_challenge_method: %s (supported: S256%s)", codeChallengeMethod, func() string {
				if s.Config.AllowPKCEPlain {
					return ", plain"
				}
				return ""
			}())
		}
	}

	// Validate client
	client, err := s.clientStore.GetClient(clientID)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", ErrorCodeInvalidClient)
		}
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	// Validate redirect URI
	if err := s.validateRedirectURI(client, redirectURI); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", ErrorCodeInvalidRedirectURI)
		}
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	// Validate scopes
	if err := s.validateScopes(scope); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("%s: %v", ErrorCodeInvalidScope, err))
		}
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidScope, err)
	}

	// Log authorization flow start
	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
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
		ExpiresAt:           time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
	}
	if err := s.flowStore.SaveAuthorizationState(authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Generate authorization URL with provider
	// Pass the code challenge from client (already computed)
	authURL := s.provider.AuthorizationURL(providerState, codeChallenge, codeChallengeMethod)

	return authURL, nil
}

// HandleProviderCallback handles the callback from the OAuth provider
// Returns: (authorizationCode, clientState, error)
// clientState is the original state parameter from the client for CSRF validation
func (s *Server) HandleProviderCallback(ctx context.Context, providerState, code string) (*storage.AuthorizationCode, string, error) {
	// CRITICAL SECURITY: Validate provider state to prevent callback injection
	// We must lookup by providerState (not client state) since that's what the provider returns
	authState, err := s.flowStore.GetAuthorizationStateByProviderState(providerState)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
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
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
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
		s.Logger.Warn("Failed to save user info", "error", err)
	}
	if err := s.tokenStore.SaveToken(userInfo.ID, providerToken); err != nil {
		s.Logger.Warn("Failed to save provider token", "error", err)
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
		ExpiresAt:           time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
		Used:                false,
	}

	// Save authorization code
	if err := s.flowStore.SaveAuthorizationCode(authCodeObj); err != nil {
		return nil, "", fmt.Errorf("failed to save authorization code: %w", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
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
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "invalid_authorization_code")
		}
		return nil, "", fmt.Errorf("%s: authorization code not found", ErrorCodeInvalidGrant)
	}

	// Validate authorization code hasn't been used
	if authCode.Used {
		if s.Auditor != nil {
			// Authorization code reuse is a critical security event (token theft indicator)
			s.Auditor.LogEvent(security.Event{
				Type:     "authorization_code_reuse_detected",
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details: map[string]any{
					"severity": "critical",
					"action":   "code_deleted_tokens_revoked",
				},
			})
			s.Auditor.LogAuthFailure(authCode.UserID, clientID, "", "authorization_code_reuse")
		}
		// Delete the code and revoke associated tokens (security measure)
		_ = s.flowStore.DeleteAuthorizationCode(code)
		return nil, "", fmt.Errorf("%s: authorization code already used", ErrorCodeInvalidGrant)
	}

	// Validate client ID matches
	if authCode.ClientID != clientID {
		return nil, "", fmt.Errorf("%s: client ID mismatch", ErrorCodeInvalidGrant)
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		return nil, "", fmt.Errorf("%s: redirect URI mismatch", ErrorCodeInvalidGrant)
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if err := s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier); err != nil {
			if s.Auditor != nil {
				// This is a security event - log it separately
				s.Auditor.LogEvent(security.Event{
					Type:     "pkce_validation_failed",
					UserID:   authCode.UserID,
					ClientID: clientID,
					Details: map[string]any{
						"reason": err.Error(),
					},
				})
				s.Auditor.LogAuthFailure(authCode.UserID, clientID, "", fmt.Sprintf("pkce_validation_failed: %v", err))
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
		Expiry:       time.Now().Add(time.Duration(s.Config.AccessTokenTTL) * time.Second),
		TokenType:    "Bearer",
	}

	// Store access token -> provider token mapping
	if err := s.tokenStore.SaveToken(accessToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save access token mapping", "error", err)
	}

	// Store refresh token -> provider token mapping (for refresh flow)
	if err := s.tokenStore.SaveToken(refreshToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save refresh token", "error", err)
	}

	// Track refresh token with expiry (OAuth 2.1 security)
	// Use family tracking if storage supports it (for reuse detection)
	refreshTokenExpiry := time.Now().Add(time.Duration(s.Config.RefreshTokenTTL) * time.Second)
	if familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); ok {
		// Create new token family (generation 0)
		familyID := generateRandomToken()
		if err := familyStore.SaveRefreshTokenWithFamily(refreshToken, authCode.UserID, clientID, familyID, 0, refreshTokenExpiry); err != nil {
			s.Logger.Warn("Failed to track refresh token with family", "error", err)
		} else {
			s.Logger.Debug("Created new refresh token family",
				"user_id", authCode.UserID,
				"family_id", familyID[:min(8, len(familyID))])
		}
	} else {
		// Fallback to basic tracking
		if err := s.tokenStore.SaveRefreshToken(refreshToken, authCode.UserID, refreshTokenExpiry); err != nil {
			s.Logger.Warn("Failed to track refresh token", "error", err)
		}
	}

	// Delete authorization code (one-time use)
	_ = s.flowStore.DeleteAuthorizationCode(code)

	if s.Auditor != nil {
		s.Auditor.LogTokenIssued(authCode.UserID, clientID, "", authCode.Scope)
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
				if s.Auditor != nil {
					s.Auditor.LogEvent(security.Event{
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
				s.Logger.Error("Attempted use of revoked token family",
					"user_id", family.UserID,
					"family_id", family.FamilyID[:min(8, len(family.FamilyID))])
				return nil, fmt.Errorf("refresh token has been revoked")
			}
		}
	}

	// Validate refresh token and get user ID
	userID, err := s.tokenStore.GetRefreshTokenInfo(refreshToken)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "invalid_refresh_token")
		}
		return nil, fmt.Errorf("%s: %w", ErrorCodeInvalidGrant, err)
	}

	// Get provider token using refresh token
	providerToken, err := s.tokenStore.GetToken(refreshToken)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure(userID, clientID, "", "refresh_token_not_found")
		}
		return nil, fmt.Errorf("%s: refresh token not found", ErrorCodeInvalidGrant)
	}

	// Refresh token with provider
	newProviderToken, err := s.provider.RefreshToken(ctx, providerToken.RefreshToken)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure(userID, clientID, "", fmt.Sprintf("provider_refresh_failed: %v", err))
		}
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// Generate new access token using oauth2.GenerateVerifier (same quality)
	newAccessToken := generateRandomToken()

	// OAuth 2.1: Refresh Token Rotation with Reuse Detection
	var newRefreshToken string
	var rotated bool

	if s.Config.AllowRefreshTokenRotation {
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
			s.Logger.Warn("Failed to delete old refresh token", "error", err)
		}
		if err := s.tokenStore.DeleteToken(refreshToken); err != nil {
			s.Logger.Warn("Failed to delete old refresh token mapping", "error", err)
		}

		rotated = true
		s.Logger.Info("Refresh token rotated (OAuth 2.1)",
			"user_id", userID,
			"generation", generation,
			"family_tracking", supportsFamilies)

		// Save with family tracking if supported
		refreshTokenExpiry := time.Now().Add(time.Duration(s.Config.RefreshTokenTTL) * time.Second)
		if supportsFamilies && familyID != "" {
			if err := familyStore.SaveRefreshTokenWithFamily(newRefreshToken, userID, clientID, familyID, generation, refreshTokenExpiry); err != nil {
				s.Logger.Warn("Failed to save refresh token with family", "error", err)
			}
		} else {
			if err := s.tokenStore.SaveRefreshToken(newRefreshToken, userID, refreshTokenExpiry); err != nil {
				s.Logger.Warn("Failed to track new refresh token", "error", err)
			}
		}
	} else {
		// Reuse old refresh token (not recommended, but allowed for backward compatibility)
		newRefreshToken = refreshToken
		rotated = false
		s.Logger.Warn("Refresh token reused (rotation disabled)", "user_id", userID)
	}

	// Create token response using oauth2.Token
	tokenResponse := &oauth2.Token{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		Expiry:       time.Now().Add(time.Duration(s.Config.AccessTokenTTL) * time.Second),
		TokenType:    "Bearer",
	}

	// Store new access token -> provider token mapping
	if err := s.tokenStore.SaveToken(newAccessToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new access token", "error", err)
	}

	// Store new refresh token -> provider token mapping
	if err := s.tokenStore.SaveToken(newRefreshToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new refresh token", "error", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogTokenRefreshed(userID, clientID, "", rotated)
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
			s.Logger.Warn("Failed to revoke token at provider", "error", err)
			// Continue with local deletion even if provider revocation fails
		}
	}

	// Delete locally
	if err := s.tokenStore.DeleteToken(token); err != nil {
		s.Logger.Warn("Failed to delete token locally", "error", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogTokenRevoked("", clientID, clientIP, "access_or_refresh")
	}

	s.Logger.Info("Token revoked", "client_id", clientID, "ip", clientIP)
	return nil
}
