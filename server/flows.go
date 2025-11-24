package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math"
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
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*oauth2.Token, string, error) {
	// SECURITY: Atomically check and mark authorization code as used
	// This prevents race conditions where multiple concurrent requests could use the same code
	authCode, err := s.flowStore.AtomicCheckAndMarkAuthCodeUsed(code)
	if err != nil {
		// Check if this is a reuse attempt (code already used)
		if authCode != nil && authCode.Used {
			// CRITICAL SECURITY: Authorization code reuse detected - this indicates a potential token theft attack
			// OAuth 2.1 requires revoking ALL tokens for this user+client when code reuse is detected
			// Rate limit logging to prevent DoS via log flooding
			if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(authCode.UserID+":"+clientID) {
				s.Logger.Error("Authorization code reuse detected - revoking all tokens",
					"user_id", authCode.UserID,
					"client_id", clientID,
					"oauth_spec", "OAuth 2.1 Section 4.1.2")
			}

			// Revoke all tokens for this user+client (OAuth 2.1 requirement)
			if err := s.RevokeAllTokensForUserClient(ctx, authCode.UserID, clientID); err != nil {
				s.Logger.Error("Failed to revoke tokens after code reuse detection", "error", err)
				// Continue with deletion even if revocation failed
			}

			if s.Auditor != nil {
				// Log the critical security event
				s.Auditor.LogEvent(security.Event{
					Type:     "authorization_code_reuse_detected",
					UserID:   authCode.UserID,
					ClientID: clientID,
					Details: map[string]any{
						"severity":   "critical",
						"action":     "all_tokens_revoked",
						"oauth_spec": "OAuth 2.1 Section 4.1.2",
					},
				})
				s.Auditor.LogAuthFailure(authCode.UserID, clientID, "", "authorization_code_reuse")
			}

			// Delete the authorization code
			_ = s.flowStore.DeleteAuthorizationCode(code)

			// Return generic error per RFC 6749 (don't reveal details to attacker)
			return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
		}

		// Other error (not found, expired, etc.)
		// SECURITY: Log detailed internal error for debugging, but return generic error to client
		s.Logger.Debug("Authorization code validation failed",
			"reason", err.Error(),
			"client_id", clientID,
			"code_prefix", safeTruncate(code, 8))

		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "invalid_authorization_code")
		}
		// Return generic error per RFC 6749 (don't reveal details to attacker)
		return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Code is now atomically marked as used - no other request can use it

	// Validate client ID matches
	if authCode.ClientID != clientID {
		// SECURITY: Log detailed internal error for debugging, but return generic error to client
		s.Logger.Debug("Authorization code validation failed",
			"reason", "client_id_mismatch",
			"expected_client_id", authCode.ClientID,
			"provided_client_id", clientID,
			"code_prefix", safeTruncate(code, 8))

		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "client_id_mismatch")
		}
		// Return generic error per RFC 6749 (don't reveal details to attacker)
		return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		// SECURITY: Log detailed internal error for debugging, but return generic error to client
		s.Logger.Debug("Authorization code validation failed",
			"reason", "redirect_uri_mismatch",
			"expected_uri", authCode.RedirectURI,
			"provided_uri", redirectURI,
			"client_id", clientID,
			"code_prefix", safeTruncate(code, 8))

		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "redirect_uri_mismatch")
		}
		// Return generic error per RFC 6749 (don't reveal details to attacker)
		return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
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

	// Track access token metadata for revocation (OAuth 2.1 code reuse detection)
	if metadataStore, ok := s.tokenStore.(interface {
		SaveTokenMetadata(tokenID, userID, clientID, tokenType string) error
	}); ok {
		if err := metadataStore.SaveTokenMetadata(accessToken, authCode.UserID, clientID, "access"); err != nil {
			s.Logger.Warn("Failed to save access token metadata", "error", err)
		}
		// CRITICAL: Also save refresh token metadata for revocation
		// This ensures refresh tokens can be found and revoked during code reuse detection
		if err := metadataStore.SaveTokenMetadata(refreshToken, authCode.UserID, clientID, "refresh"); err != nil {
			s.Logger.Warn("Failed to save refresh token metadata", "error", err)
		}
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
				"family_id", safeTruncate(familyID, 8))
		}
	} else {
		// Fallback to basic tracking
		if err := s.tokenStore.SaveRefreshToken(refreshToken, authCode.UserID, refreshTokenExpiry); err != nil {
			s.Logger.Warn("Failed to track refresh token", "error", err)
		}
	}

	// NOTE: We do NOT delete the authorization code immediately (OAuth 2.1 security)
	// Instead, we keep it marked as "Used" to detect reuse attempts (token theft indicator)
	// The cleanup goroutine will delete expired/used codes after the TTL expires
	// This is critical for the code reuse detection security feature

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

	// OAUTH 2.1 SECURITY: Atomically get and delete refresh token FIRST
	// This is the synchronization point - only ONE concurrent request can succeed
	// After this, we check family metadata to detect reuse of already-rotated tokens
	userID, providerToken, err := s.tokenStore.AtomicGetAndDeleteRefreshToken(refreshToken)

	if err != nil {
		// Token not found or already deleted - check if this is a reuse attempt
		// SECURITY FIX: Check family AFTER atomic delete to eliminate TOCTOU vulnerability
		if supportsFamilies {
			family, famErr := familyStore.GetRefreshTokenFamily(refreshToken)
			if famErr == nil {
				// Family exists but token was already deleted/rotated → REUSE DETECTED!
				// Check if family was previously revoked
				if family.Revoked {
					// Attempted use of token from previously revoked family
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
						"family_id", safeTruncate(family.FamilyID, 8))
					return nil, fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
				}

				// Token is deleted but family exists and NOT revoked → FRESH REUSE DETECTED!
				// This means someone is trying to use an old (rotated) refresh token
				// Rate limit logging to prevent DoS via log flooding
				if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(family.UserID+":"+clientID) {
					s.Logger.Error("Refresh token reuse detected - token was rotated but still being used",
						"user_id", family.UserID,
						"client_id", clientID,
						"family_id", safeTruncate(family.FamilyID, 8),
						"generation", family.Generation,
						"oauth_spec", "OAuth 2.1 Refresh Token Rotation")
				}

				// Step 1: Revoke entire token family (OAuth 2.1 requirement)
				if err := familyStore.RevokeRefreshTokenFamily(family.FamilyID); err != nil {
					s.Logger.Error("Failed to revoke token family", "error", err)
					// Continue with user token revocation even if family revocation failed
				}

				// Step 2: Revoke all tokens for this user+client (defense in depth)
				if err := s.RevokeAllTokensForUserClient(ctx, family.UserID, family.ClientID); err != nil {
					s.Logger.Error("Failed to revoke user tokens", "error", err)
					// Continue - log error but still return security error to client
				}

				// Step 3: Log critical security event for monitoring/alerting
				if s.Auditor != nil {
					s.Auditor.LogEvent(security.Event{
						Type:     "refresh_token_reuse_detected",
						UserID:   family.UserID,
						ClientID: clientID,
						Details: map[string]any{
							"severity":   "critical",
							"family_id":  family.FamilyID,
							"generation": family.Generation,
							"action":     "family_and_tokens_revoked",
							"oauth_spec": "OAuth 2.1 Refresh Token Rotation",
							"impact":     "All tokens for user+client revoked to prevent token theft",
						},
					})
					s.Auditor.LogTokenReuse(family.UserID, clientID)
				}

				// Return generic error per RFC 6749 (don't reveal security details to attacker)
				return nil, fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
			}
		}

		// Token not found and no family metadata - regular invalid token error
		// SECURITY: Log detailed internal error for debugging, but return generic error to client
		s.Logger.Debug("Refresh token validation failed",
			"reason", err.Error(),
			"client_id", clientID,
			"token_prefix", safeTruncate(refreshToken, 8))

		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "invalid_refresh_token")
		}
		// Return generic error per RFC 6749 (don't reveal details to attacker)
		return nil, fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Token is now atomically deleted - no other request can use it

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

	// Track new access token metadata for revocation (OAuth 2.1 code reuse detection)
	if metadataStore, ok := s.tokenStore.(interface {
		SaveTokenMetadata(tokenID, userID, clientID, tokenType string) error
	}); ok {
		if err := metadataStore.SaveTokenMetadata(newAccessToken, userID, clientID, "access"); err != nil {
			s.Logger.Warn("Failed to save access token metadata", "error", err)
		}
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

// RevokeAllTokensForUserClient revokes all tokens (access + refresh) for a specific user+client combination.
// This is called when authorization code or refresh token reuse is detected (OAuth 2.1 security requirement).
// It provides defense against token theft by invalidating all tokens when an attack is detected.
//
// SECURITY: This function revokes tokens at BOTH the provider (Google/GitHub) and locally.
// The storage backend MUST implement TokenRevocationStore for OAuth 2.1 compliance.
//
// Provider Revocation Behavior:
// - Attempts to revoke all tokens at the OAuth provider (Google/GitHub/etc) FIRST before local revocation
// - Uses exponential backoff retry logic (configurable via ProviderRevocationMaxRetries)
// - Individual token failures are logged but don't stop the process
// - If provider revocation failures exceed ProviderRevocationFailureThreshold (default 50%), returns error
// - If ALL provider revocations fail (100% failure rate), returns error and logs critical alert
// - Tokens are ALWAYS revoked locally, even if provider revocation fails
// - This ensures defense-in-depth: tokens become invalid locally while operators investigate provider issues
//
// Error Handling:
// - Returns error if storage doesn't support TokenRevocationStore (OAuth 2.1 compliance failure)
// - Returns error if provider revocation failure rate exceeds threshold
// - Returns error if local revocation fails
// - Logs detailed information about partial failures for operator investigation
func (s *Server) RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) error {
	// Check if storage supports token revocation
	revocationStore, supportsRevocation := s.tokenStore.(storage.TokenRevocationStore)

	if !supportsRevocation {
		// SECURITY: Fail hard - this is a critical security feature required for OAuth 2.1
		s.Logger.Error("CRITICAL: Token storage does not support TokenRevocationStore - OAuth 2.1 NOT compliant",
			"user_id", userID,
			"client_id", clientID)

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "token_revocation_not_supported",
				UserID:   userID,
				ClientID: clientID,
				Details: map[string]any{
					"severity": "critical",
					"message":  "Storage backend does not support bulk token revocation - OAuth 2.1 compliance FAILED",
				},
			})
		}

		return fmt.Errorf("storage backend must implement TokenRevocationStore for OAuth 2.1 compliance")
	}

	// Get list of tokens BEFORE revoking locally (so we can revoke at provider)
	tokens, err := revocationStore.GetTokensByUserClient(userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to get tokens for revocation: %w", err)
	}

	// SECURITY: Revoke at provider FIRST with retry logic
	// This ensures tokens are invalid at Google/GitHub/etc, not just locally
	revokedAtProvider := 0
	failedAtProvider := 0
	totalTokensToRevoke := 0

	for _, tokenID := range tokens {
		providerToken, err := s.tokenStore.GetToken(tokenID)
		if err != nil {
			s.Logger.Warn("Could not get provider token for revocation",
				"token_id", safeTruncate(tokenID, 8),
				"error", err)
			continue
		}

		// Count tokens that need revocation
		if providerToken.AccessToken != "" {
			totalTokensToRevoke++
		}
		if providerToken.RefreshToken != "" {
			totalTokensToRevoke++
		}

		// Revoke access token at provider with retry logic
		if providerToken.AccessToken != "" {
			if err := s.revokeTokenWithRetry(ctx, providerToken.AccessToken, "access", userID, clientID); err != nil {
				failedAtProvider++
			} else {
				revokedAtProvider++
			}
		}

		// Also revoke refresh token at provider if present
		if providerToken.RefreshToken != "" {
			if err := s.revokeTokenWithRetry(ctx, providerToken.RefreshToken, "refresh", userID, clientID); err != nil {
				failedAtProvider++
			} else {
				revokedAtProvider++
			}
		}
	}

	// Calculate failure rate
	failureRate := 0.0
	if totalTokensToRevoke > 0 {
		failureRate = float64(failedAtProvider) / float64(totalTokensToRevoke)
	}

	s.Logger.Info("Provider revocation complete",
		"user_id", userID,
		"client_id", clientID,
		"revoked_at_provider", revokedAtProvider,
		"failed_at_provider", failedAtProvider,
		"total_tokens", totalTokensToRevoke,
		"failure_rate", fmt.Sprintf("%.2f%%", failureRate*100))

	// SECURITY: Check failure threshold - fail hard if too many provider revocations failed
	// This ensures we don't proceed when tokens remain valid at the provider
	if totalTokensToRevoke > 0 && failureRate > s.Config.ProviderRevocationFailureThreshold {
		s.Logger.Error("CRITICAL: Provider revocation failure rate exceeds threshold",
			"user_id", userID,
			"client_id", clientID,
			"failure_rate", fmt.Sprintf("%.2f%%", failureRate*100),
			"threshold", fmt.Sprintf("%.2f%%", s.Config.ProviderRevocationFailureThreshold*100),
			"failed_count", failedAtProvider,
			"total_count", totalTokensToRevoke)

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "provider_revocation_threshold_exceeded",
				UserID:   userID,
				ClientID: clientID,
				Details: map[string]any{
					"severity":       "critical",
					"impact":         "Too many tokens remain valid at provider",
					"failure_rate":   failureRate,
					"threshold":      s.Config.ProviderRevocationFailureThreshold,
					"failed_count":   failedAtProvider,
					"total_count":    totalTokensToRevoke,
					"oauth_spec":     "OAuth 2.1 Section 4.1.2",
					"action":         "Manual provider-side revocation REQUIRED",
					"recommendation": "Check provider API status and network connectivity",
				},
			})
		}

		return fmt.Errorf("provider revocation failure rate %.2f%% exceeds threshold %.2f%% (%d/%d failed) - tokens may remain valid at provider",
			failureRate*100, s.Config.ProviderRevocationFailureThreshold*100, failedAtProvider, totalTokensToRevoke)
	}

	// SECURITY: Alert if ALL provider revocations failed (100% failure)
	if revokedAtProvider == 0 && totalTokensToRevoke > 0 {
		s.Logger.Error("CRITICAL: All provider revocations failed - tokens still valid at provider!",
			"user_id", userID,
			"client_id", clientID,
			"token_count", totalTokensToRevoke)

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "provider_revocation_complete_failure",
				UserID:   userID,
				ClientID: clientID,
				Details: map[string]any{
					"severity":    "critical",
					"impact":      "All tokens remain valid at provider",
					"token_count": totalTokensToRevoke,
					"oauth_spec":  "OAuth 2.1 Section 4.1.2",
					"mitigation":  "Tokens revoked locally but still usable at provider",
					"action":      "Immediate manual provider-side revocation REQUIRED",
				},
			})
		}

		return fmt.Errorf("all provider revocations failed (0/%d succeeded) - tokens remain valid at provider", totalTokensToRevoke)
	}

	// Now revoke locally
	revokedCount, err := revocationStore.RevokeAllTokensForUserClient(userID, clientID)
	if err != nil {
		s.Logger.Error("Failed to revoke tokens locally",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
		return fmt.Errorf("failed to revoke tokens locally: %w", err)
	}

	// Log the revocation
	s.Logger.Warn("Revoked all tokens for user+client due to security event",
		"user_id", userID,
		"client_id", clientID,
		"tokens_revoked_locally", revokedCount,
		"tokens_revoked_at_provider", revokedAtProvider,
		"reason", "reuse_detection")

	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type:     "all_tokens_revoked",
			UserID:   userID,
			ClientID: clientID,
			Details: map[string]any{
				"severity":                "critical",
				"tokens_revoked_local":    revokedCount,
				"tokens_revoked_provider": revokedAtProvider,
				"reason":                  "authorization_code_reuse_detected",
				"oauth_spec":              "OAuth 2.1 Section 4.1.2",
			},
		})
	}

	return nil
}

// revokeTokenWithRetry attempts to revoke a token at the provider with exponential backoff retry logic.
// Returns nil if revocation succeeds within the retry limit, or an error if all attempts fail.
// Implements exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms between retries.
func (s *Server) revokeTokenWithRetry(ctx context.Context, token, tokenType, userID, clientID string) error {
	maxRetries := s.Config.ProviderRevocationMaxRetries
	timeout := time.Duration(s.Config.ProviderRevocationTimeout) * time.Second

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Create per-attempt timeout context
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)

		// Attempt revocation
		err := s.provider.RevokeToken(attemptCtx, token)
		cancel() // Clean up context immediately after attempt

		if err == nil {
			// Success - log if this wasn't the first attempt
			if attempt > 0 {
				s.Logger.Info("Provider token revocation succeeded after retry",
					"token_type", tokenType,
					"attempt", attempt+1,
					"max_retries", maxRetries,
					"user_id", userID,
					"client_id", clientID)
			}
			return nil
		}

		lastErr = err

		// Check if we should retry (not on last attempt)
		if attempt < maxRetries {
			// Exponential backoff: 100ms * 2^attempt
			backoffDuration := time.Duration(100*math.Pow(2, float64(attempt))) * time.Millisecond

			// Don't log transient failures at high severity - only on final failure
			s.Logger.Debug("Provider token revocation failed, retrying",
				"token_type", tokenType,
				"attempt", attempt+1,
				"max_retries", maxRetries,
				"backoff_ms", backoffDuration.Milliseconds(),
				"error", err)

			// Wait before retry (check for context cancellation)
			select {
			case <-ctx.Done():
				return fmt.Errorf("revocation cancelled during backoff: %w", ctx.Err())
			case <-time.After(backoffDuration):
				// Continue to next retry
			}
		}
	}

	// All attempts failed
	s.Logger.Warn("Provider token revocation failed after all retries",
		"token_type", tokenType,
		"attempts", maxRetries+1,
		"user_id", userID,
		"client_id", clientID,
		"final_error", lastErr)

	return fmt.Errorf("provider revocation failed after %d attempts: %w", maxRetries+1, lastErr)
}
