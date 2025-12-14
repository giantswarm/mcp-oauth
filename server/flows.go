package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/util"
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

// OAuthSpecVersion is the OAuth specification version this library implements.
// Note: This is intentionally duplicated from constants.go to avoid circular imports.
// Keep in sync with constants.go.
const OAuthSpecVersion = "OAuth 2.1"

// normalizeScopes splits a space-separated scope string and filters out empty values.
// This handles malformed input gracefully by trimming whitespace and removing empty entries.
// Returns nil if the input is empty or contains only whitespace.
func normalizeScopes(scope string) []string {
	if scope == "" {
		return nil
	}

	var scopes []string
	for _, s := range strings.Split(scope, " ") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}

// logAuthCodeValidationFailure logs authorization code validation failures with
// consistent formatting and returns a generic error per RFC 6749.
// This helper reduces code duplication and ensures consistent error handling.
func (s *Server) logAuthCodeValidationFailure(reason, clientID, userID, codePrefix string) error {
	s.Logger.Debug("Authorization code validation failed",
		"reason", reason,
		"client_id", clientID,
		"user_id", userID,
		"code_prefix", codePrefix)

	if s.Auditor != nil {
		s.Auditor.LogAuthFailure(userID, clientID, "", reason)
	}

	// Return generic error per RFC 6749 (don't reveal details to attacker)
	return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
}

// isTokenExpiredLocally checks if a token is expired considering clock skew grace period.
// Returns true if the token is expired beyond the grace period.
func (s *Server) isTokenExpiredLocally(token *oauth2.Token) bool {
	gracePeriod := time.Duration(s.Config.ClockSkewGracePeriod) * time.Second
	expiryWithGrace := token.Expiry.Add(gracePeriod)
	return time.Now().After(expiryWithGrace)
}

// shouldProactivelyRefresh determines if a token should be proactively refreshed based on
// expiry threshold and refresh token availability.
func (s *Server) shouldProactivelyRefresh(token *oauth2.Token) bool {
	if token.RefreshToken == "" {
		return false
	}

	refreshThreshold := time.Duration(s.Config.TokenRefreshThreshold) * time.Second
	timeUntilExpiry := time.Until(token.Expiry)

	return timeUntilExpiry > 0 && timeUntilExpiry <= refreshThreshold
}

// attemptProactiveRefresh attempts to refresh a token that is near expiry.
// This is a graceful operation - failures are logged but don't affect the validation flow.
func (s *Server) attemptProactiveRefresh(ctx context.Context, accessToken string, storedToken *oauth2.Token) {
	refreshThreshold := time.Duration(s.Config.TokenRefreshThreshold) * time.Second
	timeUntilExpiry := time.Until(storedToken.Expiry)

	s.Logger.Debug("Token near expiry, attempting proactive refresh",
		"expiry", storedToken.Expiry,
		"time_until_expiry", timeUntilExpiry,
		"refresh_threshold", refreshThreshold,
		"token_prefix", util.SafeTruncate(accessToken, 8))

	// Attempt to refresh the provider token
	newProviderToken, err := s.provider.RefreshToken(ctx, storedToken.RefreshToken)
	if err != nil {
		// Refresh failed - log warning but continue with validation (graceful degradation)
		s.Logger.Warn("Proactive token refresh failed, falling back to validation",
			"error", err,
			"token_prefix", util.SafeTruncate(accessToken, 8),
			"time_until_expiry", timeUntilExpiry)

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type: security.EventProactiveRefreshFailed,
				Details: map[string]any{
					"error":             err.Error(),
					"time_until_expiry": timeUntilExpiry.String(),
					"fallback":          "validation",
				},
			})
		}
		return
	}

	// Refresh succeeded - update stored token
	if err := s.tokenStore.SaveToken(ctx, accessToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save refreshed token",
			"error", err,
			"token_prefix", util.SafeTruncate(accessToken, 8))
		return
	}

	s.Logger.Info("Token proactively refreshed",
		"old_expiry", storedToken.Expiry,
		"new_expiry", newProviderToken.Expiry,
		"token_prefix", util.SafeTruncate(accessToken, 8))

	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type: security.EventTokenProactivelyRefreshed,
			Details: map[string]any{
				"old_expiry": storedToken.Expiry,
				"new_expiry": newProviderToken.Expiry,
				"threshold":  refreshThreshold.String(),
			},
		})
	}
}

// ValidateToken validates an access token with local expiry check and provider validation.
// This implements defense-in-depth by checking token expiry locally BEFORE delegating to
// the provider, preventing expired tokens from being accepted due to clock skew.
//
// Validation flow:
// 1. Check if token exists in local storage
// 2. If found, validate expiry locally (with ClockSkewGracePeriod)
// 3. RFC 8707: Validate audience binding (token intended for this resource server)
// 4. If expired locally, return error immediately (don't call provider)
// 5. Validate with provider (external check)
// 6. Store updated user info
//
// Note: Rate limiting should be done at the HTTP layer with IP address, not here with token
func (s *Server) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// SECURITY: Check local token expiry BEFORE calling provider
	// This prevents expired tokens from being accepted if provider's clock is skewed
	storedToken, err := s.tokenStore.GetToken(ctx, accessToken)
	if err == nil {
		// Token found - validate expiry with grace period for clock skew
		if s.isTokenExpiredLocally(storedToken) {
			s.Logger.Debug("Token expired locally",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.Config.ClockSkewGracePeriod,
				"token_prefix", util.SafeTruncate(accessToken, 8))

			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", "", "", "token_expired_locally")
			}

			return nil, fmt.Errorf("access token expired (local validation)")
		}

		s.Logger.Debug("Token passed local expiry validation",
			"expiry", storedToken.Expiry,
			"grace_period_seconds", s.Config.ClockSkewGracePeriod)

		// RFC 8707: CRITICAL SECURITY - Validate token audience binding
		// This prevents token theft and replay attacks across different resource servers
		if metadataStore, ok := s.tokenStore.(interface {
			GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error)
		}); ok {
			metadata, err := metadataStore.GetTokenMetadata(accessToken)
			if err == nil && metadata.Audience != "" {
				// Token has audience binding - validate it matches this resource server
				expectedAudience := s.Config.GetResourceIdentifier()
				// Normalize URLs to handle trailing slash differences
				// RFC 8707 doesn't specify trailing slash handling, but practical clients
				// may send resource identifiers with or without trailing slashes
				normalizedAudience := util.NormalizeURL(metadata.Audience)
				normalizedExpected := util.NormalizeURL(expectedAudience)
				// SECURITY: Use constant-time comparison to prevent timing attacks
				// Although audience is not secret, this follows security best practices
				if subtle.ConstantTimeCompare([]byte(normalizedAudience), []byte(normalizedExpected)) != 1 {
					// Rate limit logging to prevent DoS via repeated audience mismatch attempts
					if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(metadata.UserID+":"+metadata.ClientID+":audience_mismatch") {
						s.Logger.Warn("Token audience mismatch - token not intended for this resource server",
							"token_audience", metadata.Audience,
							"server_identifier", expectedAudience,
							"token_prefix", util.SafeTruncate(accessToken, 8),
							"user_id", metadata.UserID,
							"client_id", metadata.ClientID)
					}

					if s.Auditor != nil {
						s.Auditor.LogEvent(security.Event{
							Type:     security.EventResourceMismatch,
							UserID:   metadata.UserID,
							ClientID: metadata.ClientID,
							Details: map[string]any{
								"severity":          "critical",
								"token_audience":    metadata.Audience,
								"server_identifier": expectedAudience,
								"attack_indicator":  "token_replay_to_wrong_resource_server",
							},
						})
						s.Auditor.LogAuthFailure(metadata.UserID, metadata.ClientID, "", "audience_mismatch")
					}

					return nil, fmt.Errorf("token not intended for this resource server (RFC 8707 audience mismatch)")
				}

				s.Logger.Debug("Token audience validation passed",
					"audience", metadata.Audience,
					"token_prefix", util.SafeTruncate(accessToken, 8))
			}
		}

		// PROACTIVE REFRESH: Check if token is near expiry and should be refreshed
		// This improves UX by preventing validation failures when refresh is available
		if s.shouldProactivelyRefresh(storedToken) {
			s.attemptProactiveRefresh(ctx, accessToken, storedToken)
		}
	}

	// Determine which token to use for provider validation:
	// - If we found a stored provider token, use its access token (the Google token)
	// - If no stored token found, fall back to the input token (backward compatibility
	//   for tokens from a different instance or direct provider tokens)
	tokenForProviderValidation := accessToken
	if storedToken != nil && storedToken.AccessToken != "" {
		tokenForProviderValidation = storedToken.AccessToken
	}

	// Validate with provider
	userInfo, err := s.provider.ValidateToken(ctx, tokenForProviderValidation)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", "", "", err.Error())
		}
		return nil, err
	}

	// Store user info
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, userInfo); err != nil {
		s.Logger.Warn("Failed to save user info", "error", err)
	}

	return userInfo, nil
}

// StartAuthorizationFlow starts a new OAuth authorization flow
// clientState is the state parameter from the client (REQUIRED for CSRF protection)
// resource is the target resource server identifier per RFC 8707 (optional for backward compatibility)
func (s *Server) StartAuthorizationFlow(ctx context.Context, clientID, redirectURI, scope, resource, codeChallenge, codeChallengeMethod, clientState string) (string, error) {
	// CRITICAL SECURITY: Validate state parameter from client for CSRF protection
	// This includes minimum length validation to prevent timing attacks
	if err := s.validateStateParameter(clientState); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "invalid_state_parameter")
		}
		return "", fmt.Errorf("%w (OAuth 2.0 Security BCP)", err)
	}

	// Generate server-side state if client didn't provide one (when AllowNoStateParameter=true)
	// This is needed for internal tracking even when client state is not required
	trackingState := clientState
	if trackingState == "" {
		trackingState = generateRandomToken()
		s.Logger.Debug("Generated server-side state for client without state parameter",
			"client_id", clientID)
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

	// Validate client - use getOrFetchClient to support URL-based client IDs (CIMD)
	// This enables the Client ID Metadata Document feature per MCP 2025-11-25 spec
	client, err := s.getOrFetchClient(ctx, clientID)
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

	// SECURITY: Authorization-time redirect URI validation (TOCTOU protection)
	// This re-validates the redirect URI security at authorization time to catch
	// DNS rebinding attacks where the hostname resolved to a safe IP at registration
	// but now resolves to an internal IP. Only enabled when
	// Config.ValidateRedirectURIAtAuthorization=true.
	if err := s.ValidateRedirectURIAtAuthorizationTime(ctx, redirectURI); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", "redirect_uri_security_violation")
		}
		s.Logger.Warn("Redirect URI failed authorization-time security validation",
			"client_id", clientID,
			"redirect_uri", sanitizeURIForLogging(redirectURI),
			"error", err.Error())
		return "", fmt.Errorf("%s: redirect URI failed security validation", ErrorCodeInvalidRequest)
	}

	// If client didn't provide scopes, use provider's default scopes
	// This is essential for OAuth proxy pattern where server knows required scopes
	// Only use defaults that the client is authorized for (intersection)
	scope = s.resolveScopes(scope, client)

	// SECURITY: Validate scope string length to prevent DoS attacks
	// This must happen before parsing/processing the scope string
	if len(scope) > s.Config.MaxScopeLength {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("scope_too_long: %d characters (max: %d)", len(scope), s.Config.MaxScopeLength))
		}
		return "", fmt.Errorf("%s: scope parameter exceeds maximum length of %d characters", ErrorCodeInvalidScope, s.Config.MaxScopeLength)
	}

	// Validate scopes against server configuration
	if err := s.validateScopes(scope); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("%s: %v", ErrorCodeInvalidScope, err))
		}
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidScope, err)
	}

	// SECURITY: Validate scopes against client's allowed scopes (OAuth 2.0 Security)
	// This prevents scope escalation where a client requests scopes it's not authorized for
	if err := s.validateClientScopes(scope, client.Scopes); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("%s: %v", ErrorCodeInvalidScope, err))
		}
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidScope, err)
	}

	// RFC 8707: Validate resource parameter if provided
	// The resource parameter binds tokens to a specific resource server for security
	if resource != "" {
		if err := s.validateResourceParameter(resource); err != nil {
			if s.Auditor != nil {
				s.Auditor.LogAuthFailure("", clientID, "", fmt.Sprintf("invalid_resource: %v", err))
			}
			return "", fmt.Errorf("%s: resource parameter is invalid: %w", ErrorCodeInvalidRequest, err)
		}
	}

	// Log authorization flow start
	if s.Auditor != nil {
		details := map[string]any{
			"redirect_uri":          redirectURI,
			"scope":                 scope,
			"code_challenge_method": codeChallengeMethod,
		}
		// RFC 8707: Include resource parameter in audit log if provided
		if resource != "" {
			details["resource"] = resource
		}
		s.Auditor.LogEvent(security.Event{
			Type:     security.EventAuthorizationFlowStarted,
			ClientID: clientID,
			Details:  details,
		})
	}

	// Generate provider state (different from client state for defense in depth)
	providerState := generateRandomToken()

	// Generate PKCE for server-to-provider leg (OAuth 2.1)
	providerCodeChallenge, providerCodeVerifier := generatePKCEPair()

	// Save authorization state with both client and server PKCE parameters and resource binding
	// Use trackingState (which may be server-generated if client didn't provide state)
	authState := &storage.AuthorizationState{
		StateID:              trackingState,
		OriginalClientState:  clientState, // Empty if client didn't provide state
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		Scope:                scope,
		Resource:             resource, // RFC 8707: Bind authorization to target resource server
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		ProviderState:        providerState,
		ProviderCodeVerifier: providerCodeVerifier,
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
	}
	if err := s.flowStore.SaveAuthorizationState(ctx, authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Parse scopes to pass to provider
	// If client didn't request scopes, pass empty slice and provider will use its defaults
	requestedScopes := normalizeScopes(scope)

	// Generate authorization URL with server-generated PKCE and requested scopes
	authURL := s.provider.AuthorizationURL(providerState, providerCodeChallenge, "S256", requestedScopes)

	return authURL, nil
}

// HandleProviderCallback handles the callback from the OAuth provider
// Returns: (authorizationCode, clientState, error)
// clientState is the original state parameter from the client for CSRF validation
func (s *Server) HandleProviderCallback(ctx context.Context, providerState, code string) (*storage.AuthorizationCode, string, error) {
	// CRITICAL SECURITY: Validate provider state parameter
	// Defense in depth: validate even though we generated it
	if err := s.validateStateParameter(providerState); err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type: security.EventInvalidProviderCallback,
				Details: map[string]any{
					"reason": "invalid_state_format",
				},
			})
		}
		return nil, "", fmt.Errorf("invalid state parameter: %w", err)
	}

	// CRITICAL SECURITY: Validate provider state to prevent callback injection
	// We must lookup by providerState (not client state) since that's what the provider returns
	authState, err := s.flowStore.GetAuthorizationStateByProviderState(ctx, providerState)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type: security.EventInvalidProviderCallback,
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
				Type:     security.EventProviderStateMismatch,
				ClientID: authState.ClientID,
				Details: map[string]any{
					"severity": "critical",
				},
			})
		}
		return nil, "", fmt.Errorf("state parameter mismatch")
	}

	// Save the client's original state before deletion
	// Use OriginalClientState which is empty if client didn't provide state
	clientState := authState.OriginalClientState

	// Save provider verifier before deleting state
	providerVerifier := authState.ProviderCodeVerifier

	// Delete authorization state (one-time use)
	_ = s.flowStore.DeleteAuthorizationState(ctx, providerState)

	// Exchange code with provider using PKCE verification
	providerToken, err := s.provider.ExchangeCode(ctx, code, providerVerifier)
	if err != nil {
		// SECURITY: Log PKCE validation failures for security monitoring
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type: security.EventProviderCodeExchangeFailed,
				Details: map[string]any{
					"provider":     s.provider.Name(),
					"error":        err.Error(),
					"pkce_enabled": providerVerifier != "",
					"client_id":    authState.ClientID,
					"state_id":     util.SafeTruncate(providerState, 16),
				},
			})
		}
		return nil, "", fmt.Errorf("failed to exchange code with provider: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.provider.ValidateToken(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user info: %w", err)
	}

	// Save user info and token by ID
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, userInfo); err != nil {
		s.Logger.Warn("Failed to save user info", "error", err)
	}
	if err := s.tokenStore.SaveToken(ctx, userInfo.ID, providerToken); err != nil {
		s.Logger.Warn("Failed to save provider token", "error", err)
	}

	// Also save token by email for applications that look up by email address
	// This is common in multi-account scenarios where email is the natural identifier
	if userInfo.Email != "" && userInfo.Email != userInfo.ID {
		if err := s.tokenStore.SaveUserInfo(ctx, userInfo.Email, userInfo); err != nil {
			s.Logger.Warn("Failed to save user info by email", "error", err)
		}
		if err := s.tokenStore.SaveToken(ctx, userInfo.Email, providerToken); err != nil {
			s.Logger.Warn("Failed to save provider token by email", "error", err)
		}
	}

	// Generate authorization code using oauth2.GenerateVerifier (same quality)
	authCode := generateRandomToken()

	// Create authorization code object with resource binding (RFC 8707)
	authCodeObj := &storage.AuthorizationCode{
		Code:                authCode,
		ClientID:            authState.ClientID,
		RedirectURI:         authState.RedirectURI,
		Scope:               authState.Scope,
		Resource:            authState.Resource, // RFC 8707: Carry resource from authorization request
		Audience:            authState.Resource, // RFC 8707: Audience = resource for token binding
		CodeChallenge:       authState.CodeChallenge,
		CodeChallengeMethod: authState.CodeChallengeMethod,
		UserID:              userInfo.ID,
		ProviderToken:       providerToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
		Used:                false,
	}

	// Save authorization code
	if err := s.flowStore.SaveAuthorizationCode(ctx, authCodeObj); err != nil {
		return nil, "", fmt.Errorf("failed to save authorization code: %w", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type:     security.EventAuthorizationCodeIssued,
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
// resource parameter is optional per RFC 8707 for backward compatibility
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, resource, codeVerifier string) (*oauth2.Token, string, error) {
	// Create span if tracing is enabled
	var span trace.Span
	if s.tracer != nil {
		ctx, span = s.tracer.Start(ctx, "oauth.server.exchange_authorization_code")
		defer span.End()

		span.SetAttributes(
			attribute.String("oauth.client_id", clientID),
		)
	}

	// SECURITY: Atomically check and mark authorization code as used
	// This prevents race conditions where multiple concurrent requests could use the same code
	authCode, err := s.flowStore.AtomicCheckAndMarkAuthCodeUsed(ctx, code)
	if err != nil {
		// Check if this is a reuse attempt (code already used)
		if storage.IsCodeReuseError(err) {
			// CRITICAL SECURITY: Authorization code reuse detected - this indicates a potential token theft attack
			// OAuth 2.1 requires revoking ALL tokens for this user+client when code reuse is detected

			// Record code reuse detection metric
			if s.Instrumentation != nil {
				s.Instrumentation.Metrics().RecordCodeReuseDetected(ctx)
			}

			if span != nil {
				span.SetAttributes(
					attribute.String("oauth.user_id", authCode.UserID),
					attribute.String("security.event", "code_reuse_detected"),
				)
				span.SetStatus(codes.Error, "authorization code reuse detected")
			}

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
					Type:     security.EventAuthorizationCodeReuseDetected,
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
			_ = s.flowStore.DeleteAuthorizationCode(ctx, code)

			// Return generic error per RFC 6749 (don't reveal details to attacker)
			return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
		}

		// Other error (not found, expired, etc.)
		return nil, "", s.logAuthCodeValidationFailure("invalid_authorization_code: "+err.Error(), clientID, "", util.SafeTruncate(code, 8))
	}

	// Code is now atomically marked as used - no other request can use it

	// Validate client ID matches
	if authCode.ClientID != clientID {
		return nil, "", s.logAuthCodeValidationFailure("client_id_mismatch", clientID, "", util.SafeTruncate(code, 8))
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		return nil, "", s.logAuthCodeValidationFailure("redirect_uri_mismatch", clientID, "", util.SafeTruncate(code, 8))
	}

	// RFC 8707: Validate resource parameter consistency
	if err := s.validateResourceConsistency(resource, authCode, clientID, code); err != nil {
		return nil, "", err
	}

	// CRITICAL SECURITY: Fetch client to check if PKCE is required (OAuth 2.1)
	// Public clients (mobile apps, SPAs) MUST use PKCE to prevent authorization code theft
	// Use getOrFetchClient to support URL-based client IDs (CIMD) per MCP 2025-11-25 spec
	client, err := s.getOrFetchClient(ctx, clientID)
	if err != nil {
		return nil, "", s.logAuthCodeValidationFailure("client_not_found", clientID, "", util.SafeTruncate(code, 8))
	}

	// SECURITY: Validate scopes against client's allowed scopes (OAuth 2.0 Security)
	// This is the final validation before issuing tokens - defense in depth
	// Even if authorization flow validation was bypassed, we validate again here
	if err := s.validateClientScopes(authCode.Scope, client.Scopes); err != nil {
		s.Logger.Debug("Client scope validation failed during token exchange",
			"reason", err.Error(),
			"client_id", clientID,
			"user_id", authCode.UserID,
			"requested_scope", authCode.Scope,
			"code_prefix", util.SafeTruncate(code, 8))

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     security.EventScopeEscalationAttempt,
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details: map[string]any{
					"severity":        "high",
					"requested_scope": authCode.Scope,
					"reason":          "client not authorized for requested scopes",
				},
			})
			s.Auditor.LogAuthFailure(authCode.UserID, clientID, "", fmt.Sprintf("scope_validation_failed: %v", err))
		}

		// Return generic error per RFC 6749 (don't reveal details to attacker)
		return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// CRITICAL SECURITY: Public clients SHOULD use PKCE (OAuth 2.1 requirement)
	// This prevents authorization code theft attacks where a malicious public client
	// could use another client's authorization code if intercepted
	if client.ClientType == ClientTypePublic && authCode.CodeChallenge == "" {
		// Check if insecure public clients are explicitly allowed for legacy compatibility
		if !s.Config.AllowPublicClientsWithoutPKCE {
			// SECURITY: Log detailed internal error for security monitoring
			s.Logger.Error("Public client attempted token exchange without PKCE",
				"client_id", clientID,
				"user_id", authCode.UserID,
				"client_type", client.ClientType,
				"oauth_spec", OAuthSpecVersion,
				"code_prefix", util.SafeTruncate(code, 8))

			if s.Auditor != nil {
				s.Auditor.LogEvent(security.Event{
					Type:     security.EventPKCERequiredForPublicClient,
					UserID:   authCode.UserID,
					ClientID: clientID,
					Details: map[string]any{
						"severity":    "high",
						"client_type": client.ClientType,
						"oauth_spec":  OAuthSpecVersion,
						"reason":      "Public clients must use PKCE to prevent authorization code theft",
					},
				})
				s.Auditor.LogAuthFailure(authCode.UserID, clientID, "", "pkce_required_for_public_client")
			}

			// Return generic error per RFC 6749 (don't reveal security details to attacker)
			return nil, "", fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
		}

		// WARNING: Proceeding without PKCE for public client (insecure configuration)
		s.Logger.Warn("INSECURE: Public client token exchange without PKCE allowed by configuration",
			"client_id", clientID,
			"user_id", authCode.UserID,
			"client_type", client.ClientType,
			"security_risk", "authorization_code_theft",
			"oauth_spec_violation", OAuthSpecVersion+" Section 7.6",
			"recommendation", "Update client to support PKCE or set AllowPublicClientsWithoutPKCE=false")

		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     security.EventInsecurePublicClientWithoutPKCE,
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details: map[string]any{
					"severity":    "warning",
					"client_type": client.ClientType,
					"oauth_spec":  OAuthSpecVersion,
					"risk":        "authorization_code_theft",
					"config":      "AllowPublicClientsWithoutPKCE=true",
				},
			})
		}
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if err := s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier); err != nil {
			// Record PKCE validation failure metric
			if s.Instrumentation != nil {
				s.Instrumentation.Metrics().RecordPKCEValidationFailed(ctx, authCode.CodeChallengeMethod)
			}

			if span != nil {
				span.SetAttributes(
					attribute.String("oauth.pkce_method", authCode.CodeChallengeMethod),
					attribute.String("security.event", "pkce_validation_failed"),
				)
				span.RecordError(err)
				span.SetStatus(codes.Error, "PKCE validation failed")
			}

			if s.Auditor != nil {
				// This is a security event - log it separately
				s.Auditor.LogEvent(security.Event{
					Type:     security.EventPKCEValidationFailed,
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
	if err := s.tokenStore.SaveToken(ctx, accessToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save access token mapping", "error", err)
	}

	// Store refresh token -> provider token mapping (for refresh flow)
	if err := s.tokenStore.SaveToken(ctx, refreshToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save refresh token", "error", err)
	}

	// Track access token metadata for revocation (OAuth 2.1 code reuse detection)
	// RFC 8707: Store audience binding with tokens for validation
	// MCP 2025-11-25: Store scopes with tokens for scope validation

	// Parse scopes from authorization code
	tokenScopes := normalizeScopes(authCode.Scope)

	// Store access token metadata (tries scopes+audience, audience-only, then basic)
	s.saveTokenMetadata(accessToken, authCode.UserID, clientID, "access", authCode.Audience, tokenScopes)

	// CRITICAL: Also save refresh token metadata for revocation
	// Refresh tokens inherit the audience and scopes from the authorization code
	s.saveTokenMetadata(refreshToken, authCode.UserID, clientID, "refresh", authCode.Audience, tokenScopes)

	// Track refresh token with expiry (OAuth 2.1 security)
	// Use family tracking if storage supports it (for reuse detection)
	refreshTokenExpiry := time.Now().Add(time.Duration(s.Config.RefreshTokenTTL) * time.Second)
	if familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); ok {
		// Create new token family (generation 0)
		familyID := generateRandomToken()
		if err := familyStore.SaveRefreshTokenWithFamily(ctx, refreshToken, authCode.UserID, clientID, familyID, 0, refreshTokenExpiry); err != nil {
			s.Logger.Warn("Failed to track refresh token with family", "error", err)
		} else {
			s.Logger.Debug("Created new refresh token family",
				"user_id", authCode.UserID,
				"family_id", util.SafeTruncate(familyID, 8))
		}
	} else {
		// Fallback to basic tracking
		if err := s.tokenStore.SaveRefreshToken(ctx, refreshToken, authCode.UserID, refreshTokenExpiry); err != nil {
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

	// Record success in span
	if span != nil {
		span.SetAttributes(
			attribute.String("oauth.user_id", authCode.UserID),
			attribute.String("oauth.scope", authCode.Scope),
		)
		span.SetStatus(codes.Ok, "code exchanged successfully")
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
	userID, providerToken, err := s.tokenStore.AtomicGetAndDeleteRefreshToken(ctx, refreshToken)

	if err != nil {
		// SECURITY: Distinguish between "not found" errors (potential reuse) and transient errors
		// Only check for reuse if the error indicates the token was not found or already deleted
		// Transient errors (storage timeout, network issues) should not trigger reuse detection
		isNotFoundOrExpired := storage.IsNotFoundError(err) || storage.IsExpiredError(err)

		// Token not found or already deleted - check if this is a reuse attempt
		// SECURITY FIX: Check family AFTER atomic delete to eliminate TOCTOU vulnerability
		if isNotFoundOrExpired && supportsFamilies {
			family, famErr := familyStore.GetRefreshTokenFamily(ctx, refreshToken)
			if famErr == nil {
				// Family exists but token was already deleted/rotated → REUSE DETECTED!
				// Check if family was previously revoked
				if family.Revoked {
					// Attempted use of token from previously revoked family
					if s.Auditor != nil {
						s.Auditor.LogEvent(security.Event{
							Type:     security.EventRevokedTokenFamilyReuseAttempt,
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
						"family_id", util.SafeTruncate(family.FamilyID, 8))
					return nil, fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
				}

				// Token is deleted but family exists and NOT revoked → FRESH REUSE DETECTED!
				// This means someone is trying to use an old (rotated) refresh token

				// Record token reuse detection metric
				if s.Instrumentation != nil {
					s.Instrumentation.Metrics().RecordTokenReuseDetected(ctx)
				}

				// Rate limit logging to prevent DoS via log flooding
				if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(family.UserID+":"+clientID) {
					s.Logger.Error("Refresh token reuse detected - token was rotated but still being used",
						"user_id", family.UserID,
						"client_id", clientID,
						"family_id", util.SafeTruncate(family.FamilyID, 8),
						"generation", family.Generation,
						"oauth_spec", "OAuth 2.1 Refresh Token Rotation")
				}

				// Step 1: Revoke entire token family (OAuth 2.1 requirement)
				if err := familyStore.RevokeRefreshTokenFamily(ctx, family.FamilyID); err != nil {
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
						Type:     security.EventRefreshTokenReuseDetected,
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

		// Determine error type for appropriate logging and response
		// Transient errors (storage timeouts, network issues) should be logged differently
		// than "not found" errors which indicate invalid or reused tokens
		if !isNotFoundOrExpired {
			// Transient error - log as warning and return server error
			s.Logger.Warn("Transient error during refresh token validation",
				"error", err.Error(),
				"client_id", clientID,
				"token_prefix", util.SafeTruncate(refreshToken, 8))

			if s.Auditor != nil {
				s.Auditor.LogEvent(security.Event{
					Type:     security.EventAuthFailure,
					ClientID: clientID,
					Details: map[string]any{
						"reason":     "transient_storage_error",
						"error_type": "transient",
					},
				})
			}
			// Return generic error - don't expose internal storage issues
			return nil, fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
		}

		// Token not found and no family metadata - regular invalid token error
		// SECURITY: Log detailed internal error for debugging, but return generic error to client
		s.Logger.Debug("Refresh token validation failed",
			"reason", err.Error(),
			"client_id", clientID,
			"token_prefix", util.SafeTruncate(refreshToken, 8))

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
			family, err := familyStore.GetRefreshTokenFamily(ctx, refreshToken)
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
		if err := s.tokenStore.DeleteRefreshToken(ctx, refreshToken); err != nil {
			s.Logger.Warn("Failed to delete old refresh token", "error", err)
		}
		if err := s.tokenStore.DeleteToken(ctx, refreshToken); err != nil {
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
			if err := familyStore.SaveRefreshTokenWithFamily(ctx, newRefreshToken, userID, clientID, familyID, generation, refreshTokenExpiry); err != nil {
				s.Logger.Warn("Failed to save refresh token with family", "error", err)
			}
		} else {
			if err := s.tokenStore.SaveRefreshToken(ctx, newRefreshToken, userID, refreshTokenExpiry); err != nil {
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
	if err := s.tokenStore.SaveToken(ctx, newAccessToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new access token", "error", err)
	}

	// Store new refresh token -> provider token mapping
	if err := s.tokenStore.SaveToken(ctx, newRefreshToken, newProviderToken); err != nil {
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
	providerToken, err := s.tokenStore.GetToken(ctx, token)
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
	if err := s.tokenStore.DeleteToken(ctx, token); err != nil {
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
				Type:     security.EventTokenRevocationNotSupported,
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
	tokens, err := revocationStore.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to get tokens for revocation: %w", err)
	}

	// SECURITY: Revoke at provider FIRST with retry logic
	// This ensures tokens are invalid at Google/GitHub/etc, not just locally
	revokedAtProvider := 0
	failedAtProvider := 0
	totalTokensToRevoke := 0

	for _, tokenID := range tokens {
		providerToken, err := s.tokenStore.GetToken(ctx, tokenID)
		if err != nil {
			s.Logger.Warn("Could not get provider token for revocation",
				"token_id", util.SafeTruncate(tokenID, 8),
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
				Type:     security.EventProviderRevocationThresholdExceeded,
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
				Type:     security.EventProviderRevocationCompleteFailure,
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
	revokedCount, err := revocationStore.RevokeAllTokensForUserClient(ctx, userID, clientID)
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
			Type:     security.EventAllTokensRevoked,
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

// resolveScopes determines the final scopes to use for an authorization flow.
// If requestedScope is provided, it's used as-is.
// If empty, provider defaults are used, filtered by client's allowed scopes.
func (s *Server) resolveScopes(requestedScope string, client *storage.Client) string {
	// If client provided scopes, use them
	if requestedScope != "" {
		return requestedScope
	}

	// Get provider defaults
	defaultScopes := s.provider.DefaultScopes()
	if len(defaultScopes) == 0 {
		return ""
	}

	// SECURITY: Audit when default scopes are applied for forensics and compliance
	// This helps track which clients rely on provider defaults vs explicit scopes
	var resolvedScopes string
	if len(client.Scopes) == 0 {
		// Client has no restrictions, use all provider defaults
		resolvedScopes = strings.Join(defaultScopes, " ")
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     security.EventScopeDefaultsApplied,
				ClientID: client.ClientID,
				Details: map[string]any{
					"provider":          s.provider.Name(),
					"provider_defaults": defaultScopes,
					"resolved_scopes":   resolvedScopes,
					"client_restricted": false,
				},
			})
		}
	} else {
		// Build intersection - only provider defaults that client is authorized for
		authorizedScopes := intersectScopes(defaultScopes, client.Scopes)
		resolvedScopes = strings.Join(authorizedScopes, " ")
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     security.EventScopeDefaultsApplied,
				ClientID: client.ClientID,
				Details: map[string]any{
					"provider":           s.provider.Name(),
					"provider_defaults":  defaultScopes,
					"client_allowed":     client.Scopes,
					"resolved_scopes":    resolvedScopes,
					"client_restricted":  true,
					"intersection_count": len(authorizedScopes),
				},
			})
		}
	}

	return resolvedScopes
}

// intersectScopes returns scopes that exist in both slices.
// The order is preserved from the first slice (a).
func intersectScopes(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}

	scopeSet := make(map[string]bool, len(b))
	for _, scope := range b {
		scopeSet[scope] = true
	}

	var result []string
	for _, scope := range a {
		if scopeSet[scope] {
			result = append(result, scope)
		}
	}
	return result
}
