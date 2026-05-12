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

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
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

// logAuthCodeValidationFailure logs authorization code validation failures with
// consistent formatting and returns a generic error per RFC 6749.
// This helper reduces code duplication and ensures consistent error handling.
func (s *Server) logAuthCodeValidationFailure(ctx context.Context, reason, clientID, userID, codePrefix string) error {
	s.Logger.Debug("Authorization code validation failed",
		"reason", reason,
		"client_id", clientID,
		"user_id", userID,
		"code_prefix", codePrefix)

	if s.Auditor != nil {
		s.Auditor.LogAuthFailure(ctx, userID, clientID, "", reason)
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

// registerTokenPair records the AT -> RT pairing so that provider token refreshes
// triggered by one key can also update the other.
func (s *Server) registerTokenPair(accessToken, refreshToken string) {
	s.tokenPairs.Store(accessToken, refreshToken)
	s.tokenPairsByRefresh.Store(refreshToken, accessToken)
}

// unregisterTokenPairByAccess removes both directions of a token pair using access token key.
func (s *Server) unregisterTokenPairByAccess(accessToken string) {
	pairedRT, ok := s.tokenPairs.Load(accessToken)
	s.tokenPairs.Delete(accessToken)
	if ok {
		s.tokenPairsByRefresh.Delete(pairedRT.(string))
	}
}

// unregisterTokenPairByRefresh removes both directions of a token pair using refresh token key.
func (s *Server) unregisterTokenPairByRefresh(refreshToken string) {
	pairedAT, ok := s.tokenPairsByRefresh.Load(refreshToken)
	s.tokenPairsByRefresh.Delete(refreshToken)
	if ok {
		s.tokenPairs.Delete(pairedAT.(string))
	}
}

// unregisterTokenPairIfPresent attempts cleanup regardless of whether token is
// an access token or a refresh token.
func (s *Server) unregisterTokenPairIfPresent(token string) {
	s.unregisterTokenPairByAccess(token)
	s.unregisterTokenPairByRefresh(token)
}

// preserveRefreshToken returns a copy of newToken with the old refresh token
// carried forward when the provider omitted it in the refresh response.
// OAuth 2.0 RFC 6749 Section 5.1 allows providers to omit refresh_token,
// in which case the client should keep using the previous one.
func preserveRefreshToken(newToken *oauth2.Token, oldRefreshToken string) *oauth2.Token {
	if newToken == nil || newToken.RefreshToken != "" || oldRefreshToken == "" {
		return newToken
	}
	clonedToken := *newToken
	clonedToken.RefreshToken = oldRefreshToken
	return &clonedToken
}

// updateProviderTokenMappings saves the refreshed provider token under both the
// access-token and refresh-token storage keys. This prevents the refresh-token
// mapping from becoming stale when the provider rotates refresh tokens.
func (s *Server) updateProviderTokenMappings(ctx context.Context, accessToken string, newProviderToken *oauth2.Token) {
	if saveErr := s.tokenStore.SaveToken(ctx, accessToken, newProviderToken); saveErr != nil {
		s.Logger.Warn("Failed to save refreshed provider token for access key", "error", saveErr)
	}
	if pairedRT, ok := s.tokenPairs.Load(accessToken); ok {
		if saveErr := s.tokenStore.SaveToken(ctx, pairedRT.(string), newProviderToken); saveErr != nil {
			s.Logger.Warn("Failed to save refreshed provider token for refresh key", "error", saveErr)
		}
	}
}

// fireTokenRefreshHandler invokes the registered TokenRefreshHandler (if any)
// after a provider token has been refreshed. It retrieves the userID and familyID
// from stored token metadata so callers don't need to plumb them through.
func (s *Server) fireTokenRefreshHandler(ctx context.Context, accessToken string, newProviderToken *oauth2.Token) {
	if s.tokenRefreshHandler == nil {
		return
	}

	var userID, familyID string
	if metaGetter, ok := s.tokenStore.(storage.TokenMetadataGetter); ok {
		if meta, err := metaGetter.GetTokenMetadata(accessToken); err == nil && meta != nil {
			userID = meta.UserID
			familyID = meta.FamilyID
		} else if err != nil {
			s.Logger.Debug("Failed to retrieve token metadata for refresh handler",
				"error", err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		}
	}

	s.tokenRefreshHandler(ctx, userID, familyID, newProviderToken)
}

// capTokenExpiry returns the earlier of the configured AccessTokenTTL-based expiry
// and the provider token's expiry, ensuring expires_in never promises more than
// the underlying provider token can deliver. Provider tokens with zero or past
// expiry are ignored.
func (s *Server) capTokenExpiry(providerExpiry time.Time) time.Time {
	expiry := time.Now().Add(time.Duration(s.Config.AccessTokenTTL) * time.Second)
	if !providerExpiry.IsZero() && providerExpiry.After(time.Now()) && providerExpiry.Before(expiry) {
		expiry = providerExpiry
	}
	return expiry
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
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	// Attempt to refresh the provider token
	newProviderToken, err := s.provider.RefreshToken(ctx, storedToken.RefreshToken)
	if err != nil {
		// Refresh failed - log warning but continue with validation (graceful degradation)
		s.Logger.Warn("Proactive token refresh failed, falling back to validation",
			"error", err,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"time_until_expiry", timeUntilExpiry)

		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
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

	// Preserve old refresh token if provider omitted it
	newProviderToken = preserveRefreshToken(newProviderToken, storedToken.RefreshToken)

	// Update both AT and RT storage mappings to keep provider credentials in sync
	s.updateProviderTokenMappings(ctx, accessToken, newProviderToken)

	s.fireTokenRefreshHandler(ctx, accessToken, newProviderToken)

	s.Logger.Debug("Token proactively refreshed",
		"old_expiry", storedToken.Expiry,
		"new_expiry", newProviderToken.Expiry,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventTokenProactivelyRefreshed,
			Details: map[string]any{
				"old_expiry": storedToken.Expiry,
				"new_expiry": newProviderToken.Expiry,
				"threshold":  refreshThreshold.String(),
			},
		})
	}
}

// ValidateToken validates an access token across all three accepted bearer
// formats. Validation is format-agnostic by design — operators of one
// server instance pick one issuance format, but operators running multiple
// instances or upgrading progressively can rely on the validator accepting
// every format their consumers have already received.
//
// Validation pipeline:
//
//  1. Self-issued JWT (when AccessTokenFormatJWT mode is on AND the bearer
//     is a JWT whose iss claim equals Config.Issuer). Local signature
//     verification against the configured public key. No provider
//     round-trip. See [Server.validateSelfIssuedJWT] for the security
//     boundary checks (signature, typ, exp, aud, jti, family).
//  2. Forwarded ID token (when the bearer is a JWT whose iss is something
//     else AND its aud matches Config.TrustedAudiences). Verified via the
//     upstream provider's JWKS for SSO token forwarding.
//  3. Opaque token (TokenStore lookup, then provider userinfo). The
//     catch-all for non-JWT bearers.
//
// Step 1 is opt-in (AccessTokenFormatJWT), step 2 is opt-in
// (TrustedAudiences), step 3 is always available. Rate limiting should be
// done at the HTTP layer with IP address, not here with the token.
//
// Error responses: callers SHOULD respond with a single 401 form
// regardless of the returned error class. The error message distinguishes
// expired / revoked / audience-mismatch / family-revoked / unknown for
// audit logs and operator dashboards; surfacing those distinctions to
// the client enables token-state probing across all three branches
// (opaque, SSO, self-issued JWT). Use the returned error for logging,
// not for setting the response body.
func (s *Server) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// PRIORITY 1: Self-issued JWT (RFC 9068, AccessTokenFormatJWT mode).
	// We peek at the unverified iss claim to decide whether to take this
	// branch — the verified parse below re-checks signature, typ, iss,
	// exp, aud, jti, and family_id before any authorization decision, so
	// the unverified peek is safe.
	//
	// A bearer that claims iss == Config.Issuer is committed to this
	// branch: any validation failure is a hard rejection. Falling through
	// to other branches would let an attacker who forges a bearer with
	// our iss bypass JWT-mode security by tripping the opaque or
	// forwarded-token path.
	if s.Config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
		userInfo, _, err := s.validateSelfIssuedJWT(ctx, accessToken)
		return userInfo, err
	}

	// PRIORITY 2: Forwarded ID token (JWT) from a trusted upstream service.
	// Must run BEFORE the opaque path, as ID tokens cannot be validated via
	// the upstream provider's userinfo endpoint.
	if len(s.Config.TrustedAudiences) > 0 && oidc.IsJWT(accessToken) {
		userInfo, err := s.validateForwardedIDToken(ctx, accessToken)
		if err != nil {
			s.Logger.Debug("Forwarded ID token validation failed, falling back to userinfo",
				"error", err.Error(),
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		} else if userInfo != nil {
			s.Logger.Debug("Forwarded ID token validated via JWKS",
				"user_id", userInfo.ID,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
			return userInfo, nil
		}
	}

	// PRIORITY 3: Opaque token (TokenStore + upstream provider userinfo).
	storedToken, err := s.validateStoredToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Determine which token to use for provider validation
	tokenForProviderValidation := s.selectTokenForProviderValidation(accessToken, storedToken)

	// Validate with provider (userinfo endpoint)
	userInfo, err := s.provider.ValidateToken(ctx, tokenForProviderValidation)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogAuthFailure(ctx, "", "", "", err.Error())
		}
		return nil, err
	}

	// Set token source to OAuth since this is the normal OAuth flow
	// (the server issued the token and the provider's ID token is stored)
	userInfo.TokenSource = providers.TokenSourceOAuth

	// Store user info
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, userInfo); err != nil {
		s.Logger.Warn("Failed to save user info", "error", err)
	}

	return userInfo, nil
}

// validateStoredToken checks if a stored token exists and validates it locally.
// Returns the stored token (may be nil if not found) or an error if validation fails.
func (s *Server) validateStoredToken(ctx context.Context, accessToken string) (*oauth2.Token, error) {
	storedToken, err := s.tokenStore.GetToken(ctx, accessToken)
	if err != nil {
		// Token not found in store - will fall back to provider validation
		return nil, nil
	}

	// Token found - validate expiry with grace period for clock skew
	if s.isTokenExpiredLocally(storedToken) {
		if storedToken.RefreshToken == "" {
			s.Logger.Debug("Token expired locally",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.Config.ClockSkewGracePeriod,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))

			if s.Auditor != nil {
				s.Auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")
			}

			return nil, fmt.Errorf("access token expired (local validation)")
		}

		// Singleflight: deduplicate concurrent refresh attempts for the same token
		result, err, _ := s.refreshGroup.Do(accessToken, func() (interface{}, error) {
			// Use a context detached from caller cancellation so one canceled
			// leader request does not fail all coalesced waiters.
			refreshCtx := context.WithoutCancel(ctx)
			return s.provider.RefreshToken(refreshCtx, storedToken.RefreshToken)
		})

		if err != nil {
			s.Logger.Debug("Token expired locally and refresh failed",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.Config.ClockSkewGracePeriod,
				"refresh_error", err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))

			if s.Auditor != nil {
				s.Auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")
			}

			return nil, fmt.Errorf("access token expired (local validation, refresh failed: %w)", err)
		}

		newProviderToken := result.(*oauth2.Token)
		newProviderToken = preserveRefreshToken(newProviderToken, storedToken.RefreshToken)
		s.updateProviderTokenMappings(ctx, accessToken, newProviderToken)

		s.fireTokenRefreshHandler(ctx, accessToken, newProviderToken)

		s.Logger.Debug("Expired provider token refreshed during validation",
			"old_expiry", storedToken.Expiry,
			"new_expiry", newProviderToken.Expiry,
			"token_suffix", helpers.TokenSuffix(accessToken, 8))
		storedToken = newProviderToken
	}

	s.Logger.Debug("Token passed local expiry validation",
		"expiry", storedToken.Expiry,
		"grace_period_seconds", s.Config.ClockSkewGracePeriod)

	// RFC 8707: Validate audience binding
	if err := s.validateTokenAudience(ctx, accessToken); err != nil {
		return nil, err
	}

	// PROACTIVE REFRESH: Check if token is near expiry and should be refreshed
	if s.shouldProactivelyRefresh(storedToken) {
		s.attemptProactiveRefresh(ctx, accessToken, storedToken)
	}

	return storedToken, nil
}

// validateTokenAudience validates RFC 8707 audience binding for the token.
// It checks if the token's audience matches this server's ResourceIdentifier or
// any of the TrustedAudiences configured for SSO token forwarding.
func (s *Server) validateTokenAudience(ctx context.Context, accessToken string) error {
	metadataStore, ok := s.tokenStore.(interface {
		GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error)
	})
	if !ok {
		return nil
	}

	metadata, err := metadataStore.GetTokenMetadata(accessToken)
	if err != nil || metadata.Audience == "" {
		return nil
	}

	expectedAudience := s.Config.GetResourceIdentifier()
	normalizedAudience := helpers.NormalizeURL(metadata.Audience)
	normalizedExpected := helpers.NormalizeURL(expectedAudience)

	// Check if audience matches this server's own resource identifier
	if subtle.ConstantTimeCompare([]byte(normalizedAudience), []byte(normalizedExpected)) == 1 {
		s.Logger.Debug("Token audience validation passed",
			"audience", metadata.Audience,
			"token_suffix", helpers.TokenSuffix(accessToken, 8))
		return nil
	}

	// Check if audience matches any of the TrustedAudiences (SSO token forwarding)
	if s.isTrustedAudience(metadata.Audience) {
		s.logCrossClientTokenAccepted(ctx, accessToken, metadata)
		return nil
	}

	// Audience mismatch - log and return error
	s.logAudienceMismatch(ctx, accessToken, metadata, expectedAudience)
	return fmt.Errorf("token not intended for this resource server (RFC 8707 audience mismatch)")
}

// isTrustedAudience checks if the given audience is in the TrustedAudiences list.
// This enables SSO scenarios where tokens issued to trusted upstream services are accepted.
// Uses helpers.MatchAudienceSecure for consistent URL normalization and constant-time comparison.
func (s *Server) isTrustedAudience(audience string) bool {
	return helpers.MatchAudienceSecure(audience, s.Config.TrustedAudiences) != ""
}

// logCrossClientTokenAccepted logs when a token is accepted via TrustedAudiences.
// This audit event helps track SSO token usage patterns for security monitoring.
func (s *Server) logCrossClientTokenAccepted(ctx context.Context, accessToken string, metadata *storage.TokenMetadata) {
	s.Logger.Debug("Token accepted via TrustedAudiences (SSO token forwarding)",
		"token_audience", metadata.Audience,
		"user_id", metadata.UserID,
		"client_id", metadata.ClientID,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventCrossClientTokenAccepted,
			UserID:   metadata.UserID,
			ClientID: metadata.ClientID,
			Details: map[string]any{
				"original_audience":   metadata.Audience,
				"server_identifier":   s.Config.GetResourceIdentifier(),
				"trusted_via":         "TrustedAudiences",
				"sso_token_forwarded": true,
			},
		})
	}
}

// logAudienceMismatch logs an audience mismatch security event.
func (s *Server) logAudienceMismatch(ctx context.Context, accessToken string, metadata *storage.TokenMetadata, expectedAudience string) {
	if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(metadata.UserID+":"+metadata.ClientID+":audience_mismatch") {
		s.Logger.Warn("Token audience mismatch - token not intended for this resource server",
			"token_audience", metadata.Audience,
			"server_identifier", expectedAudience,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"user_id", metadata.UserID,
			"client_id", metadata.ClientID)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
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
		s.Auditor.LogAuthFailure(ctx, metadata.UserID, metadata.ClientID, "", "audience_mismatch")
	}
}

// selectTokenForProviderValidation determines which token to use for provider validation.
func (s *Server) selectTokenForProviderValidation(accessToken string, storedToken *oauth2.Token) string {
	if storedToken != nil && storedToken.AccessToken != "" {
		return storedToken.AccessToken
	}
	return accessToken
}

// validatePKCEForAuthFlow validates PKCE parameters for authorization flow start
// Returns nil if validation passes, error otherwise
func (s *Server) validatePKCEForAuthFlow(ctx context.Context, clientID, codeChallenge, codeChallengeMethod string) error {
	// PKCE validation (secure by default, configurable for backward compatibility)
	if s.Config.RequirePKCE && (codeChallenge == "" || codeChallengeMethod == "") {
		s.logAuthFailure(ctx, "", clientID, "missing_pkce_parameters")
		return fmt.Errorf("PKCE is required: code_challenge and code_challenge_method parameters are mandatory (OAuth 2.1)")
	}

	// Validate PKCE method if provided
	if codeChallenge == "" {
		return nil
	}

	if codeChallengeMethod == "" {
		s.logAuthFailure(ctx, "", clientID, "missing_code_challenge_method")
		return fmt.Errorf("code_challenge_method is required when code_challenge is provided")
	}

	if codeChallengeMethod == PKCEMethodPlain && !s.Config.AllowPKCEPlain {
		s.logAuthFailure(ctx, "", clientID, "plain_pkce_not_allowed")
		return fmt.Errorf("'plain' code_challenge_method is not allowed (only S256 is supported for security)")
	}

	if codeChallengeMethod != PKCEMethodS256 && codeChallengeMethod != PKCEMethodPlain {
		s.logAuthFailure(ctx, "", clientID, fmt.Sprintf("invalid_pkce_method: %s", codeChallengeMethod))
		supportedMethods := "S256"
		if s.Config.AllowPKCEPlain {
			supportedMethods = "S256, plain"
		}
		return fmt.Errorf("unsupported code_challenge_method: %s (supported: %s)", codeChallengeMethod, supportedMethods)
	}

	return nil
}

// logAuthFailure logs an authentication failure if auditor is configured
func (s *Server) logAuthFailure(ctx context.Context, userID, clientID, reason string) {
	if s.Auditor != nil {
		s.Auditor.LogAuthFailure(ctx, userID, clientID, "", reason)
	}
}

// validateScopesForAuthFlow validates scopes for authorization flow
// Checks length, server configuration, and client authorization
func (s *Server) validateScopesForAuthFlow(ctx context.Context, clientID, scope string, clientScopes []string) error {
	// Validate scope string length to prevent DoS attacks
	if len(scope) > s.Config.MaxScopeLength {
		s.logAuthFailure(ctx, "", clientID, fmt.Sprintf("scope_too_long: %d characters (max: %d)", len(scope), s.Config.MaxScopeLength))
		return fmt.Errorf("%s: scope parameter exceeds maximum length of %d characters", ErrorCodeInvalidScope, s.Config.MaxScopeLength)
	}

	// Validate scopes against server configuration
	if err := s.validateScopes(scope); err != nil {
		s.logAuthFailure(ctx, "", clientID, fmt.Sprintf("%s: %v", ErrorCodeInvalidScope, err))
		return fmt.Errorf("%s: %w", ErrorCodeInvalidScope, err)
	}

	// Validate scopes against client's allowed scopes
	if err := s.validateClientScopes(scope, clientScopes); err != nil {
		s.logAuthFailure(ctx, "", clientID, fmt.Sprintf("%s: %v", ErrorCodeInvalidScope, err))
		return fmt.Errorf("%s: %w", ErrorCodeInvalidScope, err)
	}

	return nil
}

// handleCodeReuseDetection handles authorization code reuse security event
// Revokes all tokens and logs the security event per OAuth 2.1 requirements
func (s *Server) handleCodeReuseDetection(ctx context.Context, authCode *storage.AuthorizationCode, clientID, code string, span trace.Span) error {
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
			"user_id", authCode.UserID, "client_id", clientID, "oauth_spec", "OAuth 2.1 Section 4.1.2")
	}

	// Revoke all tokens for this user+client (OAuth 2.1 requirement)
	if err := s.RevokeAllTokensForUserClient(ctx, authCode.UserID, clientID); err != nil {
		s.Logger.Error("Failed to revoke tokens after code reuse detection", "error", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventAuthorizationCodeReuseDetected,
			UserID:   authCode.UserID,
			ClientID: clientID,
			Details: map[string]any{
				"severity": "critical", "action": "all_tokens_revoked", "oauth_spec": "OAuth 2.1 Section 4.1.2",
			},
		})
		s.Auditor.LogAuthFailure(ctx, authCode.UserID, clientID, "", "authorization_code_reuse")
	}

	_ = s.flowStore.DeleteAuthorizationCode(ctx, code)
	return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
}

// validatePublicClientPKCE validates that public clients use PKCE
// Returns error if public client is not using PKCE and it's required
func (s *Server) validatePublicClientPKCE(ctx context.Context, client *storage.Client, authCode *storage.AuthorizationCode, _ string) error {
	if client.ClientType != ClientTypePublic || authCode.CodeChallenge != "" {
		return nil // Not a public client or PKCE is used
	}

	if !s.Config.AllowPublicClientsWithoutPKCE {
		s.Logger.Error("Public client attempted token exchange without PKCE",
			"client_id", client.ClientID, "user_id", authCode.UserID,
			"client_type", client.ClientType, "oauth_spec", OAuthSpecVersion)

		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type:     security.EventPKCERequiredForPublicClient,
				UserID:   authCode.UserID,
				ClientID: client.ClientID,
				Details: map[string]any{
					"severity": "high", "client_type": client.ClientType, "oauth_spec": OAuthSpecVersion,
				},
			})
			s.Auditor.LogAuthFailure(ctx, authCode.UserID, client.ClientID, "", "pkce_required_for_public_client")
		}
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Warn about insecure configuration
	s.Logger.Warn("INSECURE: Public client token exchange without PKCE allowed by configuration",
		"client_id", client.ClientID, "user_id", authCode.UserID, "security_risk", "authorization_code_theft")

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventInsecurePublicClientWithoutPKCE,
			UserID:   authCode.UserID,
			ClientID: client.ClientID,
			Details: map[string]any{
				"severity": "warning", "client_type": client.ClientType, "config": "AllowPublicClientsWithoutPKCE=true",
			},
		})
	}
	return nil
}

// validatePKCEWithAudit validates PKCE and logs audit events on failure
func (s *Server) validatePKCEWithAudit(ctx context.Context, authCode *storage.AuthorizationCode, clientID, codeVerifier string, span trace.Span) error {
	if authCode.CodeChallenge == "" {
		return nil // No PKCE to validate
	}

	if err := s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier); err != nil {
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
			s.Auditor.LogEvent(ctx, security.Event{
				Type:     security.EventPKCEValidationFailed,
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details:  map[string]any{"reason": err.Error()},
			})
			s.Auditor.LogAuthFailure(ctx, authCode.UserID, clientID, "", fmt.Sprintf("pkce_validation_failed: %v", err))
		}
		return fmt.Errorf("PKCE validation failed: %w", err)
	}
	return nil
}

// handleRefreshTokenReuseDetection handles refresh token reuse detection
// Called when a refresh token lookup fails to check if it was already rotated
func (s *Server) handleRefreshTokenReuseDetection(ctx context.Context, refreshToken, clientID string, familyStore storage.RefreshTokenFamilyStore) error {
	family, famErr := familyStore.GetRefreshTokenFamily(ctx, refreshToken)
	if famErr != nil {
		return nil // No family found, not a reuse scenario
	}

	// Family exists but token was already deleted/rotated → REUSE DETECTED!
	if family.Revoked {
		// Attempted use of token from previously revoked family
		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type: security.EventRevokedTokenFamilyReuseAttempt, UserID: family.UserID, ClientID: clientID,
				Details: map[string]any{"severity": "critical", "family_id": family.FamilyID},
			})
		}
		s.Logger.Error("Attempted use of revoked token family",
			"user_id", family.UserID, "family_id", helpers.SafeTruncate(family.FamilyID, 8))
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Token is deleted but family exists and NOT revoked → FRESH REUSE DETECTED!
	if s.Instrumentation != nil {
		s.Instrumentation.Metrics().RecordTokenReuseDetected(ctx)
	}

	if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(family.UserID+":"+clientID) {
		s.Logger.Error("Refresh token reuse detected - token was rotated but still being used",
			"user_id", family.UserID, "client_id", clientID, "family_id", helpers.SafeTruncate(family.FamilyID, 8))
	}

	// Revoke entire token family
	if err := familyStore.RevokeRefreshTokenFamily(ctx, family.FamilyID); err != nil {
		s.Logger.Error("Failed to revoke token family", "error", err)
	}

	// Revoke all tokens for this user+client
	if err := s.RevokeAllTokensForUserClient(ctx, family.UserID, family.ClientID); err != nil {
		s.Logger.Error("Failed to revoke user tokens", "error", err)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventRefreshTokenReuseDetected, UserID: family.UserID, ClientID: clientID,
			Details: map[string]any{
				"severity": "critical", "family_id": family.FamilyID, "generation": family.Generation,
				"action": "family_and_tokens_revoked",
			},
		})
		s.Auditor.LogTokenReuse(ctx, family.UserID, clientID)
	}

	return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
}

// handleRefreshTokenError handles errors from refresh token validation
// Returns error suitable for returning to client
func (s *Server) handleRefreshTokenError(ctx context.Context, err error, refreshToken, clientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) error {
	isNotFoundOrExpired := storage.IsNotFoundError(err) || storage.IsExpiredError(err)

	// Check for reuse if token not found and family tracking is supported
	if isNotFoundOrExpired && supportsFamilies {
		if reuseErr := s.handleRefreshTokenReuseDetection(ctx, refreshToken, clientID, familyStore); reuseErr != nil {
			return reuseErr
		}
	}

	// Handle transient errors differently
	if !isNotFoundOrExpired {
		s.Logger.Warn("Transient error during refresh token validation",
			"error", err.Error(), "client_id", clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type: security.EventAuthFailure, ClientID: clientID,
				Details: map[string]any{"reason": "transient_storage_error"},
			})
		}
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Regular invalid token error
	s.Logger.Debug("Refresh token validation failed",
		"reason", err.Error(), "client_id", clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
	if s.Auditor != nil {
		s.Auditor.LogAuthFailure(ctx, "", clientID, "", "invalid_refresh_token")
	}
	return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
}

// rotateRefreshToken handles OAuth 2.1 refresh token rotation with family tracking.
// Returns (newRefreshToken, familyID, rotated).
func (s *Server) rotateRefreshToken(ctx context.Context, oldRefreshToken, userID, clientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) (string, string, bool) {
	if !s.Config.AllowRefreshTokenRotation {
		s.Logger.Warn("Refresh token reused (rotation disabled)", "user_id", userID)
		return oldRefreshToken, "", false
	}

	newRefreshToken := generateRandomToken()
	var familyID string
	var generation int

	if supportsFamilies {
		family, err := familyStore.GetRefreshTokenFamily(ctx, oldRefreshToken)
		if err == nil {
			familyID = family.FamilyID
			generation = family.Generation + 1
		} else {
			familyID = generateRandomToken()
			generation = 1
		}
	}

	// Invalidate old refresh token
	_ = s.tokenStore.DeleteRefreshToken(ctx, oldRefreshToken)
	_ = s.tokenStore.DeleteToken(ctx, oldRefreshToken)
	s.unregisterTokenPairByRefresh(oldRefreshToken)

	s.Logger.Debug("Refresh token rotated (OAuth 2.1)",
		"user_id", userID, "generation", generation, "family_tracking", supportsFamilies)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(attribute.Bool(instrumentation.AttrTokenRotated, true))
	}

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

	return newRefreshToken, familyID, true
}

// StartAuthorizationFlow starts a new OAuth authorization flow
// clientState is the state parameter from the client (REQUIRED for CSRF protection)
// resource is the target resource server identifier per RFC 8707 (optional for backward compatibility)
// authOpts contains optional OIDC parameters (prompt, login_hint, id_token_hint) for upstream IdP forwarding
func (s *Server) StartAuthorizationFlow(ctx context.Context, clientID, redirectURI, scope, resource, codeChallenge, codeChallengeMethod, clientState string, authOpts *providers.AuthorizationURLOptions) (string, error) {
	// CRITICAL SECURITY: Validate state parameter from client for CSRF protection
	if err := s.validateClientStateParameter(clientState); err != nil {
		s.logAuthFailure(ctx, "", clientID, "invalid_state_parameter")
		return "", fmt.Errorf("%w (OAuth 2.0 Security BCP)", err)
	}

	// Generate server-side state if client didn't provide one
	trackingState := clientState
	if trackingState == "" {
		trackingState = generateRandomToken()
		s.Logger.Debug("Generated server-side state for client without state parameter", "client_id", clientID)
	}

	// Validate PKCE parameters
	if err := s.validatePKCEForAuthFlow(ctx, clientID, codeChallenge, codeChallengeMethod); err != nil {
		return "", err
	}

	// Validate client - use getOrFetchClient to support URL-based client IDs (CIMD)
	client, err := s.getOrFetchClient(ctx, clientID)
	if err != nil {
		s.logAuthFailure(ctx, "", clientID, ErrorCodeInvalidClient)
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	// Validate redirect URI
	if err := s.validateRedirectURI(client, redirectURI); err != nil {
		s.logAuthFailure(ctx, "", clientID, ErrorCodeInvalidRedirectURI)
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	// SECURITY: Authorization-time redirect URI validation (TOCTOU protection)
	if err := s.ValidateRedirectURIAtAuthorizationTime(ctx, redirectURI); err != nil {
		s.logAuthFailure(ctx, "", clientID, "redirect_uri_security_violation")
		s.Logger.Warn("Redirect URI failed authorization-time security validation",
			"client_id", clientID, "redirect_uri", sanitizeURIForLogging(redirectURI), "error", err.Error())
		return "", fmt.Errorf("%s: redirect URI failed security validation", ErrorCodeInvalidRequest)
	}

	// Resolve scopes - use provider defaults if client didn't provide any
	scope = s.resolveScopes(ctx, scope, client)

	// Validate scope length, scopes, and client authorization
	if err := s.validateScopesForAuthFlow(ctx, clientID, scope, client.Scopes); err != nil {
		return "", err
	}

	// RFC 8707: Validate resource parameter if provided
	if resource != "" {
		if err := s.validateResourceParameter(resource); err != nil {
			s.logAuthFailure(ctx, "", clientID, fmt.Sprintf("invalid_resource: %v", err))
			return "", fmt.Errorf("%s: resource parameter is invalid: %w", ErrorCodeInvalidRequest, err)
		}
	}

	// Generate provider state (different from client state for defense in depth)
	providerState := generateRandomToken()

	// Generate PKCE for server-to-provider leg (OAuth 2.1)
	providerCodeChallenge, providerCodeVerifier := generatePKCEPair()

	effectiveNonce, authOpts := s.resolveAuthorizationNonce(clientID, scope, authOpts)

	s.logAuthorizationFlowStarted(ctx, clientID, redirectURI, scope, codeChallengeMethod, resource, authOpts)

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
		Nonce:                effectiveNonce,
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
	}
	if err := s.flowStore.SaveAuthorizationState(ctx, authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Parse scopes to pass to provider
	// If client didn't request scopes, pass empty slice and provider will use its defaults
	requestedScopes := helpers.SplitScopes(scope)

	authURL := s.provider.AuthorizationURL(providerState, providerCodeChallenge, "S256", requestedScopes, authOpts)

	return authURL, nil
}

// minClientNonceLength is the lower bound on client-supplied nonce *length*.
// 24 characters is a coarse proxy for entropy; the check does not validate
// base64 or assert any particular charset — the upstream IdP is the authority
// on the accepted nonce shape. Shorter values are replaced server-side.
const minClientNonceLength = 24

// resolveAuthorizationNonce returns the nonce to persist with the
// AuthorizationState and the authOpts forwarded to the upstream IdP. Non-OIDC
// scopes drop the nonce; OIDC scopes reuse a sufficiently long client value
// or mint a server-side replacement.
//
// Caller-visible behaviour: a client-supplied nonce shorter than
// [minClientNonceLength] is silently replaced with a server-generated value.
// RPs that rely on the upstream id_token echoing the client's original nonce
// will see the substituted value on callback, not their own. The substitution
// is logged at WARN level on the [Server.Logger]; there is no /authorize-time
// 400 rejection because the parameter is otherwise spec-conforming.
func (s *Server) resolveAuthorizationNonce(clientID, scope string, authOpts *providers.AuthorizationURLOptions) (nonce string, forwarded *providers.AuthorizationURLOptions) {
	if !helpers.HasScope(scope, "openid") {
		if authOpts != nil && authOpts.Nonce != "" {
			s.Logger.Debug("Dropping client-supplied nonce on non-OIDC flow",
				"client_id", clientID,
				"scope", scope)
			amended := *authOpts
			amended.Nonce = ""
			return "", &amended
		}
		return "", authOpts
	}

	if authOpts != nil && authOpts.Nonce != "" {
		if len(authOpts.Nonce) < minClientNonceLength {
			s.Logger.Warn("Client-supplied nonce below minimum length; replacing with server-generated value",
				"client_id", clientID,
				"client_nonce_length", len(authOpts.Nonce),
				"min_required", minClientNonceLength)
			minted := generateRandomToken()
			amended := *authOpts
			amended.Nonce = minted
			return minted, &amended
		}
		return authOpts.Nonce, authOpts
	}

	minted := generateRandomToken()
	if authOpts == nil {
		return minted, &providers.AuthorizationURLOptions{Nonce: minted}
	}
	amended := *authOpts
	amended.Nonce = minted
	return minted, &amended
}

// HandleProviderCallback handles the callback from the OAuth provider
// Returns: (authorizationCode, clientState, error)
// clientState is the original state parameter from the client for CSRF validation
func (s *Server) HandleProviderCallback(ctx context.Context, providerState, code string) (*storage.AuthorizationCode, string, error) {
	authState, err := s.validateAndRetrieveAuthState(ctx, providerState)
	if err != nil {
		return nil, "", err
	}

	// Save values before deletion
	clientState := authState.OriginalClientState
	providerVerifier := authState.ProviderCodeVerifier

	// Delete authorization state (one-time use)
	_ = s.flowStore.DeleteAuthorizationState(ctx, providerState)

	providerToken, err := s.exchangeCodeWithProvider(ctx, code, providerVerifier, authState, providerState)
	if err != nil {
		return nil, "", err
	}

	if err := s.validateUpstreamIDTokenNonce(ctx, authState, providerToken); err != nil {
		return nil, "", err
	}

	userInfo, err := s.provider.ValidateToken(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user info: %w", err)
	}

	s.saveUserInfoAndToken(ctx, userInfo, providerToken)

	authCodeObj, err := s.createAndSaveAuthorizationCode(ctx, authState, userInfo, providerToken)
	if err != nil {
		return nil, "", err
	}

	s.logAuthorizationCodeIssued(ctx, userInfo.ID, authState.ClientID, authState.Scope)
	return authCodeObj, clientState, nil
}

// validateAndRetrieveAuthState validates the provider state and retrieves the authorization state.
func (s *Server) validateAndRetrieveAuthState(ctx context.Context, providerState string) (*storage.AuthorizationState, error) {
	if err := s.validateProviderStateParameter(providerState); err != nil {
		s.logInvalidProviderCallback(ctx, "invalid_state_format")
		return nil, fmt.Errorf("invalid state parameter: %w", err)
	}

	authState, err := s.flowStore.GetAuthorizationStateByProviderState(ctx, providerState)
	if err != nil {
		s.logInvalidProviderCallback(ctx, "state_not_found")
		return nil, fmt.Errorf("invalid state parameter: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(authState.ProviderState), []byte(providerState)) != 1 {
		s.logProviderStateMismatch(ctx, authState.ClientID)
		return nil, fmt.Errorf("state parameter mismatch")
	}

	return authState, nil
}

// logInvalidProviderCallback logs an invalid provider callback event.
func (s *Server) logInvalidProviderCallback(ctx context.Context, reason string) {
	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:    security.EventInvalidProviderCallback,
			Details: map[string]any{"reason": reason},
		})
	}
}

// logProviderStateMismatch logs a provider state mismatch event.
func (s *Server) logProviderStateMismatch(ctx context.Context, clientID string) {
	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventProviderStateMismatch,
			ClientID: clientID,
			Details:  map[string]any{"severity": "critical"},
		})
	}
}

// validateUpstreamIDTokenNonce requires the upstream id_token's `nonce` claim
// to equal authState.Nonce. No-op when authState has no nonce or
// RequireNonceEcho is false. When a nonce was bound, an absent id_token in
// the provider response is rejected as a downgrade attempt — non-conformant
// IdPs are the use case for DisableNonceEchoRequirement.
//
// The id_token claims are parsed without signature verification: this echo
// check is defence-in-depth against authorization-response forgery, not the
// primary signature gate. Providers implementing [providers.JWKSProvider]
// run the OIDC Verifier on the SSO path; for OAuth-only providers (e.g.
// GitHub) the upstream token is a confidential channel and the nonce echo
// is the only replay defence available at this seam.
func (s *Server) validateUpstreamIDTokenNonce(ctx context.Context, authState *storage.AuthorizationState, providerToken *oauth2.Token) error {
	if authState == nil || authState.Nonce == "" {
		return nil
	}
	if !s.Config.RequireNonceEcho {
		return nil
	}

	idToken := ExtractIDToken(providerToken)
	if idToken == "" {
		s.logProviderNonceMismatch(ctx, authState.ClientID, "id_token_missing")
		return fmt.Errorf("upstream id_token missing: %w", oidc.ErrNonceMismatch)
	}

	claims, parseErr := oidc.ParseUnverifiedClaims(idToken)
	if parseErr != nil {
		s.logProviderNonceMismatch(ctx, authState.ClientID, "id_token_parse_failed")
		return fmt.Errorf("upstream id_token parse failed: %w", parseErr)
	}

	claimNonce, wrongType := extractNonceClaim(claims)
	if wrongType {
		s.logProviderNonceMismatch(ctx, authState.ClientID, "wrong_type")
		return fmt.Errorf("upstream id_token nonce wrong_type: %w", oidc.ErrNonceMismatch)
	}
	if err := oidc.ValidateNonceClaim(claimNonce, authState.Nonce); err != nil {
		reason := nonceMismatchReason(claimNonce)
		s.logProviderNonceMismatch(ctx, authState.ClientID, reason)
		return fmt.Errorf("upstream id_token nonce %s: %w", reason, err)
	}

	return nil
}

// extractNonceClaim returns the `nonce` claim as a string. wrongType is true
// when the claim is present but not a JSON string (e.g. a number or array) —
// distinguishable from an absent claim for audit forensics.
func extractNonceClaim(claims map[string]any) (nonce string, wrongType bool) {
	raw, ok := claims["nonce"]
	if !ok || raw == nil {
		return "", false
	}
	value, isString := raw.(string)
	if !isString {
		return "", true
	}
	return value, false
}

func nonceMismatchReason(claimNonce string) string {
	if claimNonce == "" {
		return "absent"
	}
	return "mismatch"
}

// logProviderNonceMismatch emits the audit event for an upstream id_token
// nonce echo failure. severity=high — replay-attack indicator.
func (s *Server) logProviderNonceMismatch(ctx context.Context, clientID, reason string) {
	if s.Auditor == nil {
		return
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventProviderNonceMismatch,
		ClientID: clientID,
		Details: map[string]any{
			"severity": "high",
			"reason":   reason,
		},
	})
}

// exchangeCodeWithProvider exchanges the authorization code with the provider.
func (s *Server) exchangeCodeWithProvider(ctx context.Context, code, providerVerifier string, authState *storage.AuthorizationState, providerState string) (*oauth2.Token, error) {
	providerToken, err := s.provider.ExchangeCode(ctx, code, providerVerifier)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type: security.EventProviderCodeExchangeFailed,
				Details: map[string]any{
					"provider":     s.provider.Name(),
					"error":        err.Error(),
					"pkce_enabled": providerVerifier != "",
					"client_id":    authState.ClientID,
					"state_id":     helpers.SafeTruncate(providerState, 16),
				},
			})
		}
		return nil, fmt.Errorf("failed to exchange code with provider: %w", err)
	}
	return providerToken, nil
}

// saveUserInfoAndToken saves user info and token by ID and by email.
// Tokens are always saved by both ID and email (when email is available) to ensure
// downstream consumers can reliably retrieve tokens by email, regardless of whether
// the OIDC provider's subject claim differs from the email (e.g., Dex uses base64-encoded subjects).
//
// IMPORTANT: Provider tokens are saved with an extended expiry (ProviderTokenTTL) to ensure
// they remain available for SSO token forwarding, even if the original access token has
// a short lifetime. The original token data (including refresh_token) is preserved.
func (s *Server) saveUserInfoAndToken(ctx context.Context, userInfo *providers.UserInfo, providerToken *oauth2.Token) {
	// Create a copy of the token with extended expiry for storage purposes
	// This ensures the token remains available for SSO token forwarding even if
	// the provider's access token has a short lifetime (e.g., 5 minutes from Dex)
	tokenForStorage := s.extendTokenExpiryForStorage(providerToken)

	// Save by ID (required - ID should always be present from provider's subject claim)
	if userInfo.ID != "" {
		if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, userInfo); err != nil {
			s.Logger.Warn("Failed to save user info", "error", err)
		}
		if err := s.tokenStore.SaveToken(ctx, userInfo.ID, tokenForStorage); err != nil {
			s.Logger.Warn("Failed to save provider token", "error", err)
		}
	} else {
		s.Logger.Warn("UserInfo has empty ID, skipping ID-based storage")
	}

	// Always save by email if available (regardless of whether it equals ID)
	// This ensures downstream consumers can reliably lookup tokens by email
	if userInfo.Email != "" {
		if err := s.tokenStore.SaveUserInfo(ctx, userInfo.Email, userInfo); err != nil {
			s.Logger.Warn("Failed to save user info by email", "error", err)
		}
		if err := s.tokenStore.SaveToken(ctx, userInfo.Email, tokenForStorage); err != nil {
			s.Logger.Warn("Failed to save provider token by email", "error", err)
		}
	}
}

// extendTokenExpiryForStorage creates a copy of the token with an extended expiry
// based on ProviderTokenTTL configuration. This ensures provider tokens remain
// available for SSO token forwarding regardless of the original access token's lifetime.
//
// The function preserves all original token data (access_token, refresh_token, id_token in Extra)
// but extends the Expiry field to ensure the storage backend (Valkey) keeps the token
// for the configured ProviderTokenTTL duration.
//
// Rationale:
//   - Provider access tokens may have short lifetimes (5-15 minutes)
//   - SSO token forwarding needs the id_token for longer (user session duration)
//   - If refresh_token is present, the token can be refreshed when access_token expires
//   - Storage TTL should be independent of access_token expiry
func (s *Server) extendTokenExpiryForStorage(token *oauth2.Token) *oauth2.Token {
	if token == nil {
		return nil
	}

	// Calculate the extended expiry based on ProviderTokenTTL
	extendedExpiry := time.Now().Add(time.Duration(s.Config.ProviderTokenTTL) * time.Second)

	// If the token already has a longer expiry, keep it
	if !token.Expiry.IsZero() && token.Expiry.After(extendedExpiry) {
		return token
	}

	// Create a new token with extended expiry, preserving all other fields
	// Note: We can't modify the original token as it may be used elsewhere
	extendedToken := &oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       extendedExpiry,
	}

	// Preserve Extra fields (id_token, scope, expires_in, etc.) using the shared helper
	// This ensures all KnownExtraFields are preserved, not just id_token
	if extra := storage.ExtractTokenExtra(token); extra != nil {
		extendedToken = extendedToken.WithExtra(extra)
	}

	s.Logger.Debug("Extended provider token expiry for storage",
		"original_expiry", token.Expiry,
		"extended_expiry", extendedExpiry,
		"has_refresh_token", token.RefreshToken != "",
		"provider_token_ttl_seconds", s.Config.ProviderTokenTTL)

	return extendedToken
}

// createAndSaveAuthorizationCode creates and saves an authorization code.
func (s *Server) createAndSaveAuthorizationCode(ctx context.Context, authState *storage.AuthorizationState, userInfo *providers.UserInfo, providerToken *oauth2.Token) (*storage.AuthorizationCode, error) {
	authCodeObj := &storage.AuthorizationCode{
		Code:                generateRandomToken(),
		ClientID:            authState.ClientID,
		RedirectURI:         authState.RedirectURI,
		Scope:               authState.Scope,
		Resource:            authState.Resource,
		Audience:            authState.Resource,
		CodeChallenge:       authState.CodeChallenge,
		CodeChallengeMethod: authState.CodeChallengeMethod,
		UserID:              userInfo.ID,
		ProviderToken:       providerToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
		Used:                false,
	}

	if err := s.flowStore.SaveAuthorizationCode(ctx, authCodeObj); err != nil {
		return nil, fmt.Errorf("failed to save authorization code: %w", err)
	}
	return authCodeObj, nil
}

// logAuthorizationCodeIssued logs an authorization code issued event.
func (s *Server) logAuthorizationCodeIssued(ctx context.Context, userID, clientID, scope string) {
	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventAuthorizationCodeIssued,
			UserID:   userID,
			ClientID: clientID,
			Details: map[string]any{
				"scope":                 scope,
				"client_state_returned": true,
			},
		})
	}
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
// Returns oauth2.Token directly
// resource parameter is optional per RFC 8707 for backward compatibility
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, resource, codeVerifier string) (*oauth2.Token, string, error) {
	ctx, span := s.startExchangeSpan(ctx, clientID)
	if span != nil {
		defer span.End()
	}

	authCode, err := s.validateAuthorizationCode(ctx, code, clientID, redirectURI, resource, codeVerifier, span)
	if err != nil {
		return nil, "", err
	}

	// Pre-generate familyID so metadata can reference it before the family is persisted
	var familyID string
	if _, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); ok {
		familyID = generateRandomToken()
	}

	tokenResponse, err := s.generateAndStoreTokens(ctx, authCode, clientID, familyID)
	if err != nil {
		return nil, "", err
	}

	s.trackRefreshTokenFamily(ctx, tokenResponse.RefreshToken, authCode.UserID, clientID, familyID)

	if s.sessionCreationHandler != nil && familyID != "" {
		s.sessionCreationHandler(ctx, authCode.UserID, familyID, tokenResponse)
	}

	if s.Auditor != nil {
		s.Auditor.LogTokenIssued(ctx, authCode.UserID, clientID, "", authCode.Scope)
	}

	s.recordExchangeSuccess(span, authCode)
	return tokenResponse, authCode.Scope, nil
}

// startExchangeSpan creates a tracing span for the exchange operation.
func (s *Server) startExchangeSpan(ctx context.Context, clientID string) (context.Context, trace.Span) {
	if s.tracer == nil {
		return ctx, nil
	}
	ctx, span := s.tracer.Start(ctx, "oauth.server.exchange_authorization_code")
	span.SetAttributes(attribute.String(instrumentation.AttrClientID, clientID))
	return ctx, span
}

// validateAuthorizationCode performs all authorization code validations.
func (s *Server) validateAuthorizationCode(ctx context.Context, code, clientID, redirectURI, resource, codeVerifier string, span trace.Span) (*storage.AuthorizationCode, error) {
	authCode, err := s.flowStore.AtomicCheckAndMarkAuthCodeUsed(ctx, code)
	if err != nil {
		if storage.IsCodeReuseError(err) {
			return nil, s.handleCodeReuseDetection(ctx, authCode, clientID, code, span)
		}
		return nil, s.logAuthCodeValidationFailure(ctx, "invalid_authorization_code: "+err.Error(), clientID, "", helpers.SafeTruncate(code, 8))
	}

	if err := s.validateCodeParameters(ctx, authCode, clientID, redirectURI, code); err != nil {
		return nil, err
	}

	if err := s.validateResourceConsistency(ctx, resource, authCode, clientID, code); err != nil {
		return nil, err
	}

	client, err := s.getOrFetchClient(ctx, clientID)
	if err != nil {
		return nil, s.logAuthCodeValidationFailure(ctx, "client_not_found", clientID, "", helpers.SafeTruncate(code, 8))
	}

	if err := s.validateScopesAndPKCE(ctx, authCode, client, clientID, code, codeVerifier, span); err != nil {
		return nil, err
	}

	return authCode, nil
}

// validateCodeParameters validates basic authorization code parameters.
func (s *Server) validateCodeParameters(ctx context.Context, authCode *storage.AuthorizationCode, clientID, redirectURI, code string) error {
	if authCode.ClientID != clientID {
		return s.logAuthCodeValidationFailure(ctx, "client_id_mismatch", clientID, "", helpers.SafeTruncate(code, 8))
	}
	if authCode.RedirectURI != redirectURI {
		return s.logAuthCodeValidationFailure(ctx, "redirect_uri_mismatch", clientID, "", helpers.SafeTruncate(code, 8))
	}
	return nil
}

// validateScopesAndPKCE validates scopes against client and PKCE.
func (s *Server) validateScopesAndPKCE(ctx context.Context, authCode *storage.AuthorizationCode, client *storage.Client, clientID, code, codeVerifier string, span trace.Span) error {
	if err := s.validateClientScopes(authCode.Scope, client.Scopes); err != nil {
		s.logScopeValidationFailure(ctx, authCode, clientID, code, err)
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	if err := s.validatePublicClientPKCE(ctx, client, authCode, code); err != nil {
		return err
	}

	return s.validatePKCEWithAudit(ctx, authCode, clientID, codeVerifier, span)
}

// logScopeValidationFailure logs a scope validation failure event.
func (s *Server) logScopeValidationFailure(ctx context.Context, authCode *storage.AuthorizationCode, clientID, code string, err error) {
	s.Logger.Debug("Client scope validation failed during token exchange",
		"reason", err.Error(), "client_id", clientID, "user_id", authCode.UserID,
		"requested_scope", authCode.Scope, "code_prefix", helpers.SafeTruncate(code, 8))

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventScopeEscalationAttempt, UserID: authCode.UserID, ClientID: clientID,
			Details: map[string]any{"severity": "high", "requested_scope": authCode.Scope},
		})
		s.Auditor.LogAuthFailure(ctx, authCode.UserID, clientID, "", fmt.Sprintf("scope_validation_failed: %v", err))
	}
}

// generateAndStoreTokens generates and stores access and refresh tokens.
func (s *Server) generateAndStoreTokens(ctx context.Context, authCode *storage.AuthorizationCode, clientID, familyID string) (*oauth2.Token, error) {
	var providerExpiry time.Time
	if authCode.ProviderToken != nil {
		providerExpiry = authCode.ProviderToken.Expiry
	}
	expiry := s.capTokenExpiry(providerExpiry)

	tokenScopes := helpers.SplitScopes(authCode.Scope)
	accessToken, err := s.issueAccessToken(ctx, accessTokenIssueParams{
		UserID:    authCode.UserID,
		ClientID:  clientID,
		Audience:  authCode.Audience,
		Scopes:    tokenScopes,
		ExpiresAt: expiry,
		FamilyID:  familyID,
	})
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}
	refreshToken := generateRandomToken()

	tokenResponse := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
		TokenType:    "Bearer",
	}

	// OIDC Compliance: Forward id_token from upstream provider to client
	// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token is REQUIRED in token responses
	// for OIDC flows. This enables silent re-authentication with id_token_hint and login_hint.
	if idToken := ExtractIDToken(authCode.ProviderToken); idToken != "" {
		tokenResponse = tokenResponse.WithExtra(map[string]interface{}{
			"id_token": idToken,
		})
	}

	// Store token mappings
	if err := s.tokenStore.SaveToken(ctx, accessToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save access token mapping", "error", err)
	}
	if err := s.tokenStore.SaveToken(ctx, refreshToken, authCode.ProviderToken); err != nil {
		s.Logger.Warn("Failed to save refresh token", "error", err)
	}

	// Track AT -> RT pairing for refresh-time updates
	s.registerTokenPair(accessToken, refreshToken)

	s.saveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    authCode.UserID,
		ClientID:  clientID,
		TokenType: "access",
		Audience:  authCode.Audience,
		FamilyID:  familyID,
		Scopes:    tokenScopes,
	})
	s.saveTokenMetadata(ctx, refreshToken, storage.TokenMetadata{
		UserID:    authCode.UserID,
		ClientID:  clientID,
		TokenType: "refresh",
		Audience:  authCode.Audience,
		FamilyID:  familyID,
		Scopes:    tokenScopes,
	})

	return tokenResponse, nil
}

// accessTokenIssueParams bundles the inputs to Server.issueAccessToken so
// the call sites read clearly and so adding a new claim later is a one-place
// change. All fields except UserID, ClientID, and ExpiresAt are optional —
// the issuer drops empty values rather than emitting empty claims.
type accessTokenIssueParams struct {
	UserID    string
	ClientID  string
	Audience  string
	Scopes    []string
	ExpiresAt time.Time
	FamilyID  string
}

// issueAccessToken builds AccessTokenClaims from the issuance context and
// delegates to the configured AccessTokenIssuer. Email/groups are looked up
// from the TokenStore in JWT mode only — opaque issuance ignores them so
// the lookup is skipped to avoid an unnecessary storage round-trip.
func (s *Server) issueAccessToken(ctx context.Context, p accessTokenIssueParams) (string, error) {
	claims := AccessTokenClaims{
		Subject:   p.UserID,
		ClientID:  p.ClientID,
		Audience:  p.Audience,
		Scopes:    p.Scopes,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: p.ExpiresAt,
		FamilyID:  p.FamilyID,
	}
	if s.Config.IsJWTAccessTokenFormat() {
		s.fillUserInfoClaims(ctx, p.UserID, &claims)
	}
	return s.accessTokenIssuer.Issue(ctx, claims)
}

// fillUserInfoClaims is a best-effort lookup of UserInfo from the token
// store to populate email and groups for JWT claims. A missing or errored
// UserInfo only causes the optional claims to be omitted; access-token
// issuance still succeeds.
func (s *Server) fillUserInfoClaims(ctx context.Context, userID string, c *AccessTokenClaims) {
	info, err := s.tokenStore.GetUserInfo(ctx, userID)
	if err != nil {
		s.Logger.Debug("UserInfo lookup failed during JWT access token issuance — email/groups claims omitted",
			"error", err,
			"user_id", userID)
		return
	}
	if info == nil {
		return
	}
	c.Email = info.Email
	c.EmailVerified = info.EmailVerified
	c.Name = info.Name
	c.Groups = info.Groups
}

// trackRefreshTokenFamily tracks the refresh token with family support if available.
// If familyID is provided it is used; otherwise a new one is generated.
func (s *Server) trackRefreshTokenFamily(ctx context.Context, refreshToken, userID, clientID, familyID string) {
	refreshTokenExpiry := time.Now().Add(time.Duration(s.Config.RefreshTokenTTL) * time.Second)

	if familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); ok {
		if familyID == "" {
			familyID = generateRandomToken()
		}
		if err := familyStore.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, familyID, 0, refreshTokenExpiry); err != nil {
			s.Logger.Warn("Failed to track refresh token with family", "error", err)
		} else {
			s.Logger.Debug("Created new refresh token family", "user_id", userID, "family_id", helpers.SafeTruncate(familyID, 8))
		}
		return
	}

	if err := s.tokenStore.SaveRefreshToken(ctx, refreshToken, userID, refreshTokenExpiry); err != nil {
		s.Logger.Warn("Failed to track refresh token", "error", err)
	}
}

// recordExchangeSuccess records success in the tracing span.
func (s *Server) recordExchangeSuccess(span trace.Span, authCode *storage.AuthorizationCode) {
	if span != nil {
		span.SetAttributes(
			attribute.String("oauth.user_id", authCode.UserID),
			attribute.String("oauth.scope", authCode.Scope),
		)
		span.SetStatus(codes.Ok, "code exchanged successfully")
	}
}

// RefreshAccessToken refreshes an access token using a refresh token with OAuth 2.1 rotation
// Returns oauth2.Token directly
// Implements OAuth 2.1 refresh token reuse detection for enhanced security
// Implements OAuth 2.1 Section 6 client binding validation
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken, clientID string) (*oauth2.Token, error) {
	// Check if storage supports token family tracking (OAuth 2.1 reuse detection)
	familyStore, supportsFamilies := s.tokenStore.(storage.RefreshTokenFamilyStore)

	// Capture scopes and audience from old token metadata before the atomic
	// delete removes it. Best-effort: if there's a race, the atomic operation
	// below will fail and these values won't be used.
	var oldScopes []string
	var oldAudience string
	if metaGetter, ok := s.tokenStore.(storage.TokenMetadataGetter); ok {
		if oldMeta, err := metaGetter.GetTokenMetadata(refreshToken); err == nil && oldMeta != nil {
			oldScopes = oldMeta.Scopes
			oldAudience = oldMeta.Audience
		}
	}

	// OAUTH 2.1 SECURITY: Atomically get and delete refresh token FIRST
	// Returns clientID for client binding validation
	userID, storedClientID, providerToken, err := s.tokenStore.AtomicGetAndDeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, s.handleRefreshTokenError(ctx, err, refreshToken, clientID, familyStore, supportsFamilies)
	}

	// OAUTH 2.1 SECURITY: Validate client binding (Section 6)
	// The refresh token MUST only be accepted by the client it was issued to
	if err := s.validateRefreshTokenClientBinding(ctx, storedClientID, clientID, userID); err != nil {
		return nil, err
	}

	// Refresh token with provider
	newProviderToken, err := s.provider.RefreshToken(ctx, providerToken.RefreshToken)
	if err != nil {
		s.logAuthFailure(ctx, userID, clientID, fmt.Sprintf("provider_refresh_failed: %v", err))
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// OAuth 2.1: Refresh Token Rotation
	newRefreshToken, familyID, rotated := s.rotateRefreshToken(ctx, refreshToken, userID, clientID, familyStore, supportsFamilies)

	var providerExpiry time.Time
	if newProviderToken != nil {
		providerExpiry = newProviderToken.Expiry
	}
	expiry := s.capTokenExpiry(providerExpiry)

	newAccessToken, err := s.issueAccessToken(ctx, accessTokenIssueParams{
		UserID:    userID,
		ClientID:  clientID,
		Audience:  oldAudience,
		Scopes:    oldScopes,
		ExpiresAt: expiry,
		FamilyID:  familyID,
	})
	if err != nil {
		return nil, fmt.Errorf("issue access token on refresh: %w", err)
	}

	// Create token response using oauth2.Token
	tokenResponse := &oauth2.Token{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		Expiry:       expiry,
		TokenType:    "Bearer",
	}

	// Per OpenID Connect Core 1.0 §12.2, the refreshed id_token (when present) is
	// not required to carry the original Authentication Request's `nonce` claim:
	// nonce is bound to the auth request, not the refresh. No echo validation
	// here — the upstream Verifier (when configured) is the authority on
	// signature, iss, aud, and exp. Parity with [flows_forwarded.go].
	if idToken := ExtractIDToken(newProviderToken); idToken != "" {
		tokenResponse = tokenResponse.WithExtra(map[string]interface{}{
			"id_token": idToken,
		})
	}

	// Store new access token -> provider token mapping
	if err := s.tokenStore.SaveToken(ctx, newAccessToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new access token", "error", err)
	}

	// Store new refresh token -> provider token mapping
	if err := s.tokenStore.SaveToken(ctx, newRefreshToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new refresh token", "error", err)
	}

	// Track AT -> RT pairing for refresh-time updates
	s.registerTokenPair(newAccessToken, newRefreshToken)

	s.saveTokenMetadata(ctx, newAccessToken, storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		TokenType: "access",
		Audience:  oldAudience,
		FamilyID:  familyID,
		Scopes:    oldScopes,
	})
	s.saveTokenMetadata(ctx, newRefreshToken, storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		TokenType: "refresh",
		Audience:  oldAudience,
		FamilyID:  familyID,
		Scopes:    oldScopes,
	})

	if s.Auditor != nil {
		s.Auditor.LogTokenRefreshed(ctx, userID, clientID, "", rotated)
	}

	return tokenResponse, nil
}

// handleLegacyRefreshToken rejects refresh tokens that lack client binding.
// OAuth 2.1 Section 6 requires client binding - tokens without it are invalid.
func (s *Server) handleLegacyRefreshToken(ctx context.Context, requestingClientID, userID string) error {
	// Record metric for observability (tracking rejected legacy tokens)
	if s.Instrumentation != nil {
		s.Instrumentation.Metrics().RecordLegacyRefreshTokenRejected(ctx)
	}

	s.Logger.Warn("Refresh token rejected - missing client binding",
		"user_id", userID,
		"requesting_client_id", requestingClientID,
		"reason", "OAuth 2.1 Section 6 requires client binding")

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventRefreshTokenMissingClientBinding,
			UserID:   userID,
			ClientID: requestingClientID,
			Details: map[string]any{
				"severity":      "high",
				"action":        "rejected",
				"security_risk": "cross_client_token_theft_prevented",
				"oauth_spec":    "OAuth 2.1 Section 6",
			},
		})
		s.Auditor.LogAuthFailure(ctx, userID, requestingClientID, "", "refresh_token_missing_client_binding")
	}

	// Return generic error per OAuth spec (don't reveal details to attacker)
	return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
}

// validateRefreshTokenClientBinding validates that the requesting client matches
// the client that was originally issued the refresh token.
// This implements OAuth 2.1 Section 6 client binding requirement.
//
// Security: This prevents cross-client token theft where an attacker with a stolen
// refresh token attempts to use it from a different client.
//
// Returns nil if validation passes, or an error with "invalid_grant" if:
//   - The stored clientID doesn't match the requesting clientID
//   - The stored clientID is empty (token without client binding - always rejected)
func (s *Server) validateRefreshTokenClientBinding(ctx context.Context, storedClientID, requestingClientID, userID string) error {
	// If no stored clientID, this is a legacy token without binding
	if storedClientID == "" {
		return s.handleLegacyRefreshToken(ctx, requestingClientID, userID)
	}

	// SECURITY: Validate client binding using constant-time comparison
	// This prevents timing attacks that could reveal valid client IDs
	if subtle.ConstantTimeCompare([]byte(storedClientID), []byte(requestingClientID)) != 1 {
		// Rate limit logging to prevent DoS via log flooding
		if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(userID+":"+requestingClientID+":client_binding_mismatch") {
			s.Logger.Error("Refresh token client binding validation failed - possible token theft attempt",
				"user_id", userID,
				"stored_client_id", storedClientID,
				"requesting_client_id", requestingClientID,
				"security_event", "cross_client_token_theft_attempt",
				"oauth_spec", "OAuth 2.1 Section 6")
		}

		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type:     security.EventRefreshTokenClientBindingMismatch,
				UserID:   userID,
				ClientID: requestingClientID,
				Details: map[string]any{
					"severity":             "critical",
					"stored_client_id":     storedClientID,
					"requesting_client_id": requestingClientID,
					"attack_indicator":     "cross_client_token_theft_attempt",
					"oauth_spec":           "OAuth 2.1 Section 6",
				},
			})
			s.Auditor.LogAuthFailure(ctx, userID, requestingClientID, "", "refresh_token_client_binding_mismatch")
		}

		// Return generic error per OAuth spec (don't reveal details to attacker)
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	s.Logger.Debug("Refresh token client binding validated",
		"user_id", userID,
		"client_id", storedClientID)

	return nil
}

// RevokeToken revokes a token (access or refresh).
//
// Three input shapes are accepted:
//   - Self-issued JWT access token: jti is added to RevokedTokenStore so
//     the next ValidateToken call rejects it. The denylist entry
//     auto-expires at the JWT's own exp.
//   - Opaque access token: TokenStore deletion.
//   - Refresh token: TokenStore deletion + family revocation.
//
// Per RFC 7009 §2.2 revocation always returns success when the token is
// not found or already invalid — clients have no way to distinguish "this
// token was never issued" from "this token has been forgotten" from
// "revocation succeeded", and surfacing those distinctions enables token
// scanning attacks.
func (s *Server) RevokeToken(ctx context.Context, token, clientID, clientIP string) error {
	if s.revokeSelfIssuedJWT(ctx, token, clientID, clientIP) {
		return nil
	}

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

	// Look up family metadata BEFORE deleting the token, since DeleteToken may
	// remove data that GetRefreshTokenFamily depends on in some store implementations.
	family := s.lookupRefreshTokenFamily(ctx, token)

	// Delete locally
	if err := s.tokenStore.DeleteToken(ctx, token); err != nil {
		s.Logger.Warn("Failed to delete token locally", "error", err)
	}
	s.unregisterTokenPairIfPresent(token)

	s.revokeTokenFamilyIfNeeded(ctx, family, clientID, clientIP)

	if s.Auditor != nil {
		s.Auditor.LogTokenRevoked(ctx, "", clientID, clientIP, "access_or_refresh")
	}

	s.Logger.Debug("Token revoked", "client_id", clientID, "ip", clientIP)
	return nil
}

func (s *Server) lookupRefreshTokenFamily(ctx context.Context, token string) *storage.RefreshTokenFamilyMetadata {
	familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore)
	if !ok {
		return nil
	}
	f, err := familyStore.GetRefreshTokenFamily(ctx, token)
	if err != nil || f == nil {
		return nil
	}
	return f
}

func (s *Server) revokeTokenFamilyIfNeeded(ctx context.Context, family *storage.RefreshTokenFamilyMetadata, clientID, clientIP string) {
	if family == nil || family.Revoked {
		return
	}
	familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyStore)
	if !ok {
		return
	}
	if err := familyStore.RevokeRefreshTokenFamily(ctx, family.FamilyID); err != nil {
		s.Logger.Warn("Failed to revoke refresh token family", "family_id", family.FamilyID, "error", err)
		return
	}
	s.Logger.Debug("Revoked refresh token family on explicit revocation",
		"family_id", family.FamilyID, "client_id", clientID, "ip", clientIP)

	if s.sessionRevocationHandler != nil {
		s.sessionRevocationHandler(ctx, family.UserID, family.FamilyID)
	}

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventRefreshTokenFamilyRevoked,
			UserID:   family.UserID,
			ClientID: clientID,
			Details: map[string]any{
				"family_id": family.FamilyID,
				"reason":    "explicit_revocation",
				"ip":        clientIP,
			},
		})
	}
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
// handleRevocationNotSupported handles the case when storage doesn't support revocation
func (s *Server) handleRevocationNotSupported(ctx context.Context, userID, clientID string) error {
	s.Logger.Error("CRITICAL: Token storage does not support TokenRevocationStore - OAuth 2.1 NOT compliant",
		"user_id", userID, "client_id", clientID)

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventTokenRevocationNotSupported, UserID: userID, ClientID: clientID,
			Details: map[string]any{"severity": "critical", "message": "Storage backend does not support bulk token revocation - OAuth 2.1 compliance FAILED"},
		})
	}

	return fmt.Errorf("storage backend must implement TokenRevocationStore for OAuth 2.1 compliance")
}

// revokeTokensAtProvider revokes all tokens at the provider
// Returns (revokedCount, failedCount, totalCount)
func (s *Server) revokeTokensAtProvider(ctx context.Context, tokens []string, userID, clientID string) (int, int, int) {
	revokedAtProvider := 0
	failedAtProvider := 0
	totalTokensToRevoke := 0

	for _, tokenID := range tokens {
		providerToken, err := s.tokenStore.GetToken(ctx, tokenID)
		if err != nil {
			s.Logger.Warn("Could not get provider token for revocation",
				"token_id", helpers.SafeTruncate(tokenID, 8), "error", err)
			continue
		}

		if providerToken.AccessToken != "" {
			totalTokensToRevoke++
			if err := s.revokeTokenWithRetry(ctx, providerToken.AccessToken, "access", userID, clientID); err != nil {
				failedAtProvider++
			} else {
				revokedAtProvider++
			}
		}

		if providerToken.RefreshToken != "" {
			totalTokensToRevoke++
			if err := s.revokeTokenWithRetry(ctx, providerToken.RefreshToken, "refresh", userID, clientID); err != nil {
				failedAtProvider++
			} else {
				revokedAtProvider++
			}
		}
	}

	return revokedAtProvider, failedAtProvider, totalTokensToRevoke
}

// checkProviderRevocationFailure checks if provider revocation failure rate exceeds threshold
func (s *Server) checkProviderRevocationFailure(ctx context.Context, userID, clientID string, totalTokens, revokedCount, failedCount int, failureRate float64) error {
	if totalTokens > 0 && failureRate > s.Config.ProviderRevocationFailureThreshold {
		s.Logger.Error("CRITICAL: Provider revocation failure rate exceeds threshold",
			"user_id", userID, "client_id", clientID,
			"failure_rate", fmt.Sprintf("%.2f%%", failureRate*100),
			"threshold", fmt.Sprintf("%.2f%%", s.Config.ProviderRevocationFailureThreshold*100),
			"failed_count", failedCount, "total_count", totalTokens)

		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type: security.EventProviderRevocationThresholdExceeded, UserID: userID, ClientID: clientID,
				Details: map[string]any{
					"severity": "critical", "failure_rate": failureRate, "threshold": s.Config.ProviderRevocationFailureThreshold,
					"failed_count": failedCount, "total_count": totalTokens, "oauth_spec": "OAuth 2.1 Section 4.1.2",
				},
			})
		}

		return fmt.Errorf("provider revocation failure rate %.2f%% exceeds threshold %.2f%% (%d/%d failed)",
			failureRate*100, s.Config.ProviderRevocationFailureThreshold*100, failedCount, totalTokens)
	}

	if revokedCount == 0 && totalTokens > 0 {
		s.Logger.Error("CRITICAL: All provider revocations failed - tokens still valid at provider!",
			"user_id", userID, "client_id", clientID, "token_count", totalTokens)

		if s.Auditor != nil {
			s.Auditor.LogEvent(ctx, security.Event{
				Type: security.EventProviderRevocationCompleteFailure, UserID: userID, ClientID: clientID,
				Details: map[string]any{"severity": "critical", "token_count": totalTokens, "oauth_spec": "OAuth 2.1 Section 4.1.2"},
			})
		}

		return fmt.Errorf("all provider revocations failed (0/%d succeeded)", totalTokens)
	}

	return nil
}

// RevokeAllTokensForUserClient revokes all tokens for a user-client pair per OAuth 2.1.
// Returns error if provider revocation failure rate exceeds threshold or if local revocation fails.
// Logs detailed information about partial failures for operator investigation.
func (s *Server) RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) error {
	revocationStore, supportsRevocation := s.tokenStore.(storage.TokenRevocationStore)

	if !supportsRevocation {
		return s.handleRevocationNotSupported(ctx, userID, clientID)
	}

	tokens, err := revocationStore.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to get tokens for revocation: %w", err)
	}

	revokedAtProvider, failedAtProvider, totalTokensToRevoke := s.revokeTokensAtProvider(ctx, tokens, userID, clientID)

	failureRate := 0.0
	if totalTokensToRevoke > 0 {
		failureRate = float64(failedAtProvider) / float64(totalTokensToRevoke)
	}

	s.Logger.Debug("Provider revocation complete",
		"user_id", userID, "client_id", clientID, "revoked_at_provider", revokedAtProvider,
		"failed_at_provider", failedAtProvider, "total_tokens", totalTokensToRevoke,
		"failure_rate", fmt.Sprintf("%.2f%%", failureRate*100))

	if err := s.checkProviderRevocationFailure(ctx, userID, clientID, totalTokensToRevoke, revokedAtProvider, failedAtProvider, failureRate); err != nil {
		return err
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

	for _, tokenID := range tokens {
		s.unregisterTokenPairIfPresent(tokenID)
	}

	// Log the revocation
	s.Logger.Warn("Revoked all tokens for user+client due to security event",
		"user_id", userID,
		"client_id", clientID,
		"tokens_revoked_locally", revokedCount,
		"tokens_revoked_at_provider", revokedAtProvider,
		"reason", "reuse_detection")

	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
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
				s.Logger.Debug("Provider token revocation succeeded after retry",
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
func (s *Server) resolveScopes(ctx context.Context, requestedScope string, client *storage.Client) string {
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
			s.Auditor.LogEvent(ctx, security.Event{
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
			s.Auditor.LogEvent(ctx, security.Event{
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

// logAuthorizationFlowStarted logs the authorization flow start event with all relevant details.
// This helper reduces cyclomatic complexity in StartAuthorizationFlow.
func (s *Server) logAuthorizationFlowStarted(ctx context.Context, clientID, redirectURI, scope, codeChallengeMethod, resource string, authOpts *providers.AuthorizationURLOptions) {
	if s.Auditor == nil {
		return
	}

	details := map[string]any{
		"redirect_uri":          redirectURI,
		"scope":                 scope,
		"code_challenge_method": codeChallengeMethod,
	}

	// RFC 8707: Include resource parameter in audit log if provided
	if resource != "" {
		details["resource"] = resource
	}

	// OIDC: Include forwarded parameters in audit log for security visibility
	if authOpts != nil {
		if authOpts.Prompt != "" {
			details["prompt"] = authOpts.Prompt
		}
		if authOpts.LoginHint != "" {
			// Mask email for privacy in audit logs
			details["login_hint_provided"] = true
		}
		if authOpts.IDTokenHint != "" {
			// Don't log the actual token, just that it was provided
			details["id_token_hint_provided"] = true
		}
		if authOpts.Nonce != "" {
			// presence only — value is sensitive
			details["nonce_bound"] = true
		}
	}

	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventAuthorizationFlowStarted,
		ClientID: clientID,
		Details:  details,
	})
}
