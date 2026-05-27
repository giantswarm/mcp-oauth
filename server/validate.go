package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// isTokenExpiredLocally checks if a token is expired considering clock skew grace period.
// Returns true if the token is expired beyond the grace period.
func (s *Server) isTokenExpiredLocally(token *oauth2.Token) bool {
	return security.IsTokenExpiredWithGracePeriod(token.Expiry, time.Duration(s.config.ClockSkewGracePeriod)*time.Second)
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
		s.logger.Warn("Failed to save refreshed provider token for access key", "error", saveErr)
	}
	if pairedRT, ok := s.tokenPairs.Load(accessToken); ok {
		if saveErr := s.tokenStore.SaveToken(ctx, pairedRT.(string), newProviderToken); saveErr != nil {
			s.logger.Warn("Failed to save refreshed provider token for refresh key", "error", saveErr)
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
			s.logger.Debug("Failed to retrieve token metadata for refresh handler",
				"error", err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		}
	}

	s.tokenRefreshHandler(ctx, userID, familyID, newProviderToken)
}

// shouldProactivelyRefresh determines if a token should be proactively refreshed based on
// expiry threshold and refresh token availability.
func (s *Server) shouldProactivelyRefresh(token *oauth2.Token) bool {
	if token.RefreshToken == "" {
		return false
	}

	refreshThreshold := time.Duration(s.config.TokenRefreshThreshold) * time.Second
	timeUntilExpiry := time.Until(token.Expiry)

	return timeUntilExpiry > 0 && timeUntilExpiry <= refreshThreshold
}

// attemptProactiveRefresh attempts to refresh a token that is near expiry.
// This is a graceful operation - failures are logged but don't affect the validation flow.
func (s *Server) attemptProactiveRefresh(ctx context.Context, accessToken string, storedToken *oauth2.Token) {
	refreshThreshold := time.Duration(s.config.TokenRefreshThreshold) * time.Second
	timeUntilExpiry := time.Until(storedToken.Expiry)

	s.logger.Debug("Token near expiry, attempting proactive refresh",
		"expiry", storedToken.Expiry,
		"time_until_expiry", timeUntilExpiry,
		"refresh_threshold", refreshThreshold,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	// Attempt to refresh the provider token
	newProviderToken, err := s.provider.RefreshToken(ctx, storedToken.RefreshToken)
	if err != nil {
		// Refresh failed - log warning but continue with validation (graceful degradation)
		s.logger.Warn("Proactive token refresh failed, falling back to validation",
			"error", err,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"time_until_expiry", timeUntilExpiry)

		s.auditor.LogEvent(ctx, security.Event{
			Type: security.EventProactiveRefreshFailed,
			Details: map[string]any{
				"error":             err.Error(),
				"time_until_expiry": timeUntilExpiry.String(),
				"fallback":          "validation",
			},
		})
		return
	}

	// Preserve old refresh token if provider omitted it
	newProviderToken = preserveRefreshToken(newProviderToken, storedToken.RefreshToken)

	// Update both AT and RT storage mappings to keep provider credentials in sync
	s.updateProviderTokenMappings(ctx, accessToken, newProviderToken)

	s.fireTokenRefreshHandler(ctx, accessToken, newProviderToken)

	s.logger.Debug("Token proactively refreshed",
		"old_expiry", storedToken.Expiry,
		"new_expiry", newProviderToken.Expiry,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	s.auditor.LogEvent(ctx, security.Event{
		Type: security.EventTokenProactivelyRefreshed,
		Details: map[string]any{
			"old_expiry": storedToken.Expiry,
			"new_expiry": newProviderToken.Expiry,
			"threshold":  refreshThreshold.String(),
		},
	})
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
	if s.config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
		userInfo, _, err := s.validateSelfIssuedJWT(ctx, accessToken)
		return userInfo, err
	}

	// PRIORITY 2: Forwarded ID token (JWT) from a trusted upstream service.
	// Must run BEFORE the opaque path, as ID tokens cannot be validated via
	// the upstream provider's userinfo endpoint.
	if len(s.config.TrustedAudiences) > 0 && oidc.IsJWT(accessToken) {
		userInfo, err := s.validateForwardedIDToken(ctx, accessToken)
		if err != nil {
			s.logger.Debug("Forwarded ID token validation failed, falling back to userinfo",
				"error", err.Error(),
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		} else if userInfo != nil {
			s.logger.Debug("Forwarded ID token validated via JWKS",
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
		s.auditor.LogAuthFailure(ctx, "", "", "", err.Error())
		return nil, err
	}

	// Set token source to OAuth since this is the normal OAuth flow
	// (the server issued the token and the provider's ID token is stored)
	userInfo.TokenSource = providers.TokenSourceOAuth

	// Store user info
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, providerUserInfoToStorage(userInfo)); err != nil {
		s.logger.Warn("Failed to save user info", "error", err)
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
			s.logger.Debug("Token expired locally",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.config.ClockSkewGracePeriod,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))

			s.auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")

			return nil, fmt.Errorf("access token expired (local validation)")
		}

		// Singleflight: deduplicate concurrent refresh attempts for the same token.
		// Detach the leader's ctx from caller cancellation so one cancelled
		// caller does not fail all coalesced waiters.
		result, err, _ := s.refreshGroup.Do(accessToken, func() (interface{}, error) {
			return s.provider.RefreshToken(context.WithoutCancel(ctx), storedToken.RefreshToken)
		})

		if err != nil {
			s.logger.Debug("Token expired locally and refresh failed",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.config.ClockSkewGracePeriod,
				"refresh_error", err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))

			s.auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")

			return nil, fmt.Errorf("access token expired (local validation, refresh failed: %w)", err)
		}

		newProviderToken := result.(*oauth2.Token)
		newProviderToken = preserveRefreshToken(newProviderToken, storedToken.RefreshToken)
		s.updateProviderTokenMappings(ctx, accessToken, newProviderToken)

		s.fireTokenRefreshHandler(ctx, accessToken, newProviderToken)

		s.logger.Debug("Expired provider token refreshed during validation",
			"old_expiry", storedToken.Expiry,
			"new_expiry", newProviderToken.Expiry,
			"token_suffix", helpers.TokenSuffix(accessToken, 8))
		storedToken = newProviderToken
	}

	s.logger.Debug("Token passed local expiry validation",
		"expiry", storedToken.Expiry,
		"grace_period_seconds", s.config.ClockSkewGracePeriod)

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

	expectedAudience := s.config.GetResourceIdentifier()
	normalizedAudience := helpers.NormalizeURL(metadata.Audience)
	normalizedExpected := helpers.NormalizeURL(expectedAudience)

	// Check if audience matches this server's own resource identifier
	if subtle.ConstantTimeCompare([]byte(normalizedAudience), []byte(normalizedExpected)) == 1 {
		s.logger.Debug("Token audience validation passed",
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
	return helpers.MatchAudienceSecure(audience, s.config.TrustedAudiences) != ""
}

// logCrossClientTokenAccepted logs when a token is accepted via TrustedAudiences.
// This audit event helps track SSO token usage patterns for security monitoring.
func (s *Server) logCrossClientTokenAccepted(ctx context.Context, accessToken string, metadata *storage.TokenMetadata) {
	s.logger.Debug("Token accepted via TrustedAudiences (SSO token forwarding)",
		"token_audience", metadata.Audience,
		"user_id", metadata.UserID,
		"client_id", metadata.ClientID,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	s.auditor.LogEvent(ctx, security.Event{
		Type:     security.EventCrossClientTokenAccepted,
		UserID:   metadata.UserID,
		ClientID: metadata.ClientID,
		Details: map[string]any{
			"original_audience":   metadata.Audience,
			"server_identifier":   s.config.GetResourceIdentifier(),
			"trusted_via":         "TrustedAudiences",
			"sso_token_forwarded": true,
		},
	})
}

// logAudienceMismatch logs an audience mismatch security event.
func (s *Server) logAudienceMismatch(ctx context.Context, accessToken string, metadata *storage.TokenMetadata, expectedAudience string) {
	if s.securityEventRateLimiter == nil || s.securityEventRateLimiter.Allow(metadata.UserID+":"+metadata.ClientID+":audience_mismatch") {
		s.logger.Warn("Token audience mismatch - token not intended for this resource server",
			"token_audience", metadata.Audience,
			"server_identifier", expectedAudience,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"user_id", metadata.UserID,
			"client_id", metadata.ClientID)
	}

	s.auditor.LogEvent(ctx, security.Event{
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
	s.auditor.LogAuthFailure(ctx, metadata.UserID, metadata.ClientID, "", "audience_mismatch")
}

// selectTokenForProviderValidation determines which token to use for provider validation.
func (s *Server) selectTokenForProviderValidation(accessToken string, storedToken *oauth2.Token) string {
	if storedToken != nil && storedToken.AccessToken != "" {
		return storedToken.AccessToken
	}
	return accessToken
}
