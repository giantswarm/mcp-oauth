package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

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
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventRevokedTokenFamilyReuseAttempt, UserID: family.UserID, ClientID: clientID,
			Details: map[string]any{"severity": "critical", "family_id": family.FamilyID},
		})
		s.Logger.Error("Attempted use of revoked token family",
			"user_id", family.UserID, "family_id", helpers.SafeTruncate(family.FamilyID, 8))
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Token is deleted but family exists and NOT revoked → FRESH REUSE DETECTED!
	s.Instrumentation.Metrics().RecordTokenReuseDetected(ctx)

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

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventRefreshTokenReuseDetected, UserID: family.UserID, ClientID: clientID,
		Details: map[string]any{
			"severity": "critical", "family_id": family.FamilyID, "generation": family.Generation,
			"action": "family_and_tokens_revoked",
		},
	})
	s.Auditor.LogTokenReuse(ctx, family.UserID, clientID)

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
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure, ClientID: clientID,
			Details: map[string]any{"reason": "transient_storage_error"},
		})
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	// Regular invalid token error
	s.Logger.Debug("Refresh token validation failed",
		"reason", err.Error(), "client_id", clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
	s.Auditor.LogAuthFailure(ctx, "", clientID, "", "invalid_refresh_token")
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

	s.Auditor.LogTokenRefreshed(ctx, userID, clientID, "", rotated)

	return tokenResponse, nil
}

// handleLegacyRefreshToken rejects refresh tokens that lack client binding.
// OAuth 2.1 Section 6 requires client binding - tokens without it are invalid.
func (s *Server) handleLegacyRefreshToken(ctx context.Context, requestingClientID, userID string) error {
	s.Instrumentation.Metrics().RecordLegacyRefreshTokenRejected(ctx)

	s.Logger.Warn("Refresh token rejected - missing client binding",
		"user_id", userID,
		"requesting_client_id", requestingClientID,
		"reason", "OAuth 2.1 Section 6 requires client binding")

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

		// Return generic error per OAuth spec (don't reveal details to attacker)
		return fmt.Errorf("%s: invalid grant", ErrorCodeInvalidGrant)
	}

	s.Logger.Debug("Refresh token client binding validated",
		"user_id", userID,
		"client_id", storedClientID)

	return nil
}
