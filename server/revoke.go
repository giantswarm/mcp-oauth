package server

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

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

	// Get provider token (via the shared per-user entry in the unified layout)
	providerToken, err := s.resolveProviderToken(ctx, token)
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

	// Delete locally. Unified layout: only this token's reference is removed —
	// the shared per-user provider entry stays, since the user's other
	// sessions still resolve to it (matching the legacy behavior where each
	// session held its own copy and only this one was deleted).
	if upts, unified := s.userProviderTokenStore(); unified {
		if err := upts.DeleteProviderTokenRef(ctx, token); err != nil {
			s.Logger.Warn("Failed to delete provider token reference", "error", err)
		}
	} else if err := s.tokenStore.DeleteToken(ctx, token); err != nil {
		s.Logger.Warn("Failed to delete token locally", "error", err)
	}
	s.unregisterTokenPairIfPresent(token)

	s.revokeTokenFamilyIfNeeded(ctx, family, clientID, clientIP)

	s.Auditor.LogTokenRevoked(ctx, "", clientID, clientIP, "access_or_refresh")

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

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventTokenRevocationNotSupported, UserID: userID, ClientID: clientID,
		Details: map[string]any{"severity": "critical", "message": "Storage backend does not support bulk token revocation - OAuth 2.1 compliance FAILED"},
	})

	return fmt.Errorf("storage backend must implement TokenRevocationStore for OAuth 2.1 compliance")
}

// revokeTokensAtProvider revokes all tokens at the provider
// Returns (revokedCount, failedCount, totalCount)
//
// In the unified layout every token ID resolves to the user's ONE shared
// provider entry, so the same upstream credential is deduplicated and revoked
// once rather than once per issued token.
func (s *Server) revokeTokensAtProvider(ctx context.Context, tokens []string, userID, clientID string) (int, int, int) {
	revokedAtProvider := 0
	failedAtProvider := 0
	totalTokensToRevoke := 0
	seen := make(map[string]bool)

	revokeOnce := func(credential, tokenType string) {
		if credential == "" || seen[credential] {
			return
		}
		seen[credential] = true
		totalTokensToRevoke++
		if err := s.revokeTokenWithRetry(ctx, credential, tokenType, userID, clientID); err != nil {
			failedAtProvider++
		} else {
			revokedAtProvider++
		}
	}

	for _, tokenID := range tokens {
		providerToken, err := s.resolveProviderToken(ctx, tokenID)
		if err != nil {
			s.Logger.Warn("Could not get provider token for revocation",
				"token_id", helpers.SafeTruncate(tokenID, 8), "error", err)
			continue
		}

		revokeOnce(providerToken.AccessToken, "access")
		revokeOnce(providerToken.RefreshToken, "refresh")
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

		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventProviderRevocationThresholdExceeded, UserID: userID, ClientID: clientID,
			Details: map[string]any{
				"severity": "critical", "failure_rate": failureRate, "threshold": s.Config.ProviderRevocationFailureThreshold,
				"failed_count": failedCount, "total_count": totalTokens, "oauth_spec": "OAuth 2.1 Section 4.1.2",
			},
		})

		return fmt.Errorf("provider revocation failure rate %.2f%% exceeds threshold %.2f%% (%d/%d failed)",
			failureRate*100, s.Config.ProviderRevocationFailureThreshold*100, failedCount, totalTokens)
	}

	if revokedCount == 0 && totalTokens > 0 {
		s.Logger.Error("CRITICAL: All provider revocations failed - tokens still valid at provider!",
			"user_id", userID, "client_id", clientID, "token_count", totalTokens)

		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventProviderRevocationCompleteFailure, UserID: userID, ClientID: clientID,
			Details: map[string]any{"severity": "critical", "token_count": totalTokens, "oauth_spec": "OAuth 2.1 Section 4.1.2"},
		})

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
