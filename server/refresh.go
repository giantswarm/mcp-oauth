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

// isTokenMetadataAbsent reports whether err from
// storage.TokenMetadataGetter.GetTokenMetadata means the metadata record is
// genuinely absent (storage.ErrTokenNotFound sentinel), as opposed to a
// transient storage failure. The two must not be conflated on the refresh
// path: absence classifies the token as a legacy unbound token
// (invalid_grant), while a transient failure must be retryable (server
// error). Absence signaled as (nil, nil) is handled at the call site.
func isTokenMetadataAbsent(err error) bool {
	return storage.IsNotFoundError(err)
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
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventRevokedTokenFamilyReuseAttempt, UserID: family.UserID, ClientID: clientID,
			Details: map[string]any{"severity": "critical", "family_id": family.FamilyID},
		})
		s.Logger.Error("Attempted use of revoked token family",
			"user_id", family.UserID, "family_id", helpers.SafeTruncate(family.FamilyID, 8))
		return errInvalidGrant
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

	return errInvalidGrant
}

// handleSharedProviderTokenError classifies a failure to read the user's
// shared provider entry (unified layout) for a refresh token that was just
// proven valid by GetRefreshTokenInfo.
//
// A missing or expired shared entry is NOT refresh-token reuse: the refresh
// token record itself is present and unconsumed, so routing this through
// handleRefreshTokenError would trip reuse detection against a live family
// and revoke every session of the user (RevokeRefreshTokenFamily +
// RevokeAllTokensForUserClient + critical theft audit) over a benign storage
// miss — an evicted providertoken:<user> key, TTL collapse, or a deploy
// without a token flush; the exact false positive giantswarm/giantswarm#37164
// is about. The reuse-nuke path also deletes the shared entry deliberately,
// so a nuked user's surviving sessions land here by design. The user simply
// has to log in again: return invalid_grant with a non-theft audit trail.
//
// The presented refresh token is deliberately NOT consumed here: "record
// deleted + family alive and non-revoked" is exactly the fresh-reuse
// signature, so consuming it would send a client that retries the same token
// after the invalid_grant straight into handleRefreshTokenReuseDetection —
// family revoke + RevokeAllTokensForUserClient + critical theft audit —
// recreating the false-alarm class this path exists to remove. Left
// un-consumed, a retry idempotently re-enters this same benign invalid_grant
// path (one cheap extra read), and a single re-login repairs all of the
// user's sessions.
//
// Any other error is a transient storage failure and surfaces as a server
// error, NOT invalid_grant: the grant is still valid and the client should
// retry, not re-login. The refresh token is left untouched in that case too.
func (s *Server) handleSharedProviderTokenError(ctx context.Context, err error, refreshToken, userID, clientID string) error {
	if !storage.IsNotFoundError(err) && !storage.IsExpiredError(err) {
		s.Logger.Warn("Transient error reading shared provider token during refresh",
			"error", err.Error(), "user_id", userID, "client_id", clientID,
			"token_suffix", helpers.TokenSuffix(refreshToken, 8))
		return fmt.Errorf("read shared provider token: %w", err)
	}

	s.Logger.Warn("Shared provider token missing for valid refresh token - re-login required",
		"user_id", userID, "client_id", clientID, "reason", err.Error(),
		"token_suffix", helpers.TokenSuffix(refreshToken, 8))
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, UserID: userID, ClientID: clientID,
		Details: map[string]any{
			"severity": "warning",
			"reason":   "shared_provider_token_missing",
			"action":   "re_login_required",
		},
	})
	s.Auditor.LogAuthFailure(ctx, userID, clientID, "", "shared_provider_token_missing")

	return errInvalidGrant
}

// handleRefreshTokenError handles errors from refresh token validation
// Returns error suitable for returning to client: invalid_grant for
// not-found/expired tokens (after reuse detection where supported), or a
// retryable server error for transient storage failures — the token's state
// is unknown, so the client must be able to retry rather than re-login.
// Both call sites tolerate the transient mapping: the resolve-front check
// runs before the token is consumed (retry re-validates the intact token),
// and the post-refresh consume leaves the token unconsumed on a transient
// failure (retry re-presents it and adopts the already-rotated shared entry).
func (s *Server) handleRefreshTokenError(ctx context.Context, err error, refreshToken, clientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) error {
	isNotFoundOrExpired := storage.IsNotFoundError(err) || storage.IsExpiredError(err)

	// Check for reuse if token not found and family tracking is supported
	if isNotFoundOrExpired && supportsFamilies {
		if reuseErr := s.handleRefreshTokenReuseDetection(ctx, refreshToken, clientID, familyStore); reuseErr != nil {
			return reuseErr
		}
	}

	// Transient storage failure: surface as a retryable server error, not
	// invalid_grant — the token was not proven invalid, so the client must
	// not be pushed into re-login (consistent with the transient taxonomy of
	// the shared-entry and metadata reads on this path).
	if !isNotFoundOrExpired {
		s.Logger.Warn("Transient error during refresh token validation",
			"error", err.Error(), "client_id", clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure, ClientID: clientID,
			Details: map[string]any{"reason": "transient_storage_error"},
		})
		return fmt.Errorf("validate refresh token: %w", err)
	}

	// Regular invalid token error
	s.Logger.Debug("Refresh token validation failed",
		"reason", err.Error(), "client_id", clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
	s.Auditor.LogAuthFailure(ctx, "", clientID, "", "invalid_refresh_token")
	return errInvalidGrant
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
	refreshTokenExpiry := s.refreshTokenExpiry(time.Now())
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

// consumeRefreshToken atomically consumes the refresh token and returns its
// (userID, clientID) binding. Legacy layout: the provider-token copy stored
// under the refresh-token key is returned alongside. Unified layout: no copy
// exists — the returned token is nil and providerTokenForRefresh resolves the
// shared entry AFTER client binding validation.
func (s *Server) consumeRefreshToken(ctx context.Context, refreshToken string) (userID, clientID string, providerToken *oauth2.Token, err error) {
	if upts, unified := s.userProviderTokenStore(); unified {
		userID, clientID, err = upts.AtomicConsumeRefreshToken(ctx, refreshToken)
		return userID, clientID, nil, err
	}
	return s.tokenStore.AtomicGetAndDeleteRefreshToken(ctx, refreshToken)
}

// providerTokenForRefresh returns the provider token to refresh against the
// upstream IdP: the user's shared entry in the unified layout, or the copy
// consumed together with the refresh token in the legacy layout.
func (s *Server) providerTokenForRefresh(ctx context.Context, userID string, consumedToken *oauth2.Token) (*oauth2.Token, error) {
	if upts, unified := s.userProviderTokenStore(); unified {
		return upts.GetUserProviderToken(ctx, userID)
	}
	return consumedToken, nil
}

// refreshProviderTokenForGrant refreshes the upstream provider token for a
// refresh-token grant. Unified layout: route through the per-user single-flight
// coordinator, which persists the rotated token to the shared entry under the
// lock. Legacy layout: a direct, uncoordinated provider refresh against the
// copy consumed alongside the refresh token.
func (s *Server) refreshProviderTokenForGrant(ctx context.Context, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	if _, unified := s.userProviderTokenStore(); unified {
		return s.refreshUserProviderToken(ctx, userID, observed)
	}
	if observed == nil {
		return nil, fmt.Errorf("no provider token available to refresh")
	}
	newToken, err := s.provider.RefreshToken(ctx, observed.RefreshToken)
	if err != nil {
		return nil, err
	}
	// RFC 6749 §5.1: the provider may omit the refresh token in the refresh
	// response, in which case the previous one remains valid and must be
	// carried forward.
	return preserveRefreshToken(newToken, observed.RefreshToken), nil
}

// storeRefreshedProviderToken points the freshly issued tokens at the user's
// provider token after a refresh grant. Unified layout: the shared per-user
// entry was already persisted under the refresh lock by the coordinator, so
// this only records the new access/refresh token references — re-saving the
// shared entry here (outside the lock) could clobber a newer token a sibling
// session just rotated in. Legacy layout: private copies under the new
// access/refresh token keys.
func (s *Server) storeRefreshedProviderToken(ctx context.Context, userID, newAccessToken, newRefreshToken string, newProviderToken *oauth2.Token, refreshExpiry time.Time) {
	if upts, unified := s.userProviderTokenStore(); unified {
		if err := upts.SaveProviderTokenRef(ctx, newAccessToken, userID, refreshExpiry); err != nil {
			s.Logger.Warn("Failed to save access token provider reference", "error", err)
		}
		if err := upts.SaveProviderTokenRef(ctx, newRefreshToken, userID, refreshExpiry); err != nil {
			s.Logger.Warn("Failed to save refresh token provider reference", "error", err)
		}
		return
	}
	if err := s.tokenStore.SaveToken(ctx, newAccessToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new access token", "error", err)
	}
	if err := s.tokenStore.SaveToken(ctx, newRefreshToken, newProviderToken); err != nil {
		s.Logger.Warn("Failed to save new refresh token", "error", err)
	}
}

// resolveRefreshGrant validates a refresh-token grant and returns the user it is
// bound to and the provider token to refresh against, reporting whether the
// backend uses the unified per-user provider-token layout.
//
// L2 no-orphan (giantswarm/mcp-oauth#515): in the unified layout the mcp refresh
// token is NOT deleted here. Its binding is resolved with a non-destructive
// existence + expiry check (GetRefreshTokenInfo) that keeps the same
// not-found/expired semantics the atomic consume had — a rotated-away token
// (record gone, family metadata retained) still feeds reuse detection — and the
// caller atomically consumes it only after the provider refresh succeeds. In the
// legacy layout the provider-token copy can only be read by consuming the token,
// so the atomic delete stays up front (pre-unification behavior; no shared entry
// to protect).
//
// Client binding (OAuth 2.1 §6) is validated before the shared provider entry is
// read, so a token presented by the wrong client never reads it, acquires the
// refresh lock, or triggers an upstream call. metaClientID is the stored client
// binding read non-destructively from the token metadata — the same value the
// atomic consume returns.
func (s *Server) resolveRefreshGrant(ctx context.Context, refreshToken, clientID, metaClientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) (userID string, providerToken *oauth2.Token, unified bool, err error) {
	_, unified = s.userProviderTokenStore()

	var storedClientID string
	if unified {
		userID, err = s.tokenStore.GetRefreshTokenInfo(ctx, refreshToken)
		if err != nil {
			return "", nil, unified, s.handleRefreshTokenError(ctx, err, refreshToken, clientID, familyStore, supportsFamilies)
		}
		storedClientID = metaClientID
	} else {
		userID, storedClientID, providerToken, err = s.consumeRefreshToken(ctx, refreshToken)
		if err != nil {
			return "", nil, unified, s.handleRefreshTokenError(ctx, err, refreshToken, clientID, familyStore, supportsFamilies)
		}
	}

	// OAUTH 2.1 SECURITY: Validate client binding (Section 6) BEFORE any provider
	// refresh or lock acquisition. The refresh token MUST only be accepted by the
	// client it was issued to.
	if err = s.validateRefreshTokenClientBinding(ctx, storedClientID, clientID, userID); err != nil {
		return "", nil, unified, err
	}

	if unified {
		// Resolved only after client binding passed, so a stolen token from the
		// wrong client never reads the user's shared provider entry.
		//
		// NOT routed through handleRefreshTokenError: the refresh token was
		// just proven valid, so a missing shared entry is a benign storage
		// miss (re-login), never reuse — see handleSharedProviderTokenError.
		providerToken, err = s.providerTokenForRefresh(ctx, userID, nil)
		if err != nil {
			return "", nil, unified, s.handleSharedProviderTokenError(ctx, err, refreshToken, userID, clientID)
		}
	}

	return userID, providerToken, unified, nil
}

// RefreshAccessToken refreshes an access token using a refresh token with OAuth 2.1 rotation
// Returns oauth2.Token directly
// Implements OAuth 2.1 refresh token reuse detection for enhanced security
// Implements OAuth 2.1 Section 6 client binding validation
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken, clientID string) (*oauth2.Token, error) {
	// Check if storage supports token family tracking (OAuth 2.1 reuse detection)
	familyStore, supportsFamilies := s.tokenStore.(storage.RefreshTokenFamilyStore)

	// Capture scopes, audience, JKT, and the stored client binding from the old
	// token metadata. In the unified layout metaClientID supplies the client ID
	// for the pre-refresh binding check WITHOUT consuming the refresh token, so
	// the token can be rotated only after the provider refresh succeeds (L2
	// no-orphan). It is the same value the atomic consume would return — both
	// read the token's ClientID from its metadata.
	var oldScopes []string
	var oldAudience string
	var oldJKT string
	var metaClientID string
	if metaGetter, ok := s.tokenStore.(storage.TokenMetadataGetter); ok {
		oldMeta, metaErr := metaGetter.GetTokenMetadata(refreshToken)
		switch {
		case metaErr == nil && oldMeta != nil:
			oldScopes = oldMeta.Scopes
			oldAudience = oldMeta.Audience
			oldJKT = oldMeta.JKT
			metaClientID = oldMeta.ClientID
		case metaErr != nil && !isTokenMetadataAbsent(metaErr):
			// Transient storage failure. The stored client binding is a
			// prerequisite for the grant, not optional enrichment: leaving
			// metaClientID empty would misclassify a validly-bound token as a
			// legacy unbound token downstream (invalid_grant + a high-severity
			// cross_client_token_theft_prevented audit event). Surface a
			// server error instead — the refresh token has not been consumed,
			// so the client's retry succeeds once storage recovers. The old
			// legacy layout had the same retryability: it read ClientID
			// atomically inside the consume, which failed transiently as a
			// whole.
			s.Logger.Warn("Transient error reading refresh token metadata",
				"error", metaErr.Error(), "client_id", clientID,
				"token_suffix", helpers.TokenSuffix(refreshToken, 8))
			return nil, fmt.Errorf("read refresh token metadata: %w", metaErr)
		}
		// Metadata genuinely absent: metaClientID stays "" and the grant is
		// classified as a legacy unbound token by client binding validation.
	}

	// Resolve the grant's user binding and the provider token to refresh
	// against. In the unified layout this does NOT delete the mcp refresh token
	// (L2 no-orphan): the token is atomically consumed only after the provider
	// token is confirmed fresh, so a transient provider failure leaves an
	// otherwise-valid session intact. Client binding is validated inside, before
	// any provider read or refresh.
	userID, providerToken, unified, err := s.resolveRefreshGrant(ctx, refreshToken, clientID, metaClientID, familyStore, supportsFamilies)
	if err != nil {
		return nil, err
	}

	// Refresh the upstream provider token through the per-user single-flight
	// coordinator (unified layout): at most one of the user's concurrent
	// sessions talks to the provider per rotation window, and the rest adopt
	// the freshly-written shared entry without ever calling it.
	newProviderToken, err := s.refreshProviderTokenForGrant(ctx, userID, providerToken)
	if err != nil {
		s.logAuthFailure(ctx, userID, clientID, fmt.Sprintf("provider_refresh_failed: %v", err))
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// L2 NO-ORPHAN: rotate the mcp refresh token only AFTER the provider token is
	// confirmed fresh. Every early return above left the session's refresh token
	// intact, so a transient provider hiccup no longer orphans a valid session —
	// the client's retry succeeds instead of tripping reuse detection. The atomic
	// consume remains the concurrency gate: a genuinely reused or concurrently
	// double-submitted token loses it and feeds reuse detection exactly as before.
	if unified {
		if _, _, _, consumeErr := s.consumeRefreshToken(ctx, refreshToken); consumeErr != nil {
			return nil, s.handleRefreshTokenError(ctx, consumeErr, refreshToken, clientID, familyStore, supportsFamilies)
		}
	}

	now := time.Now()

	// OAuth 2.1: Refresh Token Rotation
	newRefreshToken, familyID, rotated := s.rotateRefreshToken(ctx, refreshToken, userID, clientID, familyStore, supportsFamilies)

	var providerExpiry time.Time
	if newProviderToken != nil {
		providerExpiry = newProviderToken.Expiry
	}
	expiry := s.capTokenExpiry(now, providerExpiry)
	refreshExpiry := s.refreshTokenExpiry(now)

	newAccessToken, err := s.issueAccessToken(ctx, accessTokenIssueParams{
		UserID:    userID,
		ClientID:  clientID,
		Audience:  oldAudience,
		Scopes:    oldScopes,
		ExpiresAt: expiry,
		FamilyID:  familyID,
		JKT:       oldJKT,
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

	s.storeRefreshedProviderToken(ctx, userID, newAccessToken, newRefreshToken, newProviderToken, refreshExpiry)

	// Track AT -> RT pairing for refresh-time updates
	s.registerTokenPair(newAccessToken, newRefreshToken)

	s.saveTokenPairMetadata(ctx, newAccessToken, newRefreshToken, storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: expiry,
		Audience:  oldAudience,
		FamilyID:  familyID,
		Scopes:    oldScopes,
		JKT:       oldJKT,
	}, refreshExpiry)

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
	return errInvalidGrant
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
		return errInvalidGrant
	}

	s.Logger.Debug("Refresh token client binding validated",
		"user_id", userID,
		"client_id", storedClientID)

	return nil
}
