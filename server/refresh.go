package server

import (
	"context"
	"crypto/subtle"
	"errors"
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
			Details: map[string]any{logKeySeverity: severityCritical, logKeyFamilyID: family.FamilyID},
		})
		s.Logger.Error("Attempted use of revoked token family",
			"user_id", family.UserID, logKeyFamilyID, helpers.SafeTruncate(family.FamilyID, 8))
		return errInvalidGrant
	}

	// Token is deleted but family exists and NOT revoked → FRESH REUSE DETECTED!
	s.Instrumentation.Metrics().RecordTokenReuseDetected(ctx)

	if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(family.UserID+":"+clientID) {
		s.Logger.Error("Refresh token reuse detected - token was rotated but still being used",
			"user_id", family.UserID, paramClientID, clientID, logKeyFamilyID, helpers.SafeTruncate(family.FamilyID, 8))
	}

	s.revokeReusedFamily(ctx, family, familyStore)

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventRefreshTokenReuseDetected, UserID: family.UserID, ClientID: clientID,
		Details: map[string]any{
			logKeySeverity: severityCritical, logKeyFamilyID: family.FamilyID, "generation": family.Generation,
			logKeyAction: actionFamilyRevoked,
		},
	})
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventTokenReuseDetected, UserID: family.UserID, ClientID: clientID,
		Details: map[string]any{logKeySeverity: severityCritical, logKeyAction: actionFamilyRevoked},
	})

	return errInvalidGrant
}

// revokeReusedFamily revokes the token family a reused refresh token belongs
// to — its refresh, access and id_tokens — and nothing else of the user. A
// reuse proves only that this family's lineage leaked or raced (two processes
// of one client sharing a refresh token), so the user's other families, on
// this client or any other, stay signed in.
//
// The upstream grant follows the same line. In the legacy layout every token
// holds its own copy of its family's provider grant, and those copies are
// revoked at the provider. In the unified layout the provider grant is the
// user's ONE shared entry that every other family refreshes through; a client
// only ever holds mcp-oauth tokens, so the reused family never exposed it, and
// revoking it would sign the user out of every client — it is kept.
//
// Local revocation never depends on the provider: the family is revoked even
// when the provider cannot be reached.
func (s *Server) revokeReusedFamily(ctx context.Context, family *storage.RefreshTokenFamilyMetadata, familyStore storage.RefreshTokenFamilyStore) {
	tokens := s.familyTokens(ctx, family)

	if _, unified := s.userProviderTokenStore(); !unified && len(tokens) > 0 {
		if _, failed, total := s.revokeTokensAtProvider(ctx, tokens, family.UserID, family.ClientID); failed > 0 {
			s.Logger.Error("Failed to revoke reused token family at provider",
				"user_id", family.UserID, paramClientID, family.ClientID,
				logKeyFamilyID, helpers.SafeTruncate(family.FamilyID, 8), "failed", failed, "total", total)
		}
	}

	if fs, ok := s.tokenStore.(storage.TokenFamilyRevocationStore); ok {
		if _, err := fs.RevokeTokensForFamily(ctx, family.UserID, family.ClientID, family.FamilyID); err != nil {
			s.Logger.Error("Failed to revoke token family", logKeyError, err)
		}
	} else if err := familyStore.RevokeRefreshTokenFamily(ctx, family.FamilyID); err != nil {
		s.Logger.Error("Failed to revoke token family", logKeyError, err)
	}

	for _, tokenID := range tokens {
		s.unregisterTokenPairIfPresent(tokenID)
	}

	if s.sessionRevocationHandler != nil {
		s.sessionRevocationHandler(ctx, family.UserID, family.FamilyID)
	}
}

// familyTokens returns the access and refresh tokens issued under family,
// read from the user+client index and each token's metadata. It returns nil
// when the store can neither list nor describe tokens.
func (s *Server) familyTokens(ctx context.Context, family *storage.RefreshTokenFamilyMetadata) []string {
	lister, canList := s.tokenStore.(storage.TokenRevocationStore)
	metaGetter, canDescribe := s.tokenStore.(storage.TokenMetadataGetter)
	if !canList || !canDescribe {
		return nil
	}
	tokenIDs, err := lister.GetTokensByUserClient(ctx, family.UserID, family.ClientID)
	if err != nil {
		s.Logger.Warn("Could not list the reused token family's tokens", logKeyError, err)
		return nil
	}
	tokens := make([]string, 0, len(tokenIDs))
	for _, tokenID := range tokenIDs {
		meta, err := metaGetter.GetTokenMetadata(tokenID)
		if err == nil && meta != nil && meta.FamilyID == family.FamilyID && meta.TokenType != "id" {
			tokens = append(tokens, tokenID)
		}
	}
	return tokens
}

// handleSharedProviderTokenError classifies a failure to read the user's
// shared provider entry (unified layout) for a refresh token that was just
// proven valid by GetRefreshTokenInfo.
//
// A missing or expired shared entry is NOT refresh-token reuse: the refresh
// token record itself is present and unconsumed, so routing this through
// handleRefreshTokenError would trip reuse detection against a live family
// and revoke that session (family revocation + critical theft audit) over a
// benign storage miss — an evicted providertoken:<user> key, TTL collapse, or
// a deploy without a token flush; the exact false positive
// giantswarm/giantswarm#37164 is about. Authorization-code reuse
// (RevokeAllTokensForUserClient) also deletes the shared entry deliberately,
// so that user's surviving sessions land here by design. The user simply has
// to log in again: return invalid_grant with a non-theft audit trail.
//
// The presented refresh token is deliberately NOT consumed here: "record
// deleted + family alive and non-revoked" is exactly the fresh-reuse
// signature, so consuming it would send a client that retries the same token
// after the invalid_grant straight into handleRefreshTokenReuseDetection —
// family revoke + critical theft audit — recreating the false-alarm class this path exists to remove. Left
// un-consumed, a retry idempotently re-enters this same benign invalid_grant
// path (one cheap extra read), and a single re-login repairs all of the
// user's sessions.
//
// Any other error is a transient storage failure and surfaces as
// ErrStorageUnavailable, NOT invalid_grant: the grant is still valid and the
// client should retry, not re-login. The refresh token is left untouched in
// that case too.
func (s *Server) handleSharedProviderTokenError(ctx context.Context, err error, refreshToken, userID, clientID string) error {
	if storage.IsTransientError(err) {
		return s.storageUnavailable(ctx, "read shared provider token", clientID, userID, err)
	}

	msg, reason := "Shared provider token missing for valid refresh token - re-login required", "shared_provider_token_missing"
	if errors.Is(err, storage.ErrTokenUndecryptable) {
		msg, reason = "Shared provider token cannot be decrypted - re-login required", "token_undecryptable"
	}
	s.Logger.Warn(msg,
		"user_id", userID, paramClientID, clientID, logKeyReason, err.Error(),
		"token_suffix", helpers.TokenSuffix(refreshToken, 8))
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, UserID: userID, ClientID: clientID,
		Details: map[string]any{
			logKeySeverity: "warning",
			logKeyReason:   reason,
			logKeyAction:   "re_login_required",
		},
	})
	s.Auditor.LogAuthFailure(ctx, userID, clientID, "", reason)

	return errInvalidGrant
}

// handleRefreshTokenError handles errors from refresh token validation
// Returns error suitable for returning to client: invalid_grant for
// not-found/expired tokens (after reuse detection where supported), or
// ErrStorageUnavailable for transient storage failures — the token's state
// is unknown, so the client must be able to retry rather than re-login.
// Both call sites tolerate the transient mapping: the resolve-front check
// runs before the token is consumed (retry re-validates the intact token),
// and the post-refresh consume leaves the token unconsumed on a transient
// failure (retry re-presents it and adopts the already-rotated shared entry).
func (s *Server) handleRefreshTokenError(ctx context.Context, err error, refreshToken, clientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) error {
	// Transient storage failure: the token was not proven invalid, so the
	// client must not be pushed into re-login (consistent with the transient
	// taxonomy of the shared-entry and metadata reads on this path).
	if storage.IsTransientError(err) {
		return s.storageUnavailable(ctx, "validate refresh token", clientID, "", err)
	}

	// Legacy layout only: AtomicGetAndDeleteRefreshToken returns the
	// provider-token copy, and a copy the encryption key cannot decrypt was
	// written under an earlier key, not rotated away. No reuse, so the family
	// is left alone and the client signs in again. The consume already
	// deleted the record, so a client that presents the same refresh token
	// again still meets reuse detection.
	if errors.Is(err, storage.ErrTokenUndecryptable) {
		s.Logger.Warn("Refresh token record cannot be decrypted - re-login required",
			paramClientID, clientID, logKeyReason, err.Error(), "token_suffix", helpers.TokenSuffix(refreshToken, 8))
		s.Auditor.LogAuthFailure(ctx, "", clientID, "", "token_undecryptable")
		return errInvalidGrant
	}

	// Check for reuse if token not found and family tracking is supported
	if supportsFamilies {
		if reuseErr := s.handleRefreshTokenReuseDetection(ctx, refreshToken, clientID, familyStore); reuseErr != nil {
			return reuseErr
		}
	}

	// Regular invalid token error
	s.Logger.Debug("Refresh token validation failed",
		logKeyReason, err.Error(), paramClientID, clientID, "token_suffix", helpers.TokenSuffix(refreshToken, 8))
	s.Auditor.LogAuthFailure(ctx, "", clientID, "", "invalid_refresh_token")
	return errInvalidGrant
}

// rotateRefreshToken handles OAuth 2.1 refresh token rotation with family tracking.
// Returns (newRefreshToken, familyID, rotated).
func (s *Server) rotateRefreshToken(ctx context.Context, oldRefreshToken, userID, clientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) (string, string, bool, error) {
	if !s.Config.AllowRefreshTokenRotation {
		s.Logger.Warn("Refresh token reused (rotation disabled)", "user_id", userID)
		return oldRefreshToken, "", false, nil
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
			if storage.IsTransientError(err) {
				return "", "", false, s.storageUnavailable(ctx, "read refresh token family", clientID, userID, err)
			}
			familyID = generateRandomToken()
			generation = 1
		}
	}

	s.Logger.Debug("Refresh token rotated (OAuth 2.1)",
		"user_id", userID, "generation", generation, "family_tracking", supportsFamilies)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(attribute.Bool(instrumentation.AttrTokenRotated, true))
	}

	// Save with family tracking if supported
	refreshTokenExpiry := s.refreshTokenExpiry(time.Now())
	if supportsFamilies && familyID != "" {
		if err := familyStore.SaveRefreshTokenWithFamily(ctx, newRefreshToken, userID, clientID, familyID, generation, refreshTokenExpiry); err != nil {
			s.discardTokenPair(ctx, "", newRefreshToken)
			return "", "", false, s.storageUnavailable(ctx, "save refresh token family", clientID, userID, err)
		}
	} else {
		if err := s.tokenStore.SaveRefreshToken(ctx, newRefreshToken, userID, refreshTokenExpiry); err != nil {
			s.discardTokenPair(ctx, "", newRefreshToken)
			return "", "", false, s.storageUnavailable(ctx, "save refresh token", clientID, userID, err)
		}
	}

	return newRefreshToken, familyID, true, nil
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

// providerTokenForRefresh reads the user's shared provider entry when present.
func (s *Server) providerTokenForRefresh(ctx context.Context, userID string, consumedToken *oauth2.Token) (*oauth2.Token, error) {
	if upts, unified := s.userProviderTokenStore(); unified {
		return upts.GetUserProviderToken(ctx, userID)
	}
	return consumedToken, nil
}

// refreshProviderTokenForGrant coordinates provider refresh and durable
// write-back under a user lock or a legacy token-entry lock.
func (s *Server) refreshProviderTokenForGrant(ctx context.Context, userID, refreshToken string, observed *oauth2.Token) (*oauth2.Token, error) {
	if _, unified := s.userProviderTokenStore(); unified {
		return s.refreshUserProviderToken(ctx, userID, observed)
	}
	if _, ok := s.providerRefreshLocker(); !ok {
		return nil, errors.New("legacy token grants require storage.ProviderRefreshLockStore")
	}
	entry := legacyProviderTokenEntry{store: s.tokenStore, tokenID: refreshToken}
	return s.refreshProviderTokenEntry(ctx, entry, entry.key(), observed)
}

// storeRefreshedProviderToken points the freshly issued tokens at the user's
// provider token after a refresh grant. Unified layout: the shared per-user
// entry was already persisted under the refresh lock by the coordinator, so
// this only records the new access/refresh token references — re-saving the
// shared entry here (outside the lock) could clobber a newer token a sibling
// session just rotated in. Legacy layout: private copies under the new
// access/refresh token keys.
func (s *Server) storeRefreshedProviderToken(ctx context.Context, userID, newAccessToken, newRefreshToken string, newProviderToken *oauth2.Token, refreshExpiry time.Time) error {
	if upts, unified := s.userProviderTokenStore(); unified {
		if err := upts.SaveProviderTokenRef(ctx, newAccessToken, userID, refreshExpiry); err != nil {
			return s.storageUnavailable(ctx, "save access token provider reference", "", userID, err)
		}
		if err := upts.SaveProviderTokenRef(ctx, newRefreshToken, userID, refreshExpiry); err != nil {
			return s.storageUnavailable(ctx, "save refresh token provider reference", "", userID, err)
		}
		return nil
	}
	if err := s.tokenStore.SaveToken(ctx, newAccessToken, newProviderToken); err != nil {
		return s.storageUnavailable(ctx, "save access token mapping", "", userID, err)
	}
	if err := s.tokenStore.SaveToken(ctx, newRefreshToken, newProviderToken); err != nil {
		return s.storageUnavailable(ctx, "save refresh token mapping", "", userID, err)
	}
	return nil
}

// resolveRefreshGrant validates a refresh-token grant and returns the user it is
// bound to and the provider token to refresh against, reporting whether the
// backend uses the unified per-user provider-token layout.
//
// The grant remains unconsumed until required token writes succeed. Missing
// refresh-token records feed reuse detection through their retained family.
//
// Client binding (OAuth 2.1 §6) is validated before the shared provider entry is
// read, so a token presented by the wrong client never reads it, acquires the
// refresh lock, or triggers an upstream call. metaClientID is the stored client
// binding read non-destructively from the token metadata — the same value the
// atomic consume returns.
func (s *Server) resolveRefreshGrant(ctx context.Context, refreshToken, clientID, metaClientID string, familyStore storage.RefreshTokenFamilyStore, supportsFamilies bool) (userID string, providerToken *oauth2.Token, unified bool, err error) {
	_, unified = s.userProviderTokenStore()

	var storedClientID string
	userID, err = s.tokenStore.GetRefreshTokenInfo(ctx, refreshToken)
	if err != nil {
		return "", nil, unified, s.handleRefreshTokenError(ctx, err, refreshToken, clientID, familyStore, supportsFamilies)
	}
	storedClientID = metaClientID

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
	} else {
		providerToken, err = s.tokenStore.GetToken(ctx, refreshToken)
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

	metadata, err := s.TokenMetadata(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		metadata = &storage.TokenMetadata{}
	}

	userID, providerToken, unified, err := s.resolveRefreshGrant(ctx, refreshToken, clientID, metadata.ClientID, familyStore, supportsFamilies)
	if err != nil {
		return nil, err
	}

	// Refresh the upstream provider token through the per-user single-flight
	// coordinator (unified layout): at most one of the user's concurrent
	// sessions talks to the provider per rotation window, and the rest adopt
	// the freshly-written shared entry without ever calling it.
	newProviderToken, err := s.refreshProviderTokenForGrant(ctx, userID, refreshToken, providerToken)
	if err != nil {
		if !unified && storage.IsNotFoundError(err) {
			_, _, _, grantErr := s.resolveRefreshGrant(ctx, refreshToken, clientID, metadata.ClientID, familyStore, supportsFamilies)
			if grantErr != nil {
				return nil, grantErr
			}
		}
		if !errors.Is(err, ErrStorageUnavailable) && isTransientProviderError(err) {
			return nil, s.providerUnavailable(ctx, "refresh", userID, clientID, err)
		}
		s.logAuthFailure(ctx, userID, clientID, fmt.Sprintf("provider_refresh_failed: %v", err))
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	baseMetadata := *metadata
	baseMetadata.UserID = userID
	return s.issueRefreshedTokens(ctx, refreshToken, newProviderToken, baseMetadata)
}

func (s *Server) issueRefreshedTokens(ctx context.Context, refreshToken string, newProviderToken *oauth2.Token, metadata storage.TokenMetadata) (*oauth2.Token, error) {
	userID, clientID := metadata.UserID, metadata.ClientID
	familyStore, supportsFamilies := s.tokenStore.(storage.RefreshTokenFamilyStore)
	now := time.Now()

	// OAuth 2.1: Refresh Token Rotation
	newRefreshToken, familyID, rotated, err := s.rotateRefreshToken(ctx, refreshToken, userID, clientID, familyStore, supportsFamilies)
	if err != nil {
		return nil, err
	}
	if !rotated {
		familyID = metadata.FamilyID
	}
	committed := false
	var newAccessToken string
	defer func() {
		if !committed {
			stagedRefreshToken := newRefreshToken
			if !rotated {
				stagedRefreshToken = ""
			}
			s.discardTokenPair(ctx, newAccessToken, stagedRefreshToken)
		}
	}()

	var providerExpiry time.Time
	if newProviderToken != nil {
		providerExpiry = newProviderToken.Expiry
	}
	expiry := s.capTokenExpiry(now, providerExpiry)
	refreshExpiry := s.refreshTokenExpiry(now)

	newAccessToken, err = s.issueAccessToken(ctx, accessTokenIssueParams{
		UserID:    userID,
		ClientID:  clientID,
		Audience:  metadata.Audience,
		Scopes:    metadata.Scopes,
		ExpiresAt: expiry,
		FamilyID:  familyID,
		JKT:       metadata.JKT,
	})
	if err != nil {
		return nil, fmt.Errorf("issue access token on refresh: %w", err)
	}

	// Create token response using oauth2.Token
	tokenResponse := &oauth2.Token{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		Expiry:       expiry,
		TokenType:    tokenTypeBearer,
	}

	// OIDC Core §12.2 binds nonce to the authentication request, not refresh.
	idToken := ExtractIDToken(newProviderToken)
	if idToken != "" {
		tokenResponse = tokenResponse.WithExtra(map[string]any{
			"id_token": idToken,
		})
	}

	if err := s.storeRefreshedProviderToken(ctx, userID, newAccessToken, newRefreshToken, newProviderToken, refreshExpiry); err != nil {
		return nil, err
	}

	baseMetadata := storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: expiry,
		Audience:  metadata.Audience,
		FamilyID:  familyID,
		Scopes:    metadata.Scopes,
		JKT:       metadata.JKT,
	}
	if err := s.saveTokenPairMetadata(ctx, newAccessToken, newRefreshToken, baseMetadata, refreshExpiry); err != nil {
		return nil, err
	}
	if rotated {
		if _, _, _, err := s.consumeRefreshToken(ctx, refreshToken); err != nil {
			return nil, s.handleRefreshTokenError(ctx, err, refreshToken, clientID, familyStore, supportsFamilies)
		}
		s.unregisterTokenPairByRefresh(refreshToken)
	}
	committed = true
	s.registerTokenPair(newAccessToken, newRefreshToken)
	if idToken != "" {
		s.saveIDTokenMetadata(ctx, idToken, baseMetadata)
	}

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
		logKeyReason, "OAuth 2.1 Section 6 requires client binding")

	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventRefreshTokenMissingClientBinding,
		UserID:   userID,
		ClientID: requestingClientID,
		Details: map[string]any{
			logKeySeverity:  severityHigh,
			logKeyAction:    "rejected",
			"security_risk": "cross_client_token_theft_prevented",
			logKeyOAuthSpec: "OAuth 2.1 Section 6",
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
				logKeyOAuthSpec, "OAuth 2.1 Section 6")
		}

		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventRefreshTokenClientBindingMismatch,
			UserID:   userID,
			ClientID: requestingClientID,
			Details: map[string]any{
				logKeySeverity:         severityCritical,
				"stored_client_id":     storedClientID,
				"requesting_client_id": requestingClientID,
				"attack_indicator":     "cross_client_token_theft_attempt",
				logKeyOAuthSpec:        "OAuth 2.1 Section 6",
			},
		})
		s.Auditor.LogAuthFailure(ctx, userID, requestingClientID, "", "refresh_token_client_binding_mismatch")

		// Return generic error per OAuth spec (don't reveal details to attacker)
		return errInvalidGrant
	}

	s.Logger.Debug("Refresh token client binding validated",
		"user_id", userID,
		paramClientID, storedClientID)

	return nil
}
