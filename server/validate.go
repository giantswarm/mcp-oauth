package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// checkTypeHeader verifies the JWT typ header against an accepted set. An
// empty string in accepted matches a token with no typ header (Kubernetes
// ServiceAccount tokens omit it). The check runs on the verified token;
// reading the header from a re-parse is safe because the JWS signature
// covers the header bytes.
func checkTypeHeader(tokenString string, accepted []string) error {
	parsed, err := josejwt.ParseSigned(tokenString, supportedAccessTokenAlgs)
	if err != nil {
		return fmt.Errorf("parse JWT header: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return errors.New("JWT has no header")
	}
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if slices.Contains(accepted, typ) {
		return nil
	}
	return fmt.Errorf("typ header is %q, accepted %q (RFC 9068 §4 unless overridden per issuer)", typ, accepted)
}

// supportedAccessTokenAlgs lists the asymmetric signing algorithms accepted
// for JWT access tokens. HMAC and "none" are absent by design (RFC 9068 §4
// alg confusion mitigations).
var supportedAccessTokenAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// isTokenExpiredLocally checks if a token is expired considering clock skew grace period.
// Returns true if the token is expired beyond the grace period.
func (s *Server) isTokenExpiredLocally(token *oauth2.Token) bool {
	return security.IsTokenExpiredWithGracePeriod(token.Expiry, time.Duration(s.Config.ClockSkewGracePeriod)*time.Second)
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

// updateProviderTokenMappings persists a provider token refreshed during
// validation. Unified layout: the rotated token is written back to the ONE
// shared per-user entry (resolved via the access token's reference), so every
// sibling session sees the fresh credential. Legacy layout: copies are saved
// under both the access-token and refresh-token storage keys to prevent the
// refresh-token mapping from becoming stale when the provider rotates
// refresh tokens.
func (s *Server) updateProviderTokenMappings(ctx context.Context, accessToken string, newProviderToken *oauth2.Token) {
	if upts, unified := s.userProviderTokenStore(); unified {
		userID, err := upts.GetProviderTokenRef(ctx, accessToken)
		if err != nil {
			s.Logger.Warn("Failed to resolve access token to user for provider token write-back", logKeyError, err)
			return
		}
		if saveErr := upts.SaveUserProviderToken(ctx, userID, newProviderToken); saveErr != nil {
			s.Logger.Warn("Failed to save refreshed shared provider token", logKeyError, saveErr)
		}
		return
	}
	if saveErr := s.tokenStore.SaveToken(ctx, accessToken, newProviderToken); saveErr != nil {
		s.Logger.Warn("Failed to save refreshed provider token for access key", logKeyError, saveErr)
	}
	if pairedRT, ok := s.tokenPairs.Load(accessToken); ok {
		if saveErr := s.tokenStore.SaveToken(ctx, pairedRT.(string), newProviderToken); saveErr != nil {
			s.Logger.Warn("Failed to save refreshed provider token for refresh key", logKeyError, saveErr)
		}
	}
}

// refreshProviderDuringValidation refreshes the provider token backing an
// issued access token during validation (both the proactive near-expiry path
// and the reactive expired-token path).
//
// Unified layout: route through the per-user single-flight coordinator, which
// deduplicates concurrent refreshes across the user's sessions (same-pod via
// singleflight, cross-pod via the per-user lock) and persists the rotated
// token to the shared entry under the lock — so this MUST NOT write it back.
// The coordinator waits under the CALLER's ctx: a cancelled request stops
// waiting promptly instead of polling out the refresh window, while the
// winner's provider round-trip and write-back are detached inside the
// coordinator (refreshAndStoreSharedProviderToken), so one cancelled request
// can neither abort nor poison the refresh the user's other sessions adopt.
//
// Legacy layout: a direct provider refresh, coalesced per access token so
// concurrent validations of the same token hit the provider once, followed by
// a write-back to the token copies.
func (s *Server) refreshProviderDuringValidation(ctx context.Context, accessToken string, storedToken *oauth2.Token) (*oauth2.Token, error) {
	if upts, unified := s.userProviderTokenStore(); unified {
		return s.coordinatedRefreshByIssuedToken(ctx, upts, accessToken, storedToken)
	}

	result, err, _ := s.refreshGroup.Do(accessToken, func() (interface{}, error) {
		return s.provider.RefreshToken(context.WithoutCancel(ctx), storedToken.RefreshToken)
	})
	if err != nil {
		return nil, err
	}

	newProviderToken := preserveRefreshToken(result.(*oauth2.Token), storedToken.RefreshToken)
	s.updateProviderTokenMappings(ctx, accessToken, newProviderToken)
	return newProviderToken, nil
}

// fireTokenRefreshHandler invokes the registered TokenRefreshHandler (if any)
// after a provider token has been refreshed. It retrieves the userID and familyID
// from stored token metadata so callers don't need to plumb them through.
//
// The handler fires only with both IDs resolved. Consumers key per-session state
// on them, so an event they cannot attribute is worse than no event: a metadata
// miss drops it.
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
				logKeyError, err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		}
	}

	if userID == "" || familyID == "" {
		s.Logger.Debug("Skipping token refresh handler: unattributable refresh event",
			"has_user_id", userID != "",
			"has_family_id", familyID != "")
		return
	}

	s.tokenRefreshHandler(ctx, userID, familyID, newProviderToken)
}

// resolveProviderToken returns the provider token backing the given issued
// token. Unified layout: the token key is a reference — resolve token → user →
// shared provider entry. Legacy layout: the token key holds its own copy.
func (s *Server) resolveProviderToken(ctx context.Context, token string) (*oauth2.Token, error) {
	if upts, unified := s.userProviderTokenStore(); unified {
		userID, err := upts.GetProviderTokenRef(ctx, token)
		if err != nil {
			return nil, err
		}
		return upts.GetUserProviderToken(ctx, userID)
	}
	return s.tokenStore.GetToken(ctx, token)
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

	// Refresh the provider token — coordinated through the per-user
	// single-flight lock in the unified layout, direct in the legacy layout.
	newProviderToken, err := s.refreshProviderDuringValidation(ctx, accessToken, storedToken)
	if err != nil {
		// Refresh failed - log warning but continue with validation (graceful degradation)
		s.Logger.Warn("Proactive token refresh failed, falling back to validation",
			logKeyError, err,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"time_until_expiry", timeUntilExpiry)

		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventProactiveRefreshFailed,
			Details: map[string]any{
				logKeyError:         err.Error(),
				"time_until_expiry": timeUntilExpiry.String(),
				"fallback":          "validation",
			},
		})
		return
	}

	s.fireTokenRefreshHandler(ctx, accessToken, newProviderToken)

	s.Logger.Debug("Token proactively refreshed",
		"old_expiry", storedToken.Expiry,
		"new_expiry", newProviderToken.Expiry,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventTokenProactivelyRefreshed,
		Details: map[string]any{
			"old_expiry": storedToken.Expiry,
			"new_expiry": newProviderToken.Expiry,
			"threshold":  refreshThreshold.String(),
		},
	})
}

// ValidateToken validates an access token across every accepted bearer
// format. Validation is format-agnostic by design — operators of one
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
//  2. Trusted-issuer JWT (when WithTrustedIssuers is configured AND the
//     bearer's iss matches a configured entry). Signature verified via the
//     entry's JWKS; aud checked against the entry's AllowedAudiences
//     (defaulting to Config.GetResourceIdentifier when empty); typ header
//     checked against the entry's AcceptedTypHeaders (default RFC 9068 §4
//     at+jwt). A non-matching iss returns ErrIssuerNotTrusted
//     and falls through to subsequent branches; a typ failure on a token
//     whose aud is in Config.TrustedAudiences falls through to the
//     forwarded-ID-token branch (it is an ID token, not an access token);
//     any other validation failure is a hard rejection.
//  3. Forwarded ID token (when the bearer is a JWT whose aud matches
//     Config.TrustedAudiences). Verified via the upstream provider's JWKS
//     for SSO token forwarding.
//  4. Opaque token (TokenStore lookup, then provider userinfo). The
//     catch-all for non-JWT bearers.
//
// Steps 1, 2, and 3 are opt-in (AccessTokenFormatJWT, WithTrustedIssuers,
// TrustedAudiences respectively); step 4 is always available. Rate
// limiting should be done at the HTTP layer with IP address, not here
// with the token.
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

	// PRIORITY 2: Trusted-issuer JWT (WithTrustedIssuers).
	if userInfo, err := s.validateTrustedIssuerJWT(ctx, accessToken); userInfo != nil || err != nil {
		return userInfo, err
	}

	// PRIORITY 3: Forwarded ID token (JWT) from a trusted upstream service.
	// Must run BEFORE the opaque path, as ID tokens cannot be validated via
	// the upstream provider's userinfo endpoint.
	if len(s.Config.TrustedAudiences) > 0 && oidc.IsJWT(accessToken) {
		userInfo, err := s.validateForwardedIDToken(ctx, accessToken)
		if err != nil {
			// A non-nil error here means the token carried a trusted audience
			// (it was meant to be an SSO-forwarded ID token) but validation
			// then failed — e.g. a JWKS fetch/TLS error or a bad signature.
			// That is a real misconfiguration, not the benign "not an SSO
			// token" case (which returns nil, nil and is silent), so surface
			// it at WARN. No token material is logged (only an 8-char suffix
			// for correlation).
			s.Logger.Warn("Forwarded ID token validation failed, falling back to userinfo",
				logKeyError, err.Error(),
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
		} else if userInfo != nil {
			s.Logger.Debug("Forwarded ID token validated via JWKS",
				"user_id", userInfo.ID,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
			return userInfo, nil
		}
	}

	// PRIORITY 4: Opaque token (TokenStore + upstream provider userinfo).
	storedToken, err := s.validateStoredToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Determine which token to use for provider validation
	tokenForProviderValidation := s.selectTokenForProviderValidation(accessToken, storedToken)

	// Validate with provider (userinfo endpoint)
	userInfo, err := s.provider.ValidateToken(ctx, tokenForProviderValidation)
	if err != nil {
		s.Auditor.LogAuthFailure(ctx, "", "", "", err.Error())
		return nil, err
	}

	// Set token source to OAuth since this is the normal OAuth flow
	// (the server issued the token and the provider's ID token is stored)
	userInfo.TokenSource = providers.TokenSourceOAuth

	// Store user info
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, providerUserInfoToStorage(userInfo)); err != nil {
		s.Logger.Warn("Failed to save user info", logKeyError, err)
	}

	return userInfo, nil
}

// validateStoredToken checks if a stored token exists and validates it locally.
// Returns the stored token (may be nil if not found) or an error if validation fails.
func (s *Server) validateStoredToken(ctx context.Context, accessToken string) (*oauth2.Token, error) {
	storedToken, err := s.resolveProviderToken(ctx, accessToken)
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

			s.Auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")

			return nil, fmt.Errorf("access token expired (local validation)")
		}

		// Refresh the expired provider token — coordinated through the
		// per-user single-flight lock (unified layout, cross-pod) or the
		// per-access-token singleflight (legacy layout). Either way at most
		// one refresh reaches the provider; the rest adopt its result.
		newProviderToken, err := s.refreshProviderDuringValidation(ctx, accessToken, storedToken)
		if err != nil {
			s.Logger.Debug("Token expired locally and refresh failed",
				"expiry", storedToken.Expiry,
				"grace_period_seconds", s.Config.ClockSkewGracePeriod,
				"refresh_error", err,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))

			s.Auditor.LogAuthFailure(ctx, "", "", "", "token_expired_locally")

			return nil, fmt.Errorf("access token expired (local validation, refresh failed: %w)", err)
		}

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
			paramAudience, metadata.Audience,
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

// hasTrustedAudience reports whether any of the token's audiences is in the
// TrustedAudiences list.
func (s *Server) hasTrustedAudience(audiences []string) bool {
	for _, aud := range audiences {
		if s.isTrustedAudience(aud) {
			return true
		}
	}
	return false
}

// validateTrustedIssuerJWT runs the WithTrustedIssuers Bearer branch of
// ValidateToken. Returns (nil, nil) when no validator is configured or the
// token's iss is not a configured peer (caller falls through); (userInfo,
// nil) on success; (nil, err) on any other validation failure (caller
// returns the error). The typ header enforcement (per-issuer
// AcceptedTypHeaders, default RFC 9068 at+jwt) runs only after the JWS
// signature has been verified by Validate.
//
// A token that fails only the typ check but carries an audience listed in
// Config.TrustedAudiences is not an access token at all — it is an ID
// token forwarded by a trusted upstream service (SSO token forwarding).
// Hard-rejecting it here would shadow the forwarded-ID-token branch
// whenever the upstream issuer is also configured as a trusted issuer
// (e.g. for RFC 8693 subject-token validation). Such tokens fall through
// instead; the forwarded-ID-token branch re-validates them independently
// against the server's own provider JWKS.
func (s *Server) validateTrustedIssuerJWT(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	if s.trustedIssuerValidator == nil {
		return nil, nil
	}
	identity, err := s.trustedIssuerValidator.Validate(ctx, accessToken, []string{s.Config.GetResourceIdentifier()})
	if errors.Is(err, ErrIssuerNotTrusted) {
		return nil, nil
	}
	if err != nil {
		s.Auditor.LogAuthFailure(ctx, "", "", "", "trusted_issuer_jwt_invalid")
		return nil, fmt.Errorf("trusted issuer JWT validation failed: %w", err)
	}
	if err := checkTypeHeader(accessToken, s.trustedIssuerValidator.BearerTypHeaders(identity.Issuer)); err != nil {
		if identity.Claims != nil && s.hasTrustedAudience(identity.Claims.Audience) {
			s.Logger.Debug("Trusted-issuer JWT failed typ check but carries a trusted audience, deferring to forwarded ID token validation",
				"issuer", identity.Issuer,
				"token_suffix", helpers.TokenSuffix(accessToken, 8))
			return nil, nil
		}
		s.Auditor.LogAuthFailure(ctx, identity.Subject, "", "", "trusted_issuer_typ_invalid")
		return nil, fmt.Errorf("trusted issuer JWT: %w", err)
	}
	userInfo := s.idTokenClaimsToUserInfo(identity.Claims)
	userInfo.Issuer = identity.Issuer
	userInfo.TokenSource = providers.TokenSourceTrustedIssuer
	s.logTrustedIssuerJWTAccepted(ctx, accessToken, identity.Issuer, userInfo)
	return userInfo, nil
}

// logTrustedIssuerJWTAccepted records a successful Bearer validation against
// a WithTrustedIssuers entry.
func (s *Server) logTrustedIssuerJWTAccepted(ctx context.Context, accessToken, issuer string, userInfo *providers.UserInfo) {
	s.Logger.Debug("Trusted-issuer JWT accepted",
		"issuer", issuer,
		"user_id", userInfo.ID,
		claimEmail, userInfo.Email,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))
	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventForwardedIDTokenAccepted,
		UserID: userInfo.ID,
		Details: map[string]any{
			logKeyValidationMethod: "trusted_issuer_jwks",
			"trusted_issuer":       issuer,
			claimEmail:             userInfo.Email,
		},
	})
}

// logCrossClientTokenAccepted logs when a token is accepted via TrustedAudiences.
// This audit event helps track SSO token usage patterns for security monitoring.
func (s *Server) logCrossClientTokenAccepted(ctx context.Context, accessToken string, metadata *storage.TokenMetadata) {
	s.Logger.Debug("Token accepted via TrustedAudiences (SSO token forwarding)",
		"token_audience", metadata.Audience,
		"user_id", metadata.UserID,
		paramClientID, metadata.ClientID,
		"token_suffix", helpers.TokenSuffix(accessToken, 8))

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

// logAudienceMismatch logs an audience mismatch security event.
func (s *Server) logAudienceMismatch(ctx context.Context, accessToken string, metadata *storage.TokenMetadata, expectedAudience string) {
	if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(metadata.UserID+":"+metadata.ClientID+":audience_mismatch") {
		s.Logger.Warn("Token audience mismatch - token not intended for this resource server",
			"token_audience", metadata.Audience,
			"server_identifier", expectedAudience,
			"token_suffix", helpers.TokenSuffix(accessToken, 8),
			"user_id", metadata.UserID,
			paramClientID, metadata.ClientID)
	}

	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventResourceMismatch,
		UserID:   metadata.UserID,
		ClientID: metadata.ClientID,
		Details: map[string]any{
			logKeySeverity:      severityCritical,
			"token_audience":    metadata.Audience,
			"server_identifier": expectedAudience,
			"attack_indicator":  "token_replay_to_wrong_resource_server",
		},
	})
	s.Auditor.LogAuthFailure(ctx, metadata.UserID, metadata.ClientID, "", "audience_mismatch")
}

// selectTokenForProviderValidation determines which token to use for provider validation.
func (s *Server) selectTokenForProviderValidation(accessToken string, storedToken *oauth2.Token) string {
	if storedToken != nil && storedToken.AccessToken != "" {
		return storedToken.AccessToken
	}
	return accessToken
}
