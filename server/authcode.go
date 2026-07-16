package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
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
	return errInvalidGrant
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
	return errInvalidGrant
}

// validatePublicClientPKCE validates that public clients use PKCE
// Returns error if public client is not using PKCE and it's required
func (s *Server) validatePublicClientPKCE(ctx context.Context, client *storage.Client, authCode *storage.AuthorizationCode, _ string) error {
	if !client.IsPublic() || authCode.CodeChallenge != "" {
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
		return errInvalidGrant
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

// ValidateRedirectURIForAuthorization resolves the redirect URI to its
// canonical, registered form for the client. Callers redirecting /authorize
// protocol errors back to the client MUST use this return value as the
// redirect target — it provably originates from server-side storage, not from
// the request, satisfying RFC 6749 §3.1.2.4.
func (s *Server) ValidateRedirectURIForAuthorization(ctx context.Context, clientID, redirectURI string) (*url.URL, error) {
	client, err := s.getOrFetchClient(ctx, clientID)
	if err != nil {
		s.logAuthFailure(ctx, "", clientID, ErrorCodeInvalidClient)
		return nil, fmt.Errorf("%s: %w", ErrorCodeInvalidClient, err)
	}
	canonical, err := s.resolveRegisteredRedirectURI(client, redirectURI)
	if err != nil {
		s.logAuthFailure(ctx, "", clientID, ErrorCodeInvalidRedirectURI)
		return nil, fmt.Errorf("%s: %w", ErrorCodeInvalidRedirectURI, err)
	}
	parsed, err := url.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("%s: canonical redirect URI is not a valid URL: %w", ErrorCodeInvalidRedirectURI, err)
	}
	return parsed, nil
}

// StartAuthorizationFlow starts a new OAuth authorization flow.
// redirectURI must be a canonical, registered URI obtained from [ValidateRedirectURIForAuthorization].
// This function re-runs the registered-URI check as defense-in-depth but the canonical value is what
// is stored in the authorization state and used as the redirect target.
// clientState is the state parameter from the client (REQUIRED for CSRF protection).
// resource is the target resource server identifier per RFC 8707 (optional for backward compatibility).
// authOpts contains optional OIDC parameters (prompt, login_hint, id_token_hint) for upstream IdP forwarding.
func (s *Server) StartAuthorizationFlow(ctx context.Context, clientID string, redirectURI *url.URL, scope, resource, codeChallenge, codeChallengeMethod, clientState string, authOpts *providers.AuthorizationURLOptions) (string, error) {
	// CRITICAL SECURITY: Validate state parameter from client for CSRF protection
	if err := s.validateClientStateParameter(clientState); err != nil {
		s.logAuthFailure(ctx, "", clientID, "invalid_state_parameter")
		return "", fmt.Errorf("oauth security bcp violation: %w", err)
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

	redirectURIStr := redirectURI.String()

	// Validate redirect URI
	if err := s.validateRedirectURI(client, redirectURIStr); err != nil {
		s.logAuthFailure(ctx, "", clientID, ErrorCodeInvalidRedirectURI)
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	// SECURITY: Authorization-time redirect URI validation (TOCTOU protection)
	if err := s.ValidateRedirectURIAtAuthorizationTime(ctx, redirectURIStr); err != nil {
		s.logAuthFailure(ctx, "", clientID, "redirect_uri_security_violation")
		s.Logger.Warn("Redirect URI failed authorization-time security validation",
			"client_id", clientID, "redirect_uri", sanitizeURIForLogging(redirectURIStr), "error", err.Error())
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

	s.logAuthorizationFlowStarted(ctx, clientID, redirectURIStr, scope, codeChallengeMethod, resource, authOpts)

	// Save authorization state with both client and server PKCE parameters and resource binding
	// Use trackingState (which may be server-generated if client didn't provide state)
	authState := &storage.AuthorizationState{
		StateID:              trackingState,
		OriginalClientState:  clientState, // Empty if client didn't provide state
		ClientID:             clientID,
		RedirectURI:          redirectURIStr,
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

	if err := s.saveUserInfoAndToken(ctx, userInfo, providerToken); err != nil {
		return nil, "", fmt.Errorf("failed to persist provider token: %w", err)
	}

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

// saveUserInfoAndToken persists the provider token + UserInfo keyed by user
// subject ID (required) and email (best-effort). ID-keyed failures are fatal:
// they surface to the OAuth flow rather than producing a successful auth code
// against an empty token store, which would manifest as silently broken SSO.
// Email-keyed failures are audited and logged but do not fail the flow, since
// ID-keyed lookups remain functional.
//
// Provider tokens are stored with an extended expiry (ProviderTokenTTL) so
// SSO token forwarding outlives short upstream access-token lifetimes; the
// original RefreshToken is preserved on the persisted copy.
func providerUserInfoToStorage(u *providers.UserInfo) *storage.UserInfo {
	return &storage.UserInfo{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		GivenName:     u.GivenName,
		FamilyName:    u.FamilyName,
		Picture:       u.Picture,
		Locale:        u.Locale,
		Groups:        u.Groups,
	}
}

func (s *Server) saveUserInfoAndToken(ctx context.Context, userInfo *providers.UserInfo, providerToken *oauth2.Token) error {
	tokenForStorage := s.extendTokenExpiryForStorage(providerToken)

	if userInfo.ID == "" {
		s.auditProviderTokenStorageFailed(ctx, userInfo, "missing_subject", "ID-keyed storage skipped")
		return fmt.Errorf("UserInfo.ID is empty; provider did not supply a subject claim")
	}

	storedInfo := providerUserInfoToStorage(userInfo)

	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.ID, storedInfo); err != nil {
		s.auditProviderTokenStorageFailed(ctx, userInfo, "save_user_info_by_id", err.Error())
		return fmt.Errorf("save user info by id: %w", err)
	}
	if err := s.tokenStore.SaveToken(ctx, userInfo.ID, tokenForStorage); err != nil {
		s.auditProviderTokenStorageFailed(ctx, userInfo, "save_token_by_id", err.Error())
		return fmt.Errorf("save provider token by id: %w", err)
	}

	if userInfo.Email == "" {
		return nil
	}
	if err := s.tokenStore.SaveUserInfo(ctx, userInfo.Email, storedInfo); err != nil {
		s.Logger.Warn("Failed to save user info by email", "error", err)
		s.auditProviderTokenStorageFailed(ctx, userInfo, "save_user_info_by_email", err.Error())
	}
	if err := s.tokenStore.SaveToken(ctx, userInfo.Email, tokenForStorage); err != nil {
		s.Logger.Warn("Failed to save provider token by email", "error", err)
		s.auditProviderTokenStorageFailed(ctx, userInfo, "save_token_by_email", err.Error())
	}
	return nil
}

// auditProviderTokenStorageFailed emits the stable audit event and metric for
// each provider-token persistence failure path. The reason enum is the stable
// dimension dashboards split on.
func (s *Server) auditProviderTokenStorageFailed(ctx context.Context, userInfo *providers.UserInfo, reason, detail string) {
	if s.Instrumentation != nil {
		s.Instrumentation.Metrics().RecordProviderTokenStorageFailed(ctx, reason)
	}
	if s.Auditor == nil {
		return
	}
	userID := ""
	if userInfo != nil {
		userID = userInfo.ID
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventProviderTokenStorageFailed,
		UserID: userID,
		Details: map[string]any{
			"reason":   reason,
			"severity": "high",
			"detail":   detail,
		},
	})
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

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
// dpopJKT is the JWK thumbprint from the DPoP proof header; empty string for
// bearer-only clients. resource is optional per RFC 8707.
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, resource, codeVerifier, dpopJKT string) (*oauth2.Token, string, error) {
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

	tokenResponse, err := s.generateAndStoreTokens(ctx, authCode, clientID, familyID, dpopJKT)
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
		return errInvalidGrant
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
func (s *Server) generateAndStoreTokens(ctx context.Context, authCode *storage.AuthorizationCode, clientID, familyID, dpopJKT string) (*oauth2.Token, error) {
	now := time.Now()
	var providerExpiry time.Time
	if authCode.ProviderToken != nil {
		providerExpiry = authCode.ProviderToken.Expiry
	}
	expiry := s.capTokenExpiry(now, providerExpiry)
	refreshExpiry := s.refreshTokenExpiry(now)

	tokenScopes := helpers.SplitScopes(authCode.Scope)
	accessToken, err := s.issueAccessToken(ctx, accessTokenIssueParams{
		UserID:    authCode.UserID,
		ClientID:  clientID,
		Audience:  authCode.Audience,
		Scopes:    tokenScopes,
		ExpiresAt: expiry,
		FamilyID:  familyID,
		JKT:       dpopJKT,
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
	idToken := ExtractIDToken(authCode.ProviderToken)
	if idToken != "" {
		tokenResponse = tokenResponse.WithExtra(map[string]any{
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

	baseMetadata := storage.TokenMetadata{
		UserID:    authCode.UserID,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: expiry,
		Audience:  authCode.Audience,
		FamilyID:  familyID,
		Scopes:    tokenScopes,
		JKT:       dpopJKT,
	}
	s.saveTokenPairMetadata(ctx, accessToken, refreshToken, baseMetadata, refreshExpiry)
	if idToken != "" {
		s.saveIDTokenMetadata(ctx, idToken, baseMetadata)
	}

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
	JKT       string
}

// issueAccessToken builds AccessTokenClaims from the issuance context and
// delegates to the configured AccessTokenIssuer. Email/groups are looked up
// from the TokenStore in JWT mode only — opaque issuance ignores them so
// the lookup is skipped to avoid an unnecessary storage round-trip.
func (s *Server) issueAccessToken(ctx context.Context, p accessTokenIssueParams) (string, error) {
	// RFC 9068 §2.2 requires the aud claim in JWT access tokens. Clients
	// that omit the RFC 8707 resource parameter (e.g. generic OAuth
	// libraries that predate resource indicators) would otherwise receive
	// a token without audience binding, which downstream JWT validators
	// (such as gateways in front of the resource server) rightly reject.
	// Default to this server's own resource identifier — the only audience
	// such a token could legitimately be used for. This also applies on
	// refresh grants, so grants created before this default self-heal.
	audience := p.Audience
	if audience == "" {
		audience = s.Config.GetResourceIdentifier()
	}
	claims := AccessTokenClaims{
		Subject:   p.UserID,
		ClientID:  p.ClientID,
		Audience:  audience,
		Scopes:    p.Scopes,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: p.ExpiresAt,
		FamilyID:  p.FamilyID,
		JKT:       p.JKT,
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
	refreshTokenExpiry := s.refreshTokenExpiry(time.Now())

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
