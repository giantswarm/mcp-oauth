package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

// SSO Token Forwarding
//
// This file contains the logic for SSO (Single Sign-On) token forwarding, where
// ID tokens from trusted upstream MCP servers are validated via JWKS signature
// verification instead of calling the userinfo endpoint.
//
// Flow:
// 1. When TrustedAudiences is configured and token looks like a JWT
// 2. Parse claims without verification to check audience
// 3. If audience matches, validate JWT signature using provider's JWKS
// 4. Extract user info from validated claims
// 5. Return the verified identity or a validation error

// validateAndParseForwardedIDToken verifies a JWT ID token whose audience
// matches Config.TrustedAudiences and returns its claims.
//
// Validation steps:
// 1. Parse the JWT claims without verification to check audience
// 2. Check if any audience matches TrustedAudiences
// 3. If matched, validate the JWT signature using the provider's JWKS
// 4. Return the verified claims
//
// Returns (nil, "", nil) if the token doesn't match any trusted audience.
// Returns (nil, "", error) if the token matches but validation fails.
// Returns (claims, matchedAudience, nil) if validation succeeds.
func (s *Server) validateAndParseForwardedIDToken(ctx context.Context, tokenString string) (*oidc.IDTokenClaims, string, error) {
	claims, err := oidc.ParseUnverifiedClaims(tokenString)
	if err != nil {
		// Wrap with errForwardedTokenParseFailed so AcceptForwardedIDToken's
		// classifier can distinguish parse errors from later validation
		// failures via errors.Is, without a second parse pass.
		return nil, "", fmt.Errorf("%w: %w", errForwardedTokenParseFailed, err)
	}

	tokenAudiences := oidc.GetAudienceFromClaims(claims)
	matchedAudience := s.findMatchingTrustedAudience(tokenAudiences)
	if matchedAudience == "" {
		return nil, "", nil
	}

	s.Logger.Debug("JWT audience matches TrustedAudiences, validating via JWKS",
		"matched_audience", matchedAudience,
		"token_suffix", helpers.TokenSuffix(tokenString, 8))

	jwksProvider, ok := s.provider.(providers.JWKSProvider)
	if !ok {
		s.Logger.Warn("Provider does not support JWKS validation, cannot validate forwarded ID token",
			logKeyProvider, s.provider.Name())
		return nil, "", fmt.Errorf("provider %s does not support JWKS validation", s.provider.Name())
	}

	jwksURI, err := jwksProvider.JWKSURI(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get JWKS URI: %w", err)
	}

	expectedIssuer := jwksProvider.IssuerURL()
	if expectedIssuer != "" {
		s.Logger.Debug("Validating JWT issuer against provider",
			"expected_issuer", expectedIssuer,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
	}

	idTokenClaims, err := oidc.ValidateIDToken(
		ctx,
		tokenString,
		s.getJWKSClient(),
		jwksURI,
		expectedIssuer,
		s.Config.TrustedAudiences,
	)
	if err != nil {
		return nil, "", fmt.Errorf("ID token signature validation failed: %w", err)
	}

	if idTokenClaims == nil {
		return nil, "", fmt.Errorf("ID token validation returned nil claims")
	}

	// Identity acceptance enforces the matched issuer's actor policy.
	if s.trustedIssuerValidator != nil {
		if err := checkActor(s.trustedIssuerValidator.actorPolicy(idTokenClaims.Issuer), idTokenClaims.Act); err != nil {
			return nil, "", err
		}
	}

	return idTokenClaims, matchedAudience, nil
}

// validateForwardedIDTokenBearer accepts an upstream ID token as a
// ValidateToken bearer. Returns (nil, nil) when the token does not parse,
// names no TrustedAudiences entry, or carries act or cnf, so the caller falls
// through: a delegated token is left to the trusted issuer's actor policy,
// and a sender-constrained one to the branches whose DPoP binding the handler
// middleware enforces.
func (s *Server) validateForwardedIDTokenBearer(ctx context.Context, bearer string) (*providers.UserInfo, error) {
	rawClaims, err := oidc.ParseUnverifiedClaims(bearer)
	if err != nil {
		return nil, nil
	}
	if _, delegated := rawClaims["act"]; delegated {
		return nil, nil
	}
	if _, bound := rawClaims["cnf"]; bound {
		return nil, nil
	}

	providerName := s.provider.Name()
	expectedIssuer := providers.IssuerOf(s.provider)
	claims, matchedAudience, err := s.validateAndParseForwardedIDToken(ctx, bearer)
	switch {
	case err == nil && claims == nil, errors.Is(err, errForwardedTokenParseFailed):
		return nil, nil
	case err != nil && isTransientProviderError(err):
		return nil, s.providerUnavailable(ctx, "forwarded ID token validation", "", "", err)
	case err != nil:
		s.Auditor.LogAuthFailure(ctx, "", "", "", auditReasonForwardedIDTokenInvalid)
		s.Logger.Warn("Forwarded ID token refused",
			logKeyError, err.Error(),
			"token_suffix", helpers.TokenSuffix(bearer, 8))
		s.recordForwardedIDTokenAccepted(ctx, providerName, expectedIssuer, "", classifyForwardedTokenError(err))
		return nil, fmt.Errorf("forwarded ID token refused: %w", err)
	}

	userInfo := s.idTokenClaimsToUserInfo(claims)
	s.logForwardedIDTokenAccepted(ctx, bearer, s.deriveForwardedSessionID(bearer), matchedAudience, expectedIssuer, userInfo)
	s.recordForwardedIDTokenAccepted(ctx, providerName, claims.Issuer, matchedAudience, instrumentation.ForwardedIDTokenResultOK)
	return userInfo, nil
}

const auditReasonForwardedIDTokenInvalid = "forwarded_id_token_invalid"

// findMatchingTrustedAudience checks if any of the token's audiences match our trusted audiences.
// Uses the shared helpers.FindMatchingAudience for consistent URL normalization
// and constant-time comparison across the codebase.
// Returns the matched audience or empty string if no match.
func (s *Server) findMatchingTrustedAudience(tokenAudiences []string) string {
	return helpers.FindMatchingAudience(tokenAudiences, s.Config.TrustedAudiences)
}

// getJWKSClient returns or creates a JWKS client for JWT validation.
// Thread-safe: uses sync.Once to ensure initialization happens only once.
//
// The client respects the AllowPrivateIPJWKS configuration option:
//   - When false (default): SSRF protection is enabled, blocking private IPs
//   - When true: Private IPs are allowed for internal IdP deployments
func (s *Server) getJWKSClient() *oidc.JWKSClient {
	s.jwksClientOnce.Do(func() {
		// AllowPrivateIPJWKS selects the dial posture; JWKSRootCAs pins the
		// trust anchor and applies on either one (nil = system pool). An
		// internal-CA Dex is trusted without relaxing the SSRF guard.
		s.jwksClient = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
			Logger:         s.Logger,
			AllowPrivateIP: s.Config.AllowPrivateIPJWKS,
			RootCAs:        s.Config.JWKSRootCAs,
		})
	})
	return s.jwksClient
}

// idTokenClaimsToUserInfo converts validated ID token claims to UserInfo.
// Sets TokenSource to TokenSourceSSO since this is called for SSO-forwarded tokens.
// ActorIssuer, ActorSubject and ActorChain are populated from claims.Act when
// the token carries an RFC 8693 §4.1 act claim.
func (s *Server) idTokenClaimsToUserInfo(claims *oidc.IDTokenClaims) *providers.UserInfo {
	info := &providers.UserInfo{
		ID:            claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
		Locale:        claims.Locale,
		Groups:        claims.Groups,
		Scopes:        claims.Scope,
		TokenSource:   providers.TokenSourceSSO,
	}
	if claims.Act != nil {
		info.ActorIssuer = claims.Act.Issuer
		info.ActorSubject = claims.Act.Subject
		info.ActorChain = claims.Act.Chain()
	}
	return info
}

// logForwardedIDTokenAccepted logs a security event when a forwarded ID token is accepted.
func (s *Server) logForwardedIDTokenAccepted(ctx context.Context, tokenString, sessionID, matchedAudience, validatedIssuer string, userInfo *providers.UserInfo) {
	s.Logger.Debug("Forwarded ID token accepted via TrustedAudiences (SSO)",
		"user_id", userInfo.ID,
		claimEmail, userInfo.Email,
		"matched_audience", matchedAudience,
		"issuer_validated", validatedIssuer != "",
		"token_suffix", helpers.TokenSuffix(tokenString, 8))

	details := map[string]any{
		"matched_audience":     matchedAudience,
		claimEmail:             userInfo.Email,
		logKeyValidationMethod: "jwks",
		"sso_token_forwarded":  true,
		"issuer_validated":     validatedIssuer != "",
		logKeySessionID:        sessionID,
	}
	if validatedIssuer != "" {
		details["validated_issuer"] = validatedIssuer
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:    security.EventForwardedIDTokenAccepted,
		UserID:  userInfo.ID,
		Details: details,
	})
}
