package server

import (
	"context"
	"fmt"

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
// 5. Fall back to userinfo endpoint if JWT validation fails

// validateAndParseForwardedIDToken validates a JWT ID token from a trusted upstream
// service and returns its verified claims. This is the shared core used by both the
// fallback-style validateForwardedIDToken (ValidateToken fast-path) and the direct
// AcceptForwardedIDToken entry point.
//
// Validation steps:
// 1. Parse the JWT claims without verification to check audience
// 2. Check if any audience matches TrustedAudiences
// 3. If matched, validate the JWT signature using the provider's JWKS
// 4. Return the verified claims
//
// Returns (nil, "", nil) if the token doesn't match any trusted audience — callers
// that want fallback semantics (the ValidateToken fast-path) treat this as "not for us."
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

	return idTokenClaims, matchedAudience, nil
}

// validateForwardedIDToken is the fallback-style wrapper used by the ValidateToken
// fast-path. It returns (nil, nil) when the token doesn't carry a trusted audience
// so the caller falls back to the normal userinfo flow.
func (s *Server) validateForwardedIDToken(ctx context.Context, tokenString string) (*providers.UserInfo, error) {
	claims, matchedAudience, err := s.validateAndParseForwardedIDToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, nil
	}

	userInfo := s.idTokenClaimsToUserInfo(claims)

	var validatedIssuer string
	if jwksProvider, ok := s.provider.(providers.JWKSProvider); ok {
		validatedIssuer = jwksProvider.IssuerURL()
	}
	s.logForwardedIDTokenAccepted(ctx, tokenString, matchedAudience, validatedIssuer, userInfo)

	return userInfo, nil
}

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
		// When AllowPrivateIPJWKS is set, NewJWKSClientWithOptions builds the
		// permissive client via NewPrivateIPAllowedHTTPClient, which keeps the
		// cross-host redirect guard and tuned timeouts. An internal-CA Dex
		// forwarding SSO ID tokens is trusted by passing the configured
		// JWKSRootCAs pool explicitly (nil = system pool).
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
// ActorIssuer/ActorSubject are populated from claims.Act when the token carries
// an RFC 8693 §4.4 delegation claim (mcp-oauth-issued OBO tokens only; ordinary
// SSO ID tokens never carry act).
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
func (s *Server) logForwardedIDTokenAccepted(ctx context.Context, tokenString, matchedAudience, validatedIssuer string, userInfo *providers.UserInfo) {
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
