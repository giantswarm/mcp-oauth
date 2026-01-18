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

// validateForwardedIDToken validates a JWT ID token from a trusted upstream service.
// This enables SSO token forwarding where an upstream MCP server forwards its ID token
// to downstream services for authentication.
//
// Validation steps:
// 1. Parse the JWT claims without verification to check audience
// 2. Check if any audience matches TrustedAudiences
// 3. If matched, validate the JWT signature using the provider's JWKS
// 4. Extract user info from the validated claims
//
// Returns (nil, nil) if the token doesn't match any trusted audience (fallback to normal flow)
// Returns (nil, error) if the token matches but validation fails
// Returns (userInfo, nil) if validation succeeds
func (s *Server) validateForwardedIDToken(ctx context.Context, tokenString string) (*providers.UserInfo, error) {
	// Parse claims without verification to check audience
	claims, err := oidc.ParseUnverifiedClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Check if any audience matches our trusted audiences
	tokenAudiences := oidc.GetAudienceFromClaims(claims)
	matchedAudience := s.findMatchingTrustedAudience(tokenAudiences)
	if matchedAudience == "" {
		// No match - this token is not for us, return nil to trigger fallback
		return nil, nil
	}

	s.Logger.Debug("JWT audience matches TrustedAudiences, validating via JWKS",
		"matched_audience", matchedAudience,
		"token_prefix", helpers.SafeTruncate(tokenString, 8))

	// Check if provider supports JWKS validation
	jwksProvider, ok := s.provider.(providers.JWKSProvider)
	if !ok {
		s.Logger.Warn("Provider does not support JWKS validation, cannot validate forwarded ID token",
			"provider", s.provider.Name())
		return nil, fmt.Errorf("provider %s does not support JWKS validation", s.provider.Name())
	}

	// Get JWKS URI from provider
	jwksURI, err := jwksProvider.JWKSURI(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS URI: %w", err)
	}

	// Get issuer URL from provider for additional validation
	// This adds defense-in-depth by ensuring the token was issued by the expected provider
	expectedIssuer := jwksProvider.IssuerURL()
	if expectedIssuer != "" {
		s.Logger.Debug("Validating JWT issuer against provider",
			"expected_issuer", expectedIssuer,
			"token_prefix", helpers.SafeTruncate(tokenString, 8))
	}

	// Validate the JWT signature using JWKS
	idTokenClaims, err := oidc.ValidateIDToken(
		ctx,
		tokenString,
		s.getJWKSClient(),
		jwksURI,
		expectedIssuer, // Validate issuer if provider specifies one
		s.Config.TrustedAudiences,
	)
	if err != nil {
		return nil, fmt.Errorf("ID token signature validation failed: %w", err)
	}

	// Defensive nil check - ValidateIDToken should never return (nil, nil)
	// but this guards against future changes
	if idTokenClaims == nil {
		return nil, fmt.Errorf("ID token validation returned nil claims")
	}

	// Extract user info from validated claims
	userInfo := s.idTokenClaimsToUserInfo(idTokenClaims)

	// Log the successful SSO token acceptance with issuer information
	s.logForwardedIDTokenAccepted(tokenString, matchedAudience, expectedIssuer, userInfo)

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
		s.jwksClient = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
			Logger:         s.Logger,
			AllowPrivateIP: s.Config.AllowPrivateIPJWKS,
		})
	})
	return s.jwksClient
}

// idTokenClaimsToUserInfo converts validated ID token claims to UserInfo.
func (s *Server) idTokenClaimsToUserInfo(claims *oidc.IDTokenClaims) *providers.UserInfo {
	return &providers.UserInfo{
		ID:            claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
		Locale:        claims.Locale,
		Groups:        claims.Groups,
	}
}

// logForwardedIDTokenAccepted logs a security event when a forwarded ID token is accepted.
func (s *Server) logForwardedIDTokenAccepted(tokenString, matchedAudience, validatedIssuer string, userInfo *providers.UserInfo) {
	s.Logger.Info("Forwarded ID token accepted via TrustedAudiences (SSO)",
		"user_id", userInfo.ID,
		"email", userInfo.Email,
		"matched_audience", matchedAudience,
		"issuer_validated", validatedIssuer != "",
		"token_prefix", helpers.SafeTruncate(tokenString, 8))

	if s.Auditor != nil {
		details := map[string]any{
			"matched_audience":    matchedAudience,
			"email":               userInfo.Email,
			"validation_method":   "jwks",
			"sso_token_forwarded": true,
			"issuer_validated":    validatedIssuer != "",
		}
		// Include validated issuer in audit log for security forensics
		if validatedIssuer != "" {
			details["validated_issuer"] = validatedIssuer
		}
		s.Auditor.LogEvent(security.Event{
			Type:    security.EventForwardedIDTokenAccepted,
			UserID:  userInfo.ID,
			Details: details,
		})
	}
}
