package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// GrantTypeTokenExchange is the grant_type value for RFC 8693 token exchange.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenExchangeResult holds the output of a successful token exchange.
type TokenExchangeResult struct {
	AccessToken     string
	ExpiresAt       time.Time
	Scope           string
	IssuedTokenType string
}

// ExchangeSubjectToken validates subjectToken using the registered SubjectTokenValidator
// for subjectTokenType, then issues a signed JWT access token. resource becomes the aud
// claim (required per RFC 8707). scope is intersected against the per-issuer AllowedScopes
// envelope from TrustedIssuer configuration. dpopJKT is the JWK thumbprint from a
// validated DPoP proof; when non-empty it is written into the cnf.jkt claim of the
// issued JWT per RFC 9449 §6.1. Pass empty string when no DPoP proof was presented.
func (s *Server) ExchangeSubjectToken(
	ctx context.Context,
	subjectToken, subjectTokenType, resource, scope, dpopJKT string,
) (*TokenExchangeResult, error) {
	if !s.Config.IsJWTAccessTokenFormat() {
		return nil, fmt.Errorf("token exchange requires JWT access token mode (set AccessTokenFormat=jwt)")
	}

	switch subjectTokenType {
	case SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT:
	default:
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: subjectTokenType}
	}

	v := s.SubjectValidatorFor(subjectTokenType)
	if v == nil {
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: subjectTokenType}
	}

	identity, err := v.Validate(ctx, subjectToken, nil)
	if err != nil {
		s.Logger.Debug("token exchange: subject token validation failed",
			"subject_token_type", subjectTokenType, "error", err)
		return nil, fmt.Errorf("subject token validation: %w", err)
	}

	grantedScope := grantedExchangeScope(scope, identity.AllowedScopes)

	now := time.Now().UTC()
	ttl := time.Duration(s.Config.AccessTokenTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expiresAt := now.Add(ttl)

	tokenStr, err := s.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:   identity.Subject,
		Audience:  resource,
		Scopes:    strings.Fields(grantedScope),
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		JTI:       generateRandomToken(),
		Act:       &Actor{Iss: identity.Issuer, Sub: identity.Subject},
		JKT:       dpopJKT,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue exchange token: %w", err)
	}

	s.Logger.Debug("token exchange: issued token",
		"sub", identity.Subject, "iss_act", identity.Issuer,
		"aud", resource, "scope", grantedScope, "exp", expiresAt)

	return &TokenExchangeResult{
		AccessToken:     tokenStr,
		ExpiresAt:       expiresAt,
		Scope:           grantedScope,
		IssuedTokenType: SubjectTokenTypeAccessToken,
	}, nil
}

// TokenExchangeUnsupportedTypeError is returned when no validator is registered
// for the requested subject_token_type.
type TokenExchangeUnsupportedTypeError struct {
	tokenType string
}

func (e *TokenExchangeUnsupportedTypeError) Error() string {
	return fmt.Sprintf("no validator registered for subject_token_type %q", e.tokenType)
}

// TokenType returns the unrecognised subject_token_type value.
func (e *TokenExchangeUnsupportedTypeError) TokenType() string {
	return e.tokenType
}

// grantedExchangeScope computes the scope for a token-exchange response.
// When allowedScopes is nil there is no per-issuer restriction.
// When scope is empty all allowed scopes are granted.
// Otherwise the result is the intersection.
func grantedExchangeScope(requestedScope string, allowedScopes []string) string {
	if len(allowedScopes) == 0 {
		return requestedScope
	}
	if requestedScope == "" {
		return strings.Join(allowedScopes, " ")
	}
	granted := intersectScopes(strings.Fields(requestedScope), allowedScopes)
	return strings.Join(granted, " ")
}
