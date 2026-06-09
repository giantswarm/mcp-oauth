package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
)

// GrantTypeTokenExchange is the grant_type value for RFC 8693 token exchange.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- RFC 8693 grant-type URN identifier, not a credential

// TokenExchangeResult holds the output of a successful token exchange.
type TokenExchangeResult struct {
	AccessToken     string
	ExpiresAt       time.Time
	Scope           string
	IssuedTokenType string
}

// ExchangeOptions carries optional identity claims to inject into the access
// token issued by ExchangeSubjectToken.
//
// String and slice fields are omitted from the JWT when empty. EmailVerified is
// emitted only when Email is also non-empty (consistent with AccessTokenClaims
// semantics). Extra is merged into the JWT body after the standard claims; RFC
// 7519 §4.1 registered claim names (iss, sub, aud, exp, nbf, iat, jti) are
// rejected — Issue returns an error if Extra contains any of them. OIDC profile
// claims set via struct fields (email, name, groups, email_verified) are not
// guarded and can be overridden by Extra.
type ExchangeOptions struct {
	Email string
	// EmailVerified indicates whether Email has been verified by the identity
	// source. Zero value is false and is emitted as email_verified: false
	// whenever Email is non-empty — set explicitly when verification is guaranteed.
	EmailVerified bool
	Name          string
	Groups        []string
	Extra         map[string]any
}

// ExchangeSubjectToken validates subjectToken using the registered SubjectTokenValidator
// for subjectTokenType, then issues a signed JWT access token. resource becomes the aud
// claim (required per RFC 8707). scope is intersected against the per-issuer AllowedScopes
// envelope from TrustedIssuer configuration. dpopJKT is the JWK thumbprint from a
// validated DPoP proof; when non-empty it is written into the cnf.jkt claim of the
// issued JWT per RFC 9449 §6.1. Pass empty string when no DPoP proof was presented.
//
// opts is an optional ExchangeOptions whose identity fields are emitted as
// standard JWT claims (email, email_verified, name, groups) and whose Extra
// map is merged verbatim into the JWT body. Omitting opts adds no identity
// claims. Only the first element is used when multiple are provided.
func (s *Server) ExchangeSubjectToken(
	ctx context.Context,
	subjectToken, subjectTokenType, resource, scope, dpopJKT string,
	opts ...ExchangeOptions,
) (*TokenExchangeResult, error) {
	if !s.Config.IsJWTAccessTokenFormat() {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: map[string]any{
				"reason":     "token_exchange_jwt_mode_required",
				"grant_type": GrantTypeTokenExchange,
			},
		})
		return nil, fmt.Errorf("token exchange requires JWT access token mode (set AccessTokenFormat=jwt)")
	}

	switch subjectTokenType {
	case SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT:
	default:
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: map[string]any{
				"reason":             "unsupported_subject_token_type",
				"grant_type":         GrantTypeTokenExchange,
				"subject_token_type": subjectTokenType,
			},
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: subjectTokenType}
	}

	v := s.SubjectValidatorFor(subjectTokenType)
	if v == nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: map[string]any{
				"reason":             "unsupported_subject_token_type",
				"grant_type":         GrantTypeTokenExchange,
				"subject_token_type": subjectTokenType,
			},
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: subjectTokenType}
	}

	identity, err := v.Validate(ctx, subjectToken, nil)
	if err != nil {
		s.Logger.Debug("token exchange: subject token validation failed",
			"subject_token_type", subjectTokenType, "error", err)
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: map[string]any{
				"reason":             "subject_token_validation_failed",
				"grant_type":         GrantTypeTokenExchange,
				"subject_token_type": subjectTokenType,
				"error":              err.Error(),
			},
		})
		return nil, fmt.Errorf("subject token validation: %w", err)
	}

	grantedScope := grantedExchangeScope(scope, identity.AllowedScopes)

	now := time.Now().UTC()
	ttl := time.Duration(s.Config.AccessTokenTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expiresAt := now.Add(ttl)

	var o ExchangeOptions
	if len(opts) > 0 {
		o = opts[0]
	}

	tokenStr, err := s.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:       identity.Subject,
		Audience:      resource,
		Scopes:        strings.Fields(grantedScope),
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
		JTI:           generateRandomToken(),
		Act:           &Actor{Iss: identity.Issuer, Sub: identity.Subject},
		JKT:           dpopJKT,
		Email:         o.Email,
		EmailVerified: o.EmailVerified,
		Name:          o.Name,
		Groups:        o.Groups,
		Extra:         o.Extra,
	})
	if err != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:   security.EventAuthFailure,
			UserID: identity.Subject,
			Details: map[string]any{
				"reason":             "access_token_issue_failed",
				"grant_type":         GrantTypeTokenExchange,
				"subject_token_type": subjectTokenType,
				"audience":           resource,
				"act_iss":            identity.Issuer,
				"error":              err.Error(),
			},
		})
		return nil, fmt.Errorf("failed to issue exchange token: %w", err)
	}

	s.Logger.Debug("token exchange: issued token",
		"sub", identity.Subject, "iss_act", identity.Issuer,
		"aud", resource, "scope", grantedScope, "exp", expiresAt)

	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventTokenIssued,
		UserID: identity.Subject,
		Details: map[string]any{
			"grant_type":         GrantTypeTokenExchange,
			"subject_token_type": subjectTokenType,
			"audience":           resource,
			"scope":              grantedScope,
			"act_iss":            identity.Issuer,
		},
	})

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
