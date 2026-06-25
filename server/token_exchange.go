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
// actorToken and actorTokenType are RFC 8693 §4.4 delegation parameters. When
// actorToken is non-empty it is validated against the server's trusted issuers
// and the resulting actor identity is written as the act claim of the issued
// JWT (act.sub = agent SA, act.iss = agent issuer). The ActorDelegationPolicy
// must explicitly allow the (actor, subject) pair; nil/empty policy denies all
// delegated exchanges. Pass empty strings for both when no delegation is
// required — the issued token will carry no act claim.
//
// opts is an optional ExchangeOptions whose identity fields are emitted as
// standard JWT claims (email, email_verified, name, groups) and whose Extra
// map is merged verbatim into the JWT body. Omitting opts adds no identity
// claims. Only the first element is used when multiple are provided.
func (s *Server) ExchangeSubjectToken(
	ctx context.Context,
	subjectToken, subjectTokenType, actorToken, actorTokenType, resource, scope, dpopJKT string,
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

	identity, err := s.validateExchangeSubjectToken(ctx, subjectToken, subjectTokenType, nil, nil)
	if err != nil {
		return nil, err
	}

	var act *Actor
	if actorToken != "" {
		actor, err := s.validateExchangeActorToken(ctx, actorToken, actorTokenType, nil)
		if err != nil {
			return nil, err
		}
		// When actor resolves to the same identity as subject, treat as pure M2M —
		// strip the actor so the minted token carries no act claim and delegation
		// checks are skipped. This lets a static SA token be sent as X-Actor-Token
		// without requiring an explicit SA→SA delegation rule.
		if actor.Issuer != identity.Issuer || actor.Subject != identity.Subject {
			if !s.actorDelegationAllowed(actor.Issuer, actor.Subject, identity.Issuer, identity.Subject) {
				s.Auditor.LogEvent(ctx, security.Event{
					Type:   security.EventAuthFailure,
					UserID: identity.Subject,
					Details: map[string]any{
						"reason":     "actor_delegation_not_authorized",
						"grant_type": GrantTypeTokenExchange,
						"actor_sub":  actor.Subject,
						"actor_iss":  actor.Issuer,
						"sub":        identity.Subject,
					},
				})
				return nil, fmt.Errorf("actor %q is not authorized to act for subject %q", actor.Subject, identity.Subject)
			}
			act = &Actor{Iss: actor.Issuer, Sub: actor.Subject}
		}
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
	// Default the identity claims from the validated subject when the caller did
	// not supply them, so a delegated or self-mint preserves the subject's email,
	// name and groups. Downstream resource servers rely on these (email->org
	// mapping, group-based RBAC); without this they receive an identity-stripped
	// token. An explicit ExchangeOptions value still takes precedence.
	if identity.Claims != nil {
		if o.Email == "" {
			o.Email = identity.Claims.Email
			o.EmailVerified = identity.Claims.EmailVerified
		}
		if o.Name == "" {
			o.Name = identity.Claims.Name
		}
		if len(o.Groups) == 0 {
			o.Groups = identity.Claims.Groups
		}
	}

	auditDetails := map[string]any{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token_type": subjectTokenType,
		"audience":           resource,
		"scope":              grantedScope,
	}
	if act != nil {
		auditDetails["actor_iss"] = act.Iss
		auditDetails["actor_sub"] = act.Sub
	}

	tokenStr, err := s.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:       identity.Subject,
		Audience:      resource,
		Scopes:        strings.Fields(grantedScope),
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
		JTI:           generateRandomToken(),
		Act:           act,
		JKT:           dpopJKT,
		Email:         o.Email,
		EmailVerified: o.EmailVerified,
		Name:          o.Name,
		Groups:        o.Groups,
		Extra:         o.Extra,
	})
	if err != nil {
		auditDetails["reason"] = "access_token_issue_failed"
		auditDetails["error"] = err.Error()
		s.Auditor.LogEvent(ctx, security.Event{
			Type:    security.EventAuthFailure,
			UserID:  identity.Subject,
			Details: auditDetails,
		})
		return nil, fmt.Errorf("failed to issue exchange token: %w", err)
	}

	s.Logger.Debug("token exchange: issued token",
		"sub", identity.Subject, "aud", resource, "scope", grantedScope, "exp", expiresAt,
		"delegated", act != nil)

	s.Auditor.LogEvent(ctx, security.Event{
		Type:    security.EventTokenIssued,
		UserID:  identity.Subject,
		Details: auditDetails,
	})

	return &TokenExchangeResult{
		AccessToken:     tokenStr,
		ExpiresAt:       expiresAt,
		Scope:           grantedScope,
		IssuedTokenType: SubjectTokenTypeAccessToken,
	}, nil
}

// validateExchangeSubjectToken validates the RFC 8693 subject token and returns
// the verified identity. Audit failure events use the "subject" role — reasons
// are subject_token_validation_failed and unsupported_subject_token_type.
// defaultAudiences is forwarded to Validate and applies only when the matched
// issuer entry has no AllowedAudiences. Pass nil on the brokered and local
// exchange paths (subject token is not broker-bound); pass []string{s.Config.Issuer}
// on the workload-authenticated path when no actor_token is present, so the
// caller-authenticating token is bound to this broker's issuer and cannot be
// replayed from a different audience context.
// extra is merged into every failure audit event; pass brokered flow context
// (exchange, client_id, audience, session_id) from BrokerExchangeSubjectToken.
func (s *Server) validateExchangeSubjectToken(ctx context.Context, subjectToken, subjectTokenType string, defaultAudiences []string, extra map[string]any) (*SubjectIdentity, error) {
	return s.validateExchangeToken(ctx, subjectToken, subjectTokenType, "subject", defaultAudiences, extra)
}

// validateExchangeActorToken validates the RFC 8693 actor token and returns
// the verified actor identity. Audit failure events use the "actor" role —
// reasons are actor_token_validation_failed and unsupported_actor_token_type.
// The broker's own issuer is passed as the default audience so actor tokens
// from issuers with no AllowedAudiences configured are still bound to this
// broker and cannot be replayed from a different audience context.
// extra is merged into every failure audit event; pass brokered flow context
// (exchange, client_id, audience, session_id) from BrokerExchangeSubjectToken.
func (s *Server) validateExchangeActorToken(ctx context.Context, actorToken, actorTokenType string, extra map[string]any) (*SubjectIdentity, error) {
	return s.validateExchangeToken(ctx, actorToken, actorTokenType, "actor", []string{s.Config.Issuer}, extra)
}

// validateExchangeToken routes token to the SubjectTokenValidator registered
// for tokenType and returns the verified identity. role is "subject" or "actor";
// it drives audit reason strings and detail keys so subject and actor failures
// produce distinct, unambiguous audit events. defaultAudiences is forwarded to
// Validate and applies only when the matched issuer entry has no AllowedAudiences.
// extra is merged into every failure audit event; use it to inject flow-level context
// (exchange, client_id, audience, session_id) so a single event carries both the
// validation detail and the brokered-flow correlation fields.
func (s *Server) validateExchangeToken(ctx context.Context, token, tokenType, role string, defaultAudiences []string, extra map[string]any) (*SubjectIdentity, error) {
	typeKey := role + "_token_type"
	unsupportedReason := "unsupported_" + role + "_token_type"
	validationFailedReason := role + "_token_validation_failed"

	auditDetails := func(base map[string]any) map[string]any {
		for k, v := range extra {
			base[k] = v
		}
		return base
	}

	switch tokenType {
	case SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT:
	default:
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     unsupportedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      tokenType,
			}),
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: tokenType, role: role}
	}

	v := s.SubjectValidatorFor(tokenType)
	if v == nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     unsupportedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      tokenType,
			}),
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: tokenType, role: role}
	}

	identity, err := v.Validate(ctx, token, defaultAudiences)
	if err != nil {
		s.Logger.Debug("token exchange: "+role+" token validation failed",
			typeKey, tokenType, "error", err)
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     validationFailedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      tokenType,
				"error":      err.Error(),
			}),
		})
		return nil, fmt.Errorf("%s token validation: %w", role, err)
	}

	return identity, nil
}

// TokenExchangeUnsupportedTypeError is returned when no validator is registered
// for the requested token type. Role is "subject" or "actor".
type TokenExchangeUnsupportedTypeError struct {
	tokenType string
	role      string
}

func (e *TokenExchangeUnsupportedTypeError) Error() string {
	return fmt.Sprintf("no validator registered for %s_token_type %q", e.role, e.tokenType)
}

// TokenType returns the unrecognised token-type URN value.
func (e *TokenExchangeUnsupportedTypeError) TokenType() string {
	return e.tokenType
}

// Role returns "subject" or "actor" identifying which token in the request
// was of an unsupported type.
func (e *TokenExchangeUnsupportedTypeError) Role() string {
	return e.role
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
