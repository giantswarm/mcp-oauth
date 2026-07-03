package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

// GrantTypeTokenExchange is the grant_type value for RFC 8693 token exchange.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- RFC 8693 grant-type URN identifier, not a credential

// ErrSelfRenewalDenied is returned by SelfIssuedExchange when a token this server
// issued is re-presented as the subject with no new actor. That is a bare
// renewal: it refreshes the TTL without extending the delegation chain, which
// would let a held token renew itself indefinitely. Re-exchange a self-issued
// token only to add an actor (a delegation hop, bounded by maxActorChainDepth).
var ErrSelfRenewalDenied = errors.New("self-issued token cannot be re-exchanged without an actor")

// ErrUnverifiedSubjectEmail is returned by SelfIssuedExchange when the validated
// subject asserts an email claim without email_verified being true. The issued
// token would carry that email as an identity claim which downstream resource
// servers authorize on, so issuance fails closed. A subject with no email claim
// (e.g. a Kubernetes ServiceAccount token) is exempt.
var ErrUnverifiedSubjectEmail = errors.New("subject email_verified is not true; refusing to issue a token asserting an unproven email")

// ErrSubjectKeyMismatch is returned by SelfIssuedExchange when the subject token
// carries an RFC 9449 §6.1 cnf.jkt proof-of-possession binding but the request
// does not present a DPoP proof for that same key. A key-bound token may only be
// re-exchanged by the holder of its confirmation key, so a bearer who lacks the
// key cannot launder the binding into a token bound to a different key.
var ErrSubjectKeyMismatch = errors.New("subject token is key-bound; request must prove possession of its confirmation key")

// TokenExchangeResult holds the output of a successful token exchange.
type TokenExchangeResult struct {
	AccessToken     string
	ExpiresAt       time.Time
	Scope           string
	IssuedTokenType string
}

// ExchangeOptions carries optional identity claims to inject into the access
// token issued by SelfIssuedExchange.
//
// String and slice fields are omitted from the JWT when empty. EmailVerified is
// emitted only when Email is also non-empty (consistent with AccessTokenClaims
// semantics). Extra is merged into the JWT body after the standard claims; RFC
// 7519 §4.1 registered claim names (iss, sub, aud, exp, nbf, iat, jti) are
// rejected: Issue returns an error if Extra contains any of them. OIDC profile
// claims set via struct fields (email, name, groups, email_verified) are not
// guarded and can be overridden by Extra.
type ExchangeOptions struct {
	Email string
	// EmailVerified indicates whether Email has been verified by the identity
	// source. It is emitted as email_verified whenever Email is non-empty, so a
	// zero value emits false. SelfIssuedExchange defaults it from the subject only
	// together with Email (when Options.Email is empty): a caller that sets Email
	// explicitly but leaves EmailVerified false gets false even if the subject was
	// verified, so set it explicitly alongside an explicit Email.
	EmailVerified bool
	Name          string
	Groups        []string
	Extra         map[string]any
}

// TypedToken is an RFC 8693 token paired with its token-type URN.
type TypedToken struct {
	Token string
	Type  string
}

// SubjectExchange carries the RFC 8693 inputs common to both exchange methods:
// the subject token (and optional actor token) and the requested target.
type SubjectExchange struct {
	// Subject is the RFC 8693 subject_token being exchanged.
	Subject TypedToken
	// Actor is the RFC 8693 §4.4 actor_token. Its zero value means no delegation.
	Actor TypedToken
	// Resource is the RFC 8707 target URI. On SelfIssuedExchange it becomes the
	// issued token's aud, defaulting to the server's resource identifier when
	// empty. On BrokeredExchange it is forwarded to the host Exchanger.
	Resource string
	Scope    string
}

// SelfIssuedExchangeRequest is the input to SelfIssuedExchange, where this server
// signs the resulting token. DPoPJKT and Options apply only here because they
// shape a token this server issues; there is no Audience field, as self-issue sets
// aud via Resource (the RFC 8693 audience selects a broker target and is
// BrokeredExchange-only).
type SelfIssuedExchangeRequest struct {
	SubjectExchange
	// DPoPJKT is the JWK thumbprint from a validated DPoP proof (RFC 9449 §6.1),
	// written into the issued token's cnf.jkt claim. Empty when no proof was
	// presented.
	DPoPJKT string
	// Options carries identity claims to emit; an explicit value takes precedence
	// over the claims defaulted from the validated subject.
	Options ExchangeOptions
}

// SelfIssuedExchange validates the subject token (and optional actor token)
// against the registered SubjectTokenValidator, then issues a JWT access token
// this server signs. req.Resource becomes the aud claim, defaulting to the
// server's own resource identifier when empty. req.Scope is intersected against
// the per-issuer AllowedScopes envelope from TrustedIssuer configuration.
// req.DPoPJKT, when non-empty, is written into the cnf.jkt claim (RFC 9449 §6.1).
//
// When an actor token is present it is validated against the server's trusted
// issuers and written as the act claim; any act chain already on the subject
// token is nested beneath it so a multi-hop delegation chain is preserved (RFC
// 8693 §4.4). A chain deeper than the bound is rejected.
//
// req.Options identity fields are emitted as standard JWT claims; email,
// email_verified, name and groups default from the validated subject when Options
// leaves them unset, and an explicit Options value takes precedence.
func (s *Server) SelfIssuedExchange(ctx context.Context, req SelfIssuedExchangeRequest) (*TokenExchangeResult, error) {
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

	// Enforce the per-session issuance limiter here too, not only in HTTP
	// middleware: an in-process caller (e.g. an aggregator) reaches this method
	// directly, so a compromised session must not flood issuance regardless of
	// entry point. Deliberately ahead of subject validation and the self-renewal
	// check: a session flooding rejected requests (bad subjects, bare renewals)
	// must still be throttled, so those attempts count against the bucket.
	sessionID := s.deriveForwardedSessionID(req.Subject.Token)
	if s.exchangeSessionRateLimited(ctx, sessionID) {
		return nil, ErrExchangeRateLimited
	}

	identity, err := s.validateExchangeSubjectToken(ctx, req.Subject, nil, nil)
	if err != nil {
		return nil, err
	}

	if err := s.checkSubjectKeyBinding(ctx, identity, req.DPoPJKT, sessionID); err != nil {
		return nil, err
	}

	actor, err := s.resolveExchangeActor(ctx, req.Actor, identity, nil)
	if err != nil {
		return nil, err
	}
	prior := priorActorChain(identity)
	// An actor identical to the outermost actor already on the subject's chain
	// adds no delegation hop; drop it so a repeated re-attachment of the same
	// actor is treated as a bare renewal (denied below) rather than a fresh TTL.
	if actor != nil && prior != nil && actor.Issuer == prior.Iss && actor.Subject == prior.Sub {
		actor = nil
	}
	if err := s.checkSelfRenewal(ctx, identity, actor, sessionID); err != nil {
		return nil, err
	}
	// The email gate applies only when the subject's own email would be
	// defaulted into the issued token; an explicit req.Options.Email is the
	// in-process caller's assertion and takes precedence over subject claims
	// (see defaultExchangeOptions), so there is no subject email to prove.
	// The HTTP handler always passes zero Options, so the external exchange
	// surface is fully gated.
	if req.Options.Email == "" {
		if err := s.checkSubjectEmailVerified(ctx, identity, sessionID); err != nil {
			return nil, err
		}
	}
	act, err := buildActorChain(actor, prior)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	audience := req.Resource
	if audience == "" {
		audience = s.Config.GetResourceIdentifier()
	}
	if err := s.checkAllowedResource(ctx, audience, sessionID); err != nil {
		return nil, err
	}

	grantedScope := grantedExchangeScope(req.Scope, identity.AllowedScopes)

	now := time.Now().UTC()
	ttl := time.Duration(s.Config.AccessTokenTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expiresAt := now.Add(ttl)

	options := defaultExchangeOptions(req.Options, identity)

	jti := generateRandomToken()
	auditDetails := map[string]any{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token_type": req.Subject.Type,
		"audience":           audience,
		"scope":              grantedScope,
		"jti":                jti,
		"session_id":         sessionID,
	}
	if act != nil {
		auditDetails["actor_iss"] = act.Iss
		auditDetails["actor_sub"] = act.Sub
	}

	tokenStr, err := s.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:       identity.Subject,
		Audience:      audience,
		Scopes:        strings.Fields(grantedScope),
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
		JTI:           jti,
		Act:           act,
		JKT:           req.DPoPJKT,
		Email:         options.Email,
		EmailVerified: options.EmailVerified,
		Name:          options.Name,
		Groups:        options.Groups,
		Extra:         options.Extra,
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
		"sub", identity.Subject, "aud", audience, "scope", grantedScope, "exp", expiresAt,
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

// defaultExchangeOptions fills the identity claims from the validated subject
// when the caller left them unset; an explicit Options value takes precedence.
// email_verified is defaulted only together with email (see ExchangeOptions).
func defaultExchangeOptions(options ExchangeOptions, identity *SubjectIdentity) ExchangeOptions {
	if identity.Claims == nil {
		return options
	}
	if options.Email == "" {
		options.Email = identity.Claims.Email
		options.EmailVerified = identity.Claims.EmailVerified
	}
	if options.Name == "" {
		options.Name = identity.Claims.Name
	}
	if len(options.Groups) == 0 {
		options.Groups = identity.Claims.Groups
	}
	return options
}

// checkSelfRenewal denies re-exchanging a token this server issued (subject
// iss == our Issuer) when no new actor is added: a bare renewal that refreshes
// the TTL without extending the delegation chain, which would let a held token
// renew itself open-endedly. Re-exchange of a self-issued token is allowed only
// to add an actor (chain extension, bounded by maxActorChainDepth). Subjects from
// external issuers are unaffected. Returns nil when the exchange is allowed.
func (s *Server) checkSelfRenewal(ctx context.Context, identity, actor *SubjectIdentity, sessionID string) error {
	if actor != nil || identity.Issuer != s.Config.Issuer {
		return nil
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventAuthFailure,
		UserID: identity.Subject,
		Details: map[string]any{
			"reason":     "token_exchange_self_renewal_denied",
			"grant_type": GrantTypeTokenExchange,
			"session_id": sessionID,
		},
	})
	return ErrSelfRenewalDenied
}

// checkSubjectKeyBinding enforces that a key-bound subject token (RFC 9449 §6.1
// cnf.jkt) is only re-exchanged by the holder of its confirmation key: the
// request's DPoP proof thumbprint must equal the subject's cnf.jkt. A subject
// with no confirmation is unaffected. Returns nil when the exchange is allowed.
func (s *Server) checkSubjectKeyBinding(ctx context.Context, identity *SubjectIdentity, requestJKT, sessionID string) error {
	if identity.ConfirmationJKT == "" || identity.ConfirmationJKT == requestJKT {
		return nil
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventAuthFailure,
		UserID: identity.Subject,
		Details: map[string]any{
			"reason":     "token_exchange_subject_key_mismatch",
			"grant_type": GrantTypeTokenExchange,
			"session_id": sessionID,
		},
	})
	return ErrSubjectKeyMismatch
}

// checkAllowedResource enforces Config.TokenExchangeAllowedResources on the
// self-issued exchange: when the list is non-empty, the audience the token would
// be minted for must be the server's own resource identifier or a listed value,
// otherwise issuance is rejected with ErrInvalidTarget. An empty list disables
// the check. Returns nil when the exchange is allowed.
func (s *Server) checkAllowedResource(ctx context.Context, audience, sessionID string) error {
	allowed := s.Config.TokenExchangeAllowedResources
	if len(allowed) == 0 || audience == s.Config.GetResourceIdentifier() || slices.Contains(allowed, audience) {
		return nil
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure,
		Details: map[string]any{
			"reason":     "token_exchange_resource_not_allowed",
			"grant_type": GrantTypeTokenExchange,
			"audience":   audience,
			"session_id": sessionID,
		},
	})
	return fmt.Errorf("%w: resource %q", ErrInvalidTarget, audience)
}

// checkSubjectEmailVerified enforces the fail-closed email gate on the
// self-issued exchange: a subject whose validated claims carry an email without
// email_verified=true is refused, because the issued token emits that email
// (see defaultExchangeOptions) and resource servers authorize on it. Subjects
// without an email claim pass; their tokens carry no email to trust.
func (s *Server) checkSubjectEmailVerified(ctx context.Context, identity *SubjectIdentity, sessionID string) error {
	if identity.Claims == nil || identity.Claims.Email == "" || identity.Claims.EmailVerified {
		return nil
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventAuthFailure,
		UserID: identity.Subject,
		Details: map[string]any{
			"reason":     "token_exchange_unverified_subject_email",
			"grant_type": GrantTypeTokenExchange,
			"session_id": sessionID,
		},
	})
	return ErrUnverifiedSubjectEmail
}

// exchangeSessionRateLimited reports whether the per-session issuance limiter rejects
// sessionID on the self-issued exchange and audits the rejection when it does. A
// nil UserRateLimiter disables the check. The brokered path has its own
// audience-aware equivalent (exchangeRateLimited).
func (s *Server) exchangeSessionRateLimited(ctx context.Context, sessionID string) bool {
	if s.UserRateLimiter == nil || s.UserRateLimiter.Allow(sessionID) {
		return false
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure,
		Details: map[string]any{
			"reason":     "token_exchange_rate_limited",
			"grant_type": GrantTypeTokenExchange,
			"session_id": sessionID,
		},
	})
	return true
}

// maxActorChainDepth bounds RFC 8693 §4.4 act nesting in an issued token. A chain
// deeper than this is rejected fail-closed: real A2A topologies are shallow, and
// unbounded nesting is an abuse vector (token-size blowup and parser pressure on
// every downstream that validates the token).
const maxActorChainDepth = 10

// priorActorChain returns the act chain already present on the validated subject
// token, converted to the issued-token Actor shape. Nil when the subject carries
// no act (the common single-hop OBO case).
func priorActorChain(subject *SubjectIdentity) *Actor {
	if subject == nil || subject.Claims == nil {
		return nil
	}
	return actorFromClaim(subject.Claims.Act)
}

// actorFromClaim recursively converts a decoded oidc.ActorClaim chain into the
// issued-token Actor shape, preserving nesting order.
func actorFromClaim(c *oidc.ActorClaim) *Actor {
	if c == nil {
		return nil
	}
	return &Actor{Iss: c.Issuer, Sub: c.Subject, Act: actorFromClaim(c.Act)}
}

// buildActorChain assembles the act claim for an issued token. When actor is
// non-nil it becomes the outermost (most recent) actor and prior is nested beneath
// it, extending a multi-hop delegation chain. When actor is nil the prior chain is
// carried forward unchanged. The combined depth is bounded by maxActorChainDepth
// and rejected fail-closed when exceeded.
func buildActorChain(actor *SubjectIdentity, prior *Actor) (*Actor, error) {
	act := prior
	if actor != nil {
		act = &Actor{Iss: actor.Issuer, Sub: actor.Subject, Act: prior}
	}
	if depth := actorChainDepth(act); depth > maxActorChainDepth {
		return nil, fmt.Errorf("actor chain depth %d exceeds maximum %d", depth, maxActorChainDepth)
	}
	return act, nil
}

// actorChainDepth counts the hops in an act chain.
func actorChainDepth(a *Actor) int {
	n := 0
	for ; a != nil; a = a.Act {
		n++
	}
	return n
}

// validateExchangeSubjectToken validates the RFC 8693 subject token and returns
// the verified identity. Audit failure events use the "subject" role; reasons
// are subject_token_validation_failed and unsupported_subject_token_type.
// defaultAudiences is forwarded to Validate and applies only when the matched
// issuer entry has no AllowedAudiences; the subject token is not broker-bound, so
// callers pass nil. extra is merged into every failure audit event; pass brokered
// flow context (exchange, client_id, audience, session_id) from BrokeredExchange.
func (s *Server) validateExchangeSubjectToken(ctx context.Context, subject TypedToken, defaultAudiences []string, extra map[string]any) (*SubjectIdentity, error) {
	return s.validateExchangeToken(ctx, subject, "subject", defaultAudiences, extra)
}

// validateExchangeActorToken validates the RFC 8693 actor token and returns
// the verified actor identity. Audit failure events use the "actor" role;
// reasons are actor_token_validation_failed and unsupported_actor_token_type.
// The broker's own issuer is passed as the default audience so actor tokens
// from issuers with no AllowedAudiences configured are still bound to this
// broker and cannot be replayed from a different audience context.
// extra is merged into every failure audit event; pass brokered flow context
// (exchange, client_id, audience, session_id) from BrokeredExchange.
func (s *Server) validateExchangeActorToken(ctx context.Context, actor TypedToken, extra map[string]any) (*SubjectIdentity, error) {
	return s.validateExchangeToken(ctx, actor, "actor", []string{s.Config.Issuer}, extra)
}

// resolveExchangeActor validates the RFC 8693 actor token when one is present
// and returns the verified actor identity. It returns nil when no actor token is
// presented, or when the actor resolves to the same identity as the subject:
// self-delegation is a no-op, so the issued token carries no act claim. extra is
// merged into actor-validation failure events; pass nil when there is none.
func (s *Server) resolveExchangeActor(ctx context.Context, actor TypedToken, subject *SubjectIdentity, extra map[string]any) (*SubjectIdentity, error) {
	if actor.Token == "" {
		return nil, nil
	}
	actorIdentity, err := s.validateExchangeActorToken(ctx, actor, extra)
	if err != nil {
		return nil, err
	}
	if actorIdentity.Issuer == subject.Issuer && actorIdentity.Subject == subject.Subject {
		return nil, nil
	}
	return actorIdentity, nil
}

// validateExchangeToken routes token to the SubjectTokenValidator registered for
// its token type and returns the verified identity. role is "subject" or "actor";
// it drives audit reason strings and detail keys so subject and actor failures
// produce distinct, unambiguous audit events. defaultAudiences is forwarded to
// Validate and applies only when the matched issuer entry has no AllowedAudiences.
// extra is merged into every failure audit event; use it to inject flow-level context
// (exchange, client_id, audience, session_id) so a single event carries both the
// validation detail and the brokered-flow correlation fields.
func (s *Server) validateExchangeToken(ctx context.Context, token TypedToken, role string, defaultAudiences []string, extra map[string]any) (*SubjectIdentity, error) {
	typeKey := role + "_token_type"
	unsupportedReason := "unsupported_" + role + "_token_type"
	validationFailedReason := role + "_token_validation_failed"

	auditDetails := func(base map[string]any) map[string]any {
		maps.Copy(base, extra)
		return base
	}

	switch token.Type {
	case SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT:
	default:
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     unsupportedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      token.Type,
			}),
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: token.Type, role: role}
	}

	v := s.SubjectValidatorFor(token.Type)
	if v == nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     unsupportedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      token.Type,
			}),
		})
		return nil, &TokenExchangeUnsupportedTypeError{tokenType: token.Type, role: role}
	}

	identity, err := v.Validate(ctx, token.Token, defaultAudiences)
	if err != nil {
		s.Logger.Debug("token exchange: "+role+" token validation failed",
			typeKey, token.Type, "error", err)
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure,
			Details: auditDetails(map[string]any{
				"reason":     validationFailedReason,
				"grant_type": GrantTypeTokenExchange,
				typeKey:      token.Type,
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
