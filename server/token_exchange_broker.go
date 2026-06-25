package server

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
)

// ErrInvalidTarget is returned by BrokerExchangeSubjectToken when the
// requested audience cannot be served: no Exchanger is configured, the
// client's allowlist does not contain the audience, or the Exchanger
// itself reports the audience as unknown. Handlers map it to the RFC 8693
// §2.2.2 invalid_target error response.
var ErrInvalidTarget = errors.New("requested audience is not allowed for this client")

// ErrExchangeRateLimited is returned by BrokerExchangeSubjectToken and
// WorkloadExchangeSubjectToken when the configured UserRateLimiter rejects the
// request. The HTTP handler rate-limits authenticated requests in middleware,
// but these methods are also called in-process (e.g. by an aggregator minting
// per-backend tokens), so the same limiter is enforced here keyed on the
// per-session ID. Callers invoking the methods directly should surface this as
// a 429-equivalent.
var ErrExchangeRateLimited = errors.New("token exchange rate limit exceeded")

// ExchangerRequest carries the validated inputs of a brokered RFC 8693
// token exchange to the host's Exchanger implementation. The subject and
// actor tokens have already been validated (signature, issuer, audience,
// expiry) against the server's trusted issuers before the Exchanger is
// invoked. ClientID is the authenticated broker client on the
// client-authenticated path; it is empty on the workload-authenticated path.
type ExchangerRequest struct {
	// Audience is the RFC 8693 audience parameter: the logical name of the
	// downstream target the client wants a token for. The host maps it to a
	// downstream issuer and credentials.
	Audience string
	// Resource is the RFC 8707 resource parameter, when the client supplied
	// one alongside audience. May be empty.
	Resource string
	// Scope is the raw requested scope string. May be empty.
	Scope string
	// ClientID is the authenticated broker client that issued the request on
	// the client-authenticated path. Empty when the request was authenticated
	// by the subject or actor token itself (workload path).
	ClientID string
	// Subject is the verified identity extracted from the subject token.
	Subject *SubjectIdentity
	// SubjectToken is the raw subject token. Hosts typically forward it
	// verbatim as the subject_token of their own downstream exchange.
	SubjectToken string
	// SubjectTokenType is the RFC 8693 token-type URN of SubjectToken.
	SubjectTokenType string
	// ActorToken is the raw RFC 8693 actor_token, forwarded verbatim.
	// Empty when no actor_token was presented.
	ActorToken string
	// ActorTokenType is the RFC 8693 token-type URN of ActorToken.
	// Empty when ActorToken is empty.
	ActorTokenType string
	// Actor is the verified identity of the acting party (RFC 8693 §4.4
	// delegation chain). Nil when no actor_token was presented.
	Actor *SubjectIdentity
	// GrantedGroups are groups the broker authorizes for this exchange from a
	// matching WorkloadGrant, distinct from any groups the subject token itself
	// carried in Subject.Claims. Populated only on the workload (no-actor) path;
	// the Exchanger merges them into the minted token. Keeping them separate
	// preserves the provenance of the validated subject identity, which is never
	// mutated to carry broker-granted authorization.
	GrantedGroups []string
	// GrantedSubject is the broker-asserted subject for this exchange from a
	// matching WorkloadGrant; when non-empty it replaces the validated subject as
	// the minted token's sub. Populated only on the workload (no-actor) path. The
	// validated subject identity (Subject) is never mutated.
	GrantedSubject string
}

// ExchangerResult is the downstream token returned by an Exchanger.
type ExchangerResult struct {
	// AccessToken is the downstream token returned to the client verbatim.
	AccessToken string
	// IssuedTokenType is the RFC 8693 issued_token_type URN. Empty defaults
	// to urn:ietf:params:oauth:token-type:access_token.
	IssuedTokenType string
	// ExpiresAt is the downstream token's expiry. It bounds the expires_in
	// reported to the client — brokered tokens never outlive the downstream
	// token, and no refresh token is issued; clients re-exchange instead.
	ExpiresAt time.Time
	// Scope is the scope granted by the downstream issuer. May be empty.
	Scope string
	// JTI is the unique identifier of the issued token, when the Exchanger
	// mints a JWT it controls (e.g. LocalMintExchanger). Surfaced so the broker
	// can record it in the mint audit event; empty when the downstream token is
	// opaque or minted by a remote issuer.
	JTI string
}

// Exchanger maps a requested audience to a downstream token. Hosts (e.g. an
// MCP aggregator acting as a token broker) implement it to perform the
// downstream exchange — typically an RFC 8693 request against a remote
// issuer using host-held credentials. mcp-oauth stays generic: it owns
// subject-token validation, allowlist policy, and audit; the host owns the
// audience→issuer mapping.
//
// Returning an error wrapping ErrInvalidTarget signals that the audience is
// unknown to the host; any other error is reported to the client as a
// generic invalid_grant without leaking detail.
type Exchanger interface {
	Exchange(ctx context.Context, req *ExchangerRequest) (*ExchangerResult, error)
}

// Exchanger returns the configured Exchanger, or nil when brokered token
// exchange is disabled.
func (s *Server) Exchanger() Exchanger {
	return s.exchanger
}

// BrokerExchangeSubjectToken implements the client-authenticated brokered
// RFC 8693 flow: a confidential client presents a subject token and an
// audience, and receives a downstream token minted by the configured
// Exchanger. When actorToken is non-empty the actor token is validated
// against the server's trusted issuers and the verified actor identity is
// forwarded to the Exchanger (RFC 8693 §4.4 delegation chain).
//
// Policy enforced here:
//   - an Exchanger must be configured and the audience must be in the
//     client's Config.TokenExchangeClientAudiences allowlist, otherwise
//     ErrInvalidTarget is returned
//   - subject and actor tokens are validated by the registered
//     SubjectTokenValidator (signature, issuer, audience, expiry)
//   - no refresh token is ever issued; the result's expiry is the downstream
//     token's expiry and clients are expected to re-exchange
//
// Every outcome is audited. Success events carry the client ID, subject,
// requested audience, granted scope, and the deterministic cross-hop session
// ID derived from the subject token (same derivation as forwarded-token
// acceptance, so broker audit lines correlate with downstream MCP audit
// lines for the same token).
func (s *Server) BrokerExchangeSubjectToken(
	ctx context.Context,
	clientID, subjectToken, subjectTokenType, actorToken, actorTokenType, audience, resource, scope string,
) (*TokenExchangeResult, error) {
	sessionID := s.deriveForwardedSessionID(subjectToken)

	if s.exchangeRateLimited(ctx, "brokered", clientID, audience, sessionID) {
		return nil, ErrExchangeRateLimited
	}

	if s.exchanger == nil {
		s.auditExchangeFailure(ctx, "brokered", clientID, audience, sessionID, "token_exchange_no_exchanger", nil)
		return nil, fmt.Errorf("%w: no exchanger configured", ErrInvalidTarget)
	}

	if !slices.Contains(s.Config.TokenExchangeClientAudiences[clientID], audience) {
		s.auditExchangeFailure(ctx, "brokered", clientID, audience, sessionID, "token_exchange_audience_not_allowed", nil)
		return nil, fmt.Errorf("%w: audience %q", ErrInvalidTarget, audience)
	}

	brokerAuditCtx := map[string]any{
		"exchange":   "brokered",
		"client_id":  clientID,
		"audience":   audience,
		"session_id": sessionID,
	}

	identity, err := s.validateExchangeSubjectToken(ctx, subjectToken, subjectTokenType, nil, brokerAuditCtx)
	if err != nil {
		return nil, err
	}

	var actor *SubjectIdentity
	if actorToken != "" {
		actor, err = s.validateExchangeActorToken(ctx, actorToken, actorTokenType, brokerAuditCtx)
		if err != nil {
			return nil, err
		}
		// Self-delegation is a no-op: strip the actor and proceed as pure M2M.
		if actor.Issuer == identity.Issuer && actor.Subject == identity.Subject {
			actor = nil
			actorToken = ""
			actorTokenType = ""
		} else if !s.actorDelegationAllowed(actor.Issuer, actor.Subject, identity.Issuer, identity.Subject) {
			s.auditExchangeFailure(ctx, "brokered", clientID, audience, sessionID, "actor_delegation_not_authorized", map[string]any{
				"actor_sub": actor.Subject,
				"sub":       identity.Subject,
			})
			return nil, fmt.Errorf("%w: actor %q is not authorized to act for subject %q", ErrInvalidTarget, actor.Subject, identity.Subject)
		}
	} else {
		actorTokenType = ""
	}

	// The client-authenticated path carries no workload identity grant.
	return s.dispatchDownstreamExchange(ctx, "brokered", clientID,
		subjectToken, subjectTokenType, actorToken, actorTokenType,
		audience, resource, scope, sessionID, identity, actor, nil, "")
}

// WorkloadExchangeSubjectToken implements the workload-authenticated brokered
// RFC 8693 flow: no OAuth client credentials are required. The requesting
// workload authenticates by presenting its own SA token as the subject_token;
// for delegation (RFC 8693 §4.4) an actor_token may also be provided. Both
// tokens are validated against the server's TrustedIssuers before the
// allowlist is checked.
//
// Policy enforced here:
//   - an Exchanger must be configured; ErrInvalidTarget otherwise
//   - subject and actor tokens are validated by the registered
//     SubjectTokenValidator (signature, issuer, audience, expiry)
//   - when actor_token is present, authorization uses actor.Subject
//     (delegation); otherwise subject.Subject is used (impersonation)
//   - the acting subject must match a Config.WorkloadAudiences key (exact or
//     glob) whose value list contains the requested audience; ErrInvalidTarget
//     on miss
//
// Every outcome is audited with exchange kind "workload" and empty ClientID.
func (s *Server) WorkloadExchangeSubjectToken(
	ctx context.Context,
	subjectToken, subjectTokenType, actorToken, actorTokenType, audience, resource, scope string,
) (*TokenExchangeResult, error) {
	sessionID := s.deriveForwardedSessionID(subjectToken)

	if s.exchangeRateLimited(ctx, "workload", "", audience, sessionID) {
		return nil, ErrExchangeRateLimited
	}

	if s.exchanger == nil {
		s.auditExchangeFailure(ctx, "workload", "", audience, sessionID, "token_exchange_no_exchanger", nil)
		return nil, fmt.Errorf("%w: no exchanger configured", ErrInvalidTarget)
	}

	identity, err := s.validateWorkloadSubject(ctx, subjectToken, subjectTokenType, actorToken)
	if err != nil {
		return nil, err
	}

	actor, err := s.validateWorkloadActor(ctx, actorToken, actorTokenType, identity, audience, sessionID)
	if err != nil {
		return nil, err
	}

	// A token this broker already minted with a delegation chain (act),
	// re-presented without a fresh actor, is an audience re-bind of an
	// already-authorized delegation. The original actor was validated against
	// ActorDelegationPolicy when the chain was minted, so re-binding authorizes
	// the new audience against the recorded acting principal (the act claim) and
	// the exchanger preserves the chain. Without this it would fall to the M2M
	// branch and be gated on the minted human subject, which holds no workload
	// grant.
	rebindDelegated := actor == nil &&
		identity.Issuer == s.Config.Issuer &&
		identity.Claims != nil && identity.Claims.Act != nil

	workloadIssuer := identity.Issuer
	workloadSubject := identity.Subject
	switch {
	case actor != nil:
		workloadIssuer = actor.Issuer
		workloadSubject = actor.Subject
	case rebindDelegated:
		workloadIssuer = identity.Claims.Act.Issuer
		workloadSubject = identity.Claims.Act.Subject
	}

	if !s.workloadAudienceAllowed(workloadIssuer, workloadSubject, audience) {
		s.auditExchangeFailure(ctx, "workload", "", audience, sessionID, "token_exchange_audience_not_allowed", map[string]any{
			"sub": workloadSubject,
		})
		return nil, fmt.Errorf("%w: audience %q", ErrInvalidTarget, audience)
	}

	// On the workload (no-actor) path the subject is the workload itself, e.g. a
	// groupless K8s SA token; a matching grant injects groups and/or subject. A
	// delegation (fresh actor) and an act-preserving re-bind both carry the human
	// subject's own identity, so nothing is injected.
	var grantedGroups []string
	var grantedSubject string
	if actor == nil && !rebindDelegated {
		if g := s.workloadGrant(identity.Issuer, identity.Subject, audience); g != nil {
			grantedGroups = g.Granted.Groups
			grantedSubject = g.Granted.Subject
		}
	}

	return s.dispatchDownstreamExchange(ctx, "workload", "",
		subjectToken, subjectTokenType, actorToken, actorTokenType,
		audience, resource, scope, sessionID, identity, actor, grantedGroups, grantedSubject)
}

// validateWorkloadSubject validates the subject token on the workload exchange
// path. On the no-actor (impersonation) path the subject token is itself the
// caller-authenticating credential, so it is bound to the broker issuer as
// default audience — the same anti-replay treatment applied to actor tokens. On
// the delegation path the subject is the user's token and must not be
// broker-bound. Authorization of a self-minted token that carries a delegation
// chain is handled by WorkloadExchangeSubjectToken, which gates the audience on
// the recorded acting principal.
func (s *Server) validateWorkloadSubject(ctx context.Context, subjectToken, subjectTokenType, actorToken string) (*SubjectIdentity, error) {
	var subjDefaultAud []string
	if actorToken == "" {
		subjDefaultAud = []string{s.Config.Issuer}
	}
	return s.validateExchangeSubjectToken(ctx, subjectToken, subjectTokenType, subjDefaultAud, nil)
}

// validateWorkloadActor validates the actor token (when present) on the workload
// exchange path and enforces the actor→subject delegation policy. Returns
// (nil, nil) when no actor token was presented (the M2M path).
func (s *Server) validateWorkloadActor(ctx context.Context, actorToken, actorTokenType string, subject *SubjectIdentity, audience, sessionID string) (*SubjectIdentity, error) {
	if actorToken == "" {
		return nil, nil
	}
	actor, err := s.validateExchangeActorToken(ctx, actorToken, actorTokenType, nil)
	if err != nil {
		return nil, err
	}
	// When actor resolves to the same identity as subject, treat as pure M2M.
	// Strip the actor so downstream minting skips the act claim and delegation
	// checks. This lets a static headersFrom SA token be sent as X-Actor-Token
	// without needing an explicit SA→SA delegation rule.
	if actor.Issuer == subject.Issuer && actor.Subject == subject.Subject {
		return nil, nil
	}
	if !s.actorDelegationAllowed(actor.Issuer, actor.Subject, subject.Issuer, subject.Subject) {
		s.auditExchangeFailure(ctx, "workload", "", audience, sessionID, "actor_delegation_not_authorized", map[string]any{
			"actor_sub": actor.Subject,
			"sub":       subject.Subject,
		})
		return nil, fmt.Errorf("%w: actor %q is not authorized to act for subject %q", ErrInvalidTarget, actor.Subject, subject.Subject)
	}
	return actor, nil
}

// workloadAudienceAllowed reports whether the workload identified by issuer+subject
// is allowed to request audience. Each WorkloadGrant in Config.WorkloadAudiences is
// checked: Issuer is matched exactly (empty = any); Subject by glob (* spans slashes).
func (s *Server) workloadAudienceAllowed(issuer, subject, audience string) bool {
	for _, g := range s.Config.WorkloadAudiences {
		if !s.issuerMatches(g.Issuer, issuer) {
			continue
		}
		if !s.subjectMatches(g.Subject, subject) {
			continue
		}
		if slices.Contains(g.Audiences, audience) {
			return true
		}
	}
	return false
}

// workloadGrant returns the first WorkloadGrant matching issuer+subject+audience
// that carries broker-granted authorization (Granted.Groups and/or Granted.Subject).
// Such grants are constrained to explicit issuer+subject by Config.Validate, so
// at most one logically applies.
func (s *Server) workloadGrant(issuer, subject, audience string) *WorkloadGrant {
	for i := range s.Config.WorkloadAudiences {
		g := &s.Config.WorkloadAudiences[i]
		if len(g.Granted.Groups) == 0 && g.Granted.Subject == "" {
			continue
		}
		if !s.issuerMatches(g.Issuer, issuer) {
			continue
		}
		if !s.subjectMatches(g.Subject, subject) {
			continue
		}
		if slices.Contains(g.Audiences, audience) {
			return g
		}
	}
	return nil
}

// actorDelegationAllowed reports whether the actor identified by actorIssuer+actorSub is
// authorized to act on behalf of the subject identified by subjectIssuer+subjectSub.
// Config.ActorDelegationPolicy is the list of DelegationGrants. A nil/empty policy
// denies all delegation.
func (s *Server) actorDelegationAllowed(actorIssuer, actorSub, subjectIssuer, subjectSub string) bool {
	for _, g := range s.Config.ActorDelegationPolicy {
		if !s.issuerMatches(g.ActorIssuer, actorIssuer) {
			continue
		}
		if !s.subjectMatches(g.ActorSubject, actorSub) {
			continue
		}
		if !s.issuerMatches(g.SubjectIssuer, subjectIssuer) {
			continue
		}
		if s.subjectMatches(g.SubjectSubject, subjectSub) {
			return true
		}
	}
	return false
}

// issuerMatches reports whether the grant's issuer pattern matches the token issuer.
// Use "*" to match any issuer; an empty pattern matches nothing.
func (s *Server) issuerMatches(pattern, issuer string) bool {
	return pattern == "*" || pattern == issuer
}

// subjectMatches reports whether value matches pattern using matchClaimPattern
// semantics (exact equality or glob with * spanning slashes). A malformed pattern
// is logged as a warning and treated as no-match (fail-closed).
func (s *Server) subjectMatches(pattern, value string) bool {
	if pattern == value {
		return true
	}
	err := matchClaimPattern(pattern, value)
	if err != nil {
		if errors.Is(err, path.ErrBadPattern) {
			s.Logger.Warn("grant subject pattern is malformed — check configuration", "pattern", pattern)
		}
		return false
	}
	return true
}

// dispatchDownstreamExchange calls the Exchanger and emits the outcome audit
// event. exchange is "brokered" or "workload"; clientID is empty on the
// workload path. identity and actor must already be validated before calling.
func (s *Server) dispatchDownstreamExchange(
	ctx context.Context,
	exchange, clientID,
	subjectToken, subjectTokenType, actorToken, actorTokenType,
	audience, resource, scope, sessionID string,
	identity *SubjectIdentity, actor *SubjectIdentity,
	grantedGroups []string,
	grantedSubject string,
) (*TokenExchangeResult, error) {
	result, err := s.exchanger.Exchange(ctx, &ExchangerRequest{
		Audience:         audience,
		Resource:         resource,
		Scope:            scope,
		ClientID:         clientID,
		Subject:          identity,
		SubjectToken:     subjectToken,
		SubjectTokenType: subjectTokenType,
		ActorToken:       actorToken,
		ActorTokenType:   actorTokenType,
		Actor:            actor,
		GrantedGroups:    grantedGroups,
		GrantedSubject:   grantedSubject,
	})
	if err != nil {
		s.Logger.Debug(exchange+" token exchange: downstream exchange failed",
			"client_id", clientID, "audience", audience, "error", err)
		s.auditExchangeFailure(ctx, exchange, clientID, audience, sessionID, "token_exchange_downstream_failed", map[string]any{
			"sub":   identity.Subject,
			"error": err.Error(),
		})
		if errors.Is(err, ErrInvalidTarget) {
			return nil, err
		}
		return nil, fmt.Errorf("downstream exchange: %w", err)
	}
	if result == nil || result.AccessToken == "" {
		s.auditExchangeFailure(ctx, exchange, clientID, audience, sessionID, "token_exchange_downstream_empty_token", map[string]any{
			"sub": identity.Subject,
		})
		return nil, fmt.Errorf("downstream exchange returned no token")
	}

	issuedTokenType := result.IssuedTokenType
	if issuedTokenType == "" {
		issuedTokenType = SubjectTokenTypeAccessToken
	}

	s.Logger.Debug(exchange+" token exchange: issued downstream token",
		"client_id", clientID, "sub", identity.Subject, "subject_iss", identity.Issuer,
		"audience", audience, "scope", result.Scope, "exp", result.ExpiresAt,
		"session_id", sessionID)

	successDetails := map[string]any{
		"grant_type":         GrantTypeTokenExchange,
		"exchange":           exchange,
		"subject_token_type": subjectTokenType,
		"audience":           audience,
		"scope":              result.Scope,
		"subject_iss":        identity.Issuer,
		"session_id":         sessionID,
	}
	if actor != nil {
		successDetails["actor_iss"] = actor.Issuer
		successDetails["actor_sub"] = actor.Subject
	}
	if result.JTI != "" {
		successDetails["jti"] = result.JTI
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventTokenIssued,
		UserID:   identity.Subject,
		ClientID: clientID,
		Details:  successDetails,
	})

	return &TokenExchangeResult{
		AccessToken:     result.AccessToken,
		ExpiresAt:       result.ExpiresAt,
		Scope:           result.Scope,
		IssuedTokenType: issuedTokenType,
	}, nil
}

// exchangeRateLimited reports whether the mint path is currently rate-limited
// for sessionID and audits the rejection when it is. The HTTP handler
// rate-limits authenticated requests in middleware keyed on the user, but the
// brokered and workload methods are also called in-process, so the same
// UserRateLimiter is enforced here keyed on the per-session ID, so a compromised
// session cannot flood mints regardless of entry point. A nil UserRateLimiter
// disables the check.
func (s *Server) exchangeRateLimited(ctx context.Context, exchange, clientID, audience, sessionID string) bool {
	if s.UserRateLimiter == nil || s.UserRateLimiter.Allow(sessionID) {
		return false
	}
	s.auditExchangeFailure(ctx, exchange, clientID, audience, sessionID, "token_exchange_rate_limited", nil)
	return true
}

// auditExchangeFailure emits the auth-failure audit event for brokered and
// workload exchange rejection paths. exchange is "brokered" or "workload".
// extra is merged over the base details.
func (s *Server) auditExchangeFailure(ctx context.Context, exchange, clientID, audience, sessionID, reason string, extra map[string]any) {
	details := map[string]any{
		"reason":     reason,
		"grant_type": GrantTypeTokenExchange,
		"exchange":   exchange,
		"audience":   audience,
		"session_id": sessionID,
	}
	for k, v := range extra {
		details[k] = v
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventAuthFailure,
		ClientID: clientID,
		Details:  details,
	})
}
