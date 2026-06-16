package server

import (
	"context"
	"errors"
	"fmt"
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

	if s.exchanger == nil {
		s.auditExchangeFailure(ctx, "brokered", clientID, audience, sessionID, "token_exchange_no_exchanger", nil)
		return nil, fmt.Errorf("%w: no exchanger configured", ErrInvalidTarget)
	}

	if !slices.Contains(s.Config.TokenExchangeClientAudiences[clientID], audience) {
		s.auditExchangeFailure(ctx, "brokered", clientID, audience, sessionID, "token_exchange_audience_not_allowed", nil)
		return nil, fmt.Errorf("%w: audience %q", ErrInvalidTarget, audience)
	}

	identity, err := s.validateExchangeSubjectToken(ctx, subjectToken, subjectTokenType)
	if err != nil {
		return nil, err
	}

	var actor *SubjectIdentity
	if actorToken != "" {
		actor, err = s.validateExchangeActorToken(ctx, actorToken, actorTokenType)
		if err != nil {
			return nil, err
		}
	} else {
		actorTokenType = ""
	}

	return s.dispatchDownstreamExchange(ctx, "brokered", clientID,
		subjectToken, subjectTokenType, actorToken, actorTokenType,
		audience, resource, scope, sessionID, identity, actor)
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

	if s.exchanger == nil {
		s.auditExchangeFailure(ctx, "workload", "", audience, sessionID, "token_exchange_no_exchanger", nil)
		return nil, fmt.Errorf("%w: no exchanger configured", ErrInvalidTarget)
	}

	identity, err := s.validateExchangeSubjectToken(ctx, subjectToken, subjectTokenType)
	if err != nil {
		return nil, err
	}

	var actor *SubjectIdentity
	if actorToken != "" {
		actor, err = s.validateExchangeActorToken(ctx, actorToken, actorTokenType)
		if err != nil {
			return nil, err
		}
	}

	workloadSubject := identity.Subject
	if actor != nil {
		workloadSubject = actor.Subject
	}

	if !workloadAudienceAllowed(s.Config.WorkloadAudiences, workloadSubject, audience) {
		s.auditExchangeFailure(ctx, "workload", "", audience, sessionID, "token_exchange_audience_not_allowed", map[string]any{
			"sub": workloadSubject,
		})
		return nil, fmt.Errorf("%w: audience %q", ErrInvalidTarget, audience)
	}

	return s.dispatchDownstreamExchange(ctx, "workload", "",
		subjectToken, subjectTokenType, actorToken, actorTokenType,
		audience, resource, scope, sessionID, identity, actor)
}

// workloadAudienceAllowed reports whether the workload identified by subject
// is allowed to request audience. Keys in allowed are matched exactly or by
// glob (matchClaimPattern semantics: * spans the whole string including any
// separators, so "system:serviceaccount:ns:*" matches every service account
// in ns).
func workloadAudienceAllowed(allowed map[string][]string, subject, audience string) bool {
	for pattern, auds := range allowed {
		if pattern != subject && matchClaimPattern(pattern, subject) != nil {
			continue
		}
		if slices.Contains(auds, audience) {
			return true
		}
	}
	return false
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
		"client_id", clientID, "sub", identity.Subject, "iss_act", identity.Issuer,
		"audience", audience, "scope", result.Scope, "exp", result.ExpiresAt,
		"session_id", sessionID)

	successDetails := map[string]any{
		"grant_type":         GrantTypeTokenExchange,
		"exchange":           exchange,
		"subject_token_type": subjectTokenType,
		"audience":           audience,
		"scope":              result.Scope,
		"act_iss":            identity.Issuer,
		"session_id":         sessionID,
	}
	if actor != nil {
		successDetails["actor_iss"] = actor.Issuer
		successDetails["actor_sub"] = actor.Subject
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
