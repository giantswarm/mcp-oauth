package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
)

// ErrInvalidTarget is returned by BrokeredExchange when the
// requested audience cannot be served: no Exchanger is configured, the
// client's allowlist does not contain the audience, or the Exchanger
// itself reports the audience as unknown. Handlers map it to the RFC 8693
// §2.2.2 invalid_target error response.
var ErrInvalidTarget = errors.New("requested audience is not allowed for this client")

// ErrExchangeRateLimited is returned by BrokeredExchange when the configured
// UserRateLimiter rejects the request. The HTTP handler rate-limits authenticated
// requests in middleware, but the method may also be called in-process, so the
// same limiter is enforced here keyed on the per-session ID. Callers invoking the
// method directly should surface this as a 429-equivalent.
var ErrExchangeRateLimited = errors.New("token exchange rate limit exceeded")

// ExchangerRequest carries the validated inputs of a brokered RFC 8693
// token exchange to the host's Exchanger implementation. The subject and
// actor tokens have already been validated (signature, issuer, audience,
// expiry) against the server's trusted issuers before the Exchanger is
// invoked. ClientID is the authenticated broker client that issued the request.
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
	// ClientID is the authenticated broker client that issued the request.
	ClientID string
	// Subject is the verified identity extracted from the subject token.
	Subject *SubjectIdentity
	// SubjectToken is the raw subject token. Hosts typically forward it
	// unchanged as the subject_token of their own downstream exchange.
	SubjectToken string
	// SubjectTokenType is the RFC 8693 token-type URN of SubjectToken.
	SubjectTokenType string
	// ActorToken is the raw RFC 8693 actor_token, forwarded unchanged.
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
	// AccessToken is the downstream token returned to the client unchanged.
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

// BrokeredExchangeRequest is the input to BrokeredExchange, where the token is
// signed by a downstream issuer reached through the host Exchanger. ClientID is
// the authenticated confidential client; Audience is the RFC 8693 logical target
// the Exchanger resolves to a downstream issuer.
type BrokeredExchangeRequest struct {
	SubjectExchange
	ClientID string
	Audience string
}

// BrokeredExchange implements the RFC 8693 flow where the resulting token is
// issued by a downstream issuer reached through the configured Exchanger. The
// subject token (and, when present, the actor token for the §4.4 delegation
// chain) are validated against the server's trusted issuers before the Exchanger
// is invoked; the verified actor identity is forwarded to it.
//
// Policy: an Exchanger must be configured (ErrInvalidTarget otherwise) and the
// audience must be in the client's Config.TokenExchangeClientAudiences allowlist.
// Self-delegation (actor equal to subject) is dropped to a no-op, and no refresh
// token is issued; the result's expiry is the downstream token's and clients
// re-exchange. Every outcome is audited with the client ID, subject, requested
// audience, granted scope, and the deterministic cross-hop session ID derived
// from the subject token, so broker audit lines correlate with downstream MCP
// audit lines for the same token.
func (s *Server) BrokeredExchange(ctx context.Context, req BrokeredExchangeRequest) (*TokenExchangeResult, error) {
	sessionID := s.deriveForwardedSessionID(req.Subject.Token)

	if s.exchangeRateLimited(ctx, req.ClientID, req.Audience, sessionID) {
		return nil, ErrExchangeRateLimited
	}

	if s.exchanger == nil {
		s.auditExchangeFailure(ctx, req.ClientID, req.Audience, sessionID, "token_exchange_no_exchanger", nil)
		return nil, fmt.Errorf("%w: no exchanger configured", ErrInvalidTarget)
	}

	if !slices.Contains(s.Config.TokenExchangeClientAudiences[req.ClientID], req.Audience) {
		s.auditExchangeFailure(ctx, req.ClientID, req.Audience, sessionID, "token_exchange_audience_not_allowed", nil)
		return nil, fmt.Errorf("%w: audience %q", ErrInvalidTarget, req.Audience)
	}

	auditCtx := map[string]any{
		logKeyExchange:  exchangeBrokered,
		paramClientID:   req.ClientID,
		paramAudience:   req.Audience,
		logKeySessionID: sessionID,
	}

	identity, err := s.validateExchangeSubjectToken(ctx, req.Subject, nil, auditCtx)
	if err != nil {
		return nil, err
	}

	actor, err := s.resolveExchangeActor(ctx, req.Actor, identity, auditCtx)
	if err != nil {
		return nil, err
	}

	return s.dispatchDownstreamExchange(ctx, req.ClientID,
		req.Subject, req.Actor, req.Audience, req.Resource, req.Scope, sessionID, identity, actor)
}

// dispatchDownstreamExchange calls the Exchanger and emits the outcome audit
// event. identity and actorIdentity must already be validated before calling. A
// nil actorIdentity (no delegation, or self-delegation stripped to a no-op) clears
// the forwarded actor token so the three actor fields on ExchangerRequest stay
// consistent.
func (s *Server) dispatchDownstreamExchange(
	ctx context.Context,
	clientID string,
	subject, actor TypedToken,
	audience, resource, scope, sessionID string,
	identity, actorIdentity *SubjectIdentity,
) (*TokenExchangeResult, error) {
	if actorIdentity == nil {
		actor = TypedToken{}
	}
	result, err := s.exchanger.Exchange(ctx, &ExchangerRequest{
		Audience:         audience,
		Resource:         resource,
		Scope:            scope,
		ClientID:         clientID,
		Subject:          identity,
		SubjectToken:     subject.Token,
		SubjectTokenType: subject.Type,
		ActorToken:       actor.Token,
		ActorTokenType:   actor.Type,
		Actor:            actorIdentity,
	})
	if err != nil {
		s.Logger.Debug("brokered token exchange: downstream exchange failed",
			paramClientID, clientID, paramAudience, audience, logKeyError, err)
		s.auditExchangeFailure(ctx, clientID, audience, sessionID, "token_exchange_downstream_failed", map[string]any{
			claimSub:    identity.Subject,
			logKeyError: err.Error(),
		})
		if errors.Is(err, ErrInvalidTarget) {
			return nil, err
		}
		return nil, fmt.Errorf("downstream exchange: %w", err)
	}
	if result == nil || result.AccessToken == "" {
		s.auditExchangeFailure(ctx, clientID, audience, sessionID, "token_exchange_downstream_empty_token", map[string]any{
			claimSub: identity.Subject,
		})
		return nil, fmt.Errorf("downstream exchange returned no token")
	}

	issuedTokenType := result.IssuedTokenType
	if issuedTokenType == "" {
		issuedTokenType = SubjectTokenTypeAccessToken
	}

	s.Logger.Debug("brokered token exchange: issued downstream token",
		paramClientID, clientID, claimSub, identity.Subject, "subject_iss", identity.Issuer,
		paramAudience, audience, paramScope, result.Scope, "exp", result.ExpiresAt,
		logKeySessionID, sessionID)

	successDetails := map[string]any{
		paramGrantType:       GrantTypeTokenExchange,
		logKeyExchange:       exchangeBrokered,
		"subject_token_type": subject.Type,
		paramAudience:        audience,
		paramScope:           result.Scope,
		"subject_iss":        identity.Issuer,
		logKeySessionID:      sessionID,
	}
	if actorIdentity != nil {
		successDetails["actor_iss"] = actorIdentity.Issuer
		successDetails["actor_sub"] = actorIdentity.Subject
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

// exchangeRateLimited reports whether the brokered exchange is currently
// rate-limited for sessionID and audits the rejection when it is. The HTTP
// handler rate-limits authenticated requests in middleware keyed on the user,
// but BrokeredExchange may also be called in-process, so the same UserRateLimiter
// is enforced here keyed on the per-session ID, so a compromised session cannot
// flood issuance regardless of entry point. A nil UserRateLimiter disables the check.
func (s *Server) exchangeRateLimited(ctx context.Context, clientID, audience, sessionID string) bool {
	if s.UserRateLimiter == nil || s.UserRateLimiter.Allow(sessionID) {
		return false
	}
	s.auditExchangeFailure(ctx, clientID, audience, sessionID, "token_exchange_rate_limited", nil)
	return true
}

// auditExchangeFailure emits the auth-failure audit event for brokered exchange
// rejection paths. extra is merged over the base details.
func (s *Server) auditExchangeFailure(ctx context.Context, clientID, audience, sessionID, reason string, extra map[string]any) {
	details := map[string]any{
		logKeyReason:    reason,
		paramGrantType:  GrantTypeTokenExchange,
		logKeyExchange:  exchangeBrokered,
		paramAudience:   audience,
		logKeySessionID: sessionID,
	}
	maps.Copy(details, extra)
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventAuthFailure,
		ClientID: clientID,
		Details:  details,
	})
}
