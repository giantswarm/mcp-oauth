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
// itself reports the audience as unknown, or the resource URI is malformed.
// ExchangeAuthorizationCode returns it for a resource parameter that is malformed or names a
// resource this server does not serve. Handlers map it to the
// invalid_target error response (RFC 8693 §2.2.2, RFC 8707 §2).
var ErrInvalidTarget = errors.New("requested audience is not allowed for this client")

// ErrExchangeRateLimited is returned by BrokeredExchange when the configured
// UserRateLimiter rejects the request. The HTTP handler rate-limits authenticated
// requests in middleware, but the method may also be called in-process, so the
// same limiter is enforced here keyed on the per-session ID. Callers invoking the
// method directly should surface this as a 429-equivalent.
var ErrExchangeRateLimited = errors.New("token exchange rate limit exceeded")

// ErrIssuedTokenTypeMismatch is returned when the Exchanger's result does not
// match the requested_token_type supplied to BrokeredExchange.
var ErrIssuedTokenTypeMismatch = errors.New("issued token type does not match requested token type")

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
	// RequestedTokenType is the RFC 8693 requested_token_type. Empty permits
	// the Exchanger to choose the output type.
	RequestedTokenType string
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
	// Actor is the verified identity of the acting party (RFC 8693 §4.1
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
	// Scope is the effective scope granted by the downstream issuer. When its
	// response omits scope, the host must resolve it against its downstream
	// request, which may differ from ExchangerRequest.Scope.
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
// unknown to the host. An error wrapping ErrProviderUnavailable signals that an
// issuer the exchange depends on did not answer; the client gets 503
// with Retry-After and retries the same request. Any
// other error is reported to the client as a generic invalid_request without
// leaking detail.
type Exchanger interface {
	Exchange(ctx context.Context, req *ExchangerRequest) (*ExchangerResult, error)
}

// Exchanger returns the configured Exchanger, or nil when brokered token
// exchange is disabled.
func (s *Server) Exchanger() Exchanger {
	return s.exchanger
}

// BrokeredExchangeRequest is the input to BrokeredExchange, where the token is
// issued by a downstream issuer reached through the host Exchanger. ClientID is
// the authenticated confidential client; Audience is the RFC 8693 logical target
// the Exchanger resolves to a downstream issuer.
type BrokeredExchangeRequest struct {
	SubjectExchange
	ClientID string
	Audience string
	// RequestedTokenType is the RFC 8693 requested_token_type. A nonempty
	// value must match the result's issued_token_type.
	RequestedTokenType string
}

// BrokeredExchange implements the RFC 8693 flow where the resulting token is
// issued by a downstream issuer reached through the configured Exchanger. The
// subject token (and, when present, the actor token for the §4.1 delegation
// chain) are validated against the server's trusted issuers before the Exchanger
// is invoked; the verified actor identity is forwarded to it.
//
// Policy: an Exchanger must be configured (ErrInvalidTarget otherwise) and the
// audience must be in the client's Config.TokenExchangeClientAudiences allowlist.
// Self-delegation (actor equal to subject) is dropped to a no-op, and no refresh
// token is issued; the result's expiry is the downstream token's and clients
// re-exchange. Every outcome is audited with the client ID, subject, requested
// audience, granted scope, and the deterministic cross-hop session ID derived
// from the subject token's bytes (it is computed before validation), so broker
// audit lines correlate with downstream MCP audit lines for the same token
// under the default bearer session identity.
func (s *Server) BrokeredExchange(ctx context.Context, req BrokeredExchangeRequest) (*TokenExchangeResult, error) {
	sessionID := s.bearerSessionID(req.Subject.Token)

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
	if req.Resource != "" {
		if _, err := parseResourceURI(req.Resource); err != nil {
			s.auditExchangeFailure(ctx, req.ClientID, req.Audience, sessionID, "token_exchange_resource_invalid", map[string]any{logKeySeverity: severityWarning})
			return nil, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
		}
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
	if identity.ConfirmationJKT != "" {
		s.auditExchangeFailure(ctx, req.ClientID, req.Audience, sessionID, "token_exchange_subject_key_mismatch", map[string]any{
			claimSub: identity.Subject, logKeySeverity: severityWarning,
		})
		return nil, ErrSubjectKeyMismatch
	}

	actor, err := s.resolveExchangeActor(ctx, req.Actor, identity, auditCtx)
	if err != nil {
		return nil, err
	}

	return s.dispatchDownstreamExchange(ctx, req, sessionID, identity, actor)
}

// dispatchDownstreamExchange calls the Exchanger and emits the outcome audit
// event. identity and actorIdentity must already be validated before calling. A
// nil actorIdentity (no delegation, or self-delegation stripped to a no-op) clears
// the forwarded actor token so the three actor fields on ExchangerRequest stay
// consistent.
func (s *Server) dispatchDownstreamExchange(
	ctx context.Context,
	request BrokeredExchangeRequest, sessionID string,
	identity, actorIdentity *SubjectIdentity,
) (*TokenExchangeResult, error) {
	if actorIdentity == nil {
		request.Actor = TypedToken{}
	}
	result, err := s.exchanger.Exchange(ctx, &ExchangerRequest{
		Audience:           request.Audience,
		Resource:           request.Resource,
		Scope:              request.Scope,
		ClientID:           request.ClientID,
		RequestedTokenType: request.RequestedTokenType,
		Subject:            identity,
		SubjectToken:       request.Subject.Token,
		SubjectTokenType:   request.Subject.Type,
		ActorToken:         request.Actor.Token,
		ActorTokenType:     request.Actor.Type,
		Actor:              actorIdentity,
	})
	if err != nil {
		reason := "token_exchange_downstream_failed"
		if errors.Is(err, ErrProviderUnavailable) {
			reason = auditReasonProviderUnavailable
			s.Logger.Warn("Identity provider temporarily unavailable during brokered token exchange",
				paramClientID, request.ClientID, paramAudience, request.Audience, logKeyError, err.Error())
		} else {
			s.Logger.Debug("brokered token exchange: downstream exchange failed",
				paramClientID, request.ClientID, paramAudience, request.Audience, logKeyError, err)
		}
		s.auditExchangeFailure(ctx, request.ClientID, request.Audience, sessionID, reason, map[string]any{
			claimSub:    identity.Subject,
			logKeyError: err.Error(),
		})
		if errors.Is(err, ErrInvalidTarget) {
			return nil, err
		}
		return nil, fmt.Errorf("downstream exchange: %w", err)
	}
	if result == nil || result.AccessToken == "" {
		s.auditExchangeFailure(ctx, request.ClientID, request.Audience, sessionID, "token_exchange_downstream_empty_token", map[string]any{
			claimSub: identity.Subject,
		})
		return nil, fmt.Errorf("downstream exchange returned no token")
	}

	issuedTokenType := result.IssuedTokenType
	if issuedTokenType == "" {
		issuedTokenType = SubjectTokenTypeAccessToken
	}
	if request.RequestedTokenType != "" && issuedTokenType != request.RequestedTokenType {
		s.auditExchangeFailure(ctx, request.ClientID, request.Audience, sessionID, "token_exchange_issued_type_mismatch", map[string]any{
			claimSub:               identity.Subject,
			logKeySeverity:         severityWarning,
			"requested_token_type": request.RequestedTokenType, "issued_token_type": issuedTokenType,
		})
		return nil, ErrIssuedTokenTypeMismatch
	}

	s.Logger.Debug("brokered token exchange: issued downstream token",
		paramClientID, request.ClientID, "subject_iss", identity.Issuer,
		paramAudience, request.Audience, paramScope, result.Scope, "exp", result.ExpiresAt,
		logKeySessionID, sessionID)

	successDetails := map[string]any{
		paramGrantType:       GrantTypeTokenExchange,
		logKeyExchange:       exchangeBrokered,
		"subject_token_type": request.Subject.Type,
		paramAudience:        request.Audience,
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
		ClientID: request.ClientID,
		Details:  successDetails,
	})

	tokenType := "N_A"
	if issuedTokenType == SubjectTokenTypeAccessToken {
		tokenType = tokenTypeBearer
	}
	return &TokenExchangeResult{
		AccessToken:     result.AccessToken,
		TokenType:       tokenType,
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
