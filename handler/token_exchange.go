package handler

import (
	"errors"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func (h *Handler) handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()
	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_exchange")
	defer endSpan()

	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	actorToken := r.Form.Get("actor_token")
	actorTokenType := r.Form.Get("actor_token_type")
	resource := r.Form.Get("resource")
	audience := r.Form.Get("audience")
	scope := r.Form.Get("scope")

	if subjectToken == "" {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_subject_token_missing",
			"token exchange: subject_token missing")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "subject_token missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "subject_token is required", http.StatusBadRequest)
		return
	}
	if subjectTokenType == "" {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_subject_token_type_missing",
			"token exchange: subject_token_type missing")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "subject_token_type missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "subject_token_type is required", http.StatusBadRequest)
		return
	}
	if actorToken != "" && actorTokenType == "" {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_actor_token_type_missing",
			"token exchange: actor_token_type missing")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "actor_token_type missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "actor_token_type is required when actor_token is present", http.StatusBadRequest)
		return
	}
	if actorToken == "" && r.Form.Has("actor_token_type") {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_actor_token_missing",
			"token exchange: actor_token_type without actor_token")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "actor_token missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "actor_token_type requires actor_token", http.StatusBadRequest)
		return
	}
	if requestedType := r.Form.Get("requested_token_type"); requestedType != "" && requestedType != server.SubjectTokenTypeAccessToken {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_requested_type_unsupported",
			"token exchange: requested_token_type unsupported")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported requested_token_type")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "only access_token is supported as requested_token_type", http.StatusBadRequest)
		return
	}
	// An audience parameter selects the brokered flow (RFC 8693 audience →
	// downstream token via the host Exchanger). Without it, the self-issued flow
	// signs a JWT whose aud is the RFC 8707 resource, defaulting to the server's
	// resource identifier when none is supplied.
	if audience != "" {
		h.handleBrokeredTokenExchange(w, r, clientIP, subjectToken, subjectTokenType, actorToken, actorTokenType, audience, resource, scope, startTime, span)
		return
	}

	clientID, ok := h.authenticateTokenExchangeClient(w, r, clientIP, startTime, span)
	if !ok {
		return
	}

	dpopJKT, err := h.extractDPoPJKT(r)
	if err != nil {
		h.writeTokenDPoPError(w, r, server.GrantTypeTokenExchange, clientID, span, startTime, err)
		return
	}

	result, err := h.server.SelfIssuedExchange(r.Context(), server.SelfIssuedExchangeRequest{
		SubjectExchange: server.SubjectExchange{
			Subject:  server.TypedToken{Token: subjectToken, Type: subjectTokenType},
			Actor:    server.TypedToken{Token: actorToken, Type: actorTokenType},
			Resource: resource,
			Scope:    scope,
		},
		ClientID: clientID,
		DPoPJKT:  dpopJKT,
	})
	if err != nil {
		h.handleTokenExchangeError(w, r, err, clientIP, startTime, span)
		return
	}

	h.logger.Debug("token exchange successful", "client_id", clientID, "ip", clientIP, "scope", result.Scope)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	h.writeTokenExchangeResponse(w, result)
}

// authenticateTokenExchangeClient enforces this server's confidential-client
// policy for RFC 8693 exchanges using the registered authentication method.
func (h *Handler) authenticateTokenExchangeClient(w http.ResponseWriter, r *http.Request, clientIP string, startTime time.Time, span trace.Span) (string, bool) {
	if !hasClientIdentificationOrCredentials(r) {
		h.server.Auditor.LogEvent(r.Context(), security.Event{
			Type: security.EventAuthFailure, IPAddress: clientIP,
			Details: map[string]any{
				"reason": "token_exchange_client_required", auditDetailSeverity: "warning",
				"grant_type": server.GrantTypeTokenExchange,
			},
		})
		h.writeClientAuthenticationError(w, r, server.GrantTypeTokenExchange, span, startTime,
			oauth.NewError(constants.ErrorCodeInvalidClient, "client authentication is required for token exchange", http.StatusBadRequest))
		return "", false
	}
	client, err := h.authenticateRegisteredClient(r, r.Form.Get("client_id"), clientIP)
	if err != nil {
		h.writeClientAuthenticationError(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return "", false
	}
	instrumentation.SetSpanAttributes(span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrGrantType, server.GrantTypeTokenExchange),
	)
	if !client.IsConfidential() {
		reason := "token_exchange_public_client"
		if r.Form.Get("audience") != "" {
			reason = "token_exchange_public_client_audience"
		}
		h.server.Auditor.LogEvent(r.Context(), security.Event{
			Type: security.EventAuthFailure, ClientID: client.ClientID, IPAddress: clientIP,
			Details: map[string]any{
				"reason": reason, auditDetailSeverity: "warning", "grant_type": server.GrantTypeTokenExchange,
			},
		})
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeUnauthorizedClient)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "public client not allowed")
		h.writeError(w, constants.ErrorCodeUnauthorizedClient,
			"token exchange requires a confidential client", http.StatusBadRequest)
		return "", false
	}
	return client.ClientID, true
}

func hasClientIdentificationOrCredentials(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" ||
		r.PostForm.Has("client_id") || r.PostForm.Has("client_secret") ||
		r.PostForm.Has("client_assertion") || r.PostForm.Has("client_assertion_type")
}

// handleBrokeredTokenExchange serves RFC 8693 requests that carry an audience
// parameter. Client authentication is mandatory (the per-client audience
// allowlist is meaningless for a spoofable client_id, so public clients are
// rejected). DPoP binding is not supported on this path: the issued token is
// issued by a downstream issuer that never saw the proof.
// actorToken and actorTokenType are RFC 8693 delegation params; both may be
// empty when no actor_token was presented.
func (h *Handler) handleBrokeredTokenExchange(
	w http.ResponseWriter, r *http.Request,
	clientIP, subjectToken, subjectTokenType, actorToken, actorTokenType, audience, resource, scope string,
	startTime time.Time, span trace.Span,
) {
	clientID, ok := h.authenticateTokenExchangeClient(w, r, clientIP, startTime, span)
	if !ok {
		return
	}

	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.token_exchange.audience", audience),
	)

	if r.Header.Get("DPoP") != "" {
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "dpop not supported for brokered exchange")
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"DPoP binding is not supported for brokered token exchange", http.StatusBadRequest)
		return
	}

	result, err := h.server.BrokeredExchange(r.Context(), server.BrokeredExchangeRequest{
		SubjectExchange: server.SubjectExchange{
			Subject:  server.TypedToken{Token: subjectToken, Type: subjectTokenType},
			Actor:    server.TypedToken{Token: actorToken, Type: actorTokenType},
			Resource: resource,
			Scope:    scope,
		},
		ClientID: clientID,
		Audience: audience,
	})
	if err != nil {
		h.handleBrokeredTokenExchangeError(w, r, err, clientID, clientIP, audience, startTime, span)
		return
	}

	h.logger.Debug("brokered token exchange successful",
		"client_id", clientID, "audience", audience, "ip", clientIP, "scope", result.Scope)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	h.writeTokenExchangeResponse(w, result)
}

func (h *Handler) handleBrokeredTokenExchangeError(
	w http.ResponseWriter, r *http.Request, err error,
	clientID, clientIP, audience string,
	startTime time.Time, span trace.Span,
) {
	if errors.Is(err, server.ErrStorageUnavailable) {
		h.writeTokenStorageUnavailable(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return
	}
	if errors.Is(err, server.ErrProviderUnavailable) {
		h.writeTokenProviderUnavailable(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return
	}
	instrumentation.RecordError(span, err)

	var unsupported *server.TokenExchangeUnsupportedTypeError
	switch {
	case errors.Is(err, server.ErrExchangeRateLimited):
		h.writeExchangeRateLimited(w, r, startTime, span)
	case errors.Is(err, server.ErrInvalidTarget):
		h.logger.Debug("brokered token exchange: invalid target",
			"client_id", clientID, "audience", audience, "ip", clientIP)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidTarget)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "invalid target")
		h.writeError(w, constants.ErrorCodeInvalidTarget,
			"the requested audience cannot be served", http.StatusBadRequest)
	case errors.As(err, &unsupported):
		h.logger.Debug("brokered token exchange: unsupported "+unsupported.Role()+"_token_type",
			"type", unsupported.TokenType(), "client_id", clientID, "ip", clientIP)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported "+unsupported.Role()+"_token_type")
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"no validator registered for "+unsupported.Role()+"_token_type "+unsupported.TokenType(), http.StatusBadRequest)
	default:
		h.logger.Debug("brokered token exchange failed",
			"client_id", clientID, "audience", audience, "ip", clientIP, paramError, err)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "brokered exchange failed")
		// SECURITY: don't leak downstream-exchange detail to the client.
		h.writeError(w, constants.ErrorCodeInvalidRequest, "subject token invalid or rejected", http.StatusBadRequest)
	}
}

// writeExchangeRateLimited renders the 429 response for a token-exchange request
// rejected by the per-session issuance limiter (server.ErrExchangeRateLimited).
// Both exchange methods enforce the issuance limiter in-process.
func (h *Handler) writeExchangeRateLimited(w http.ResponseWriter, r *http.Request, startTime time.Time, span trace.Span) {
	retryAfter := defaultRetryAfterSeconds
	if h.server.UserRateLimiter != nil {
		retryAfter = retryAfterSecondsForRate(h.server.UserRateLimiter.Rate())
	}
	h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeRateLimitExceeded)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusTooManyRequests, startTime)
	instrumentation.SetSpanError(span, "token exchange rate limited")
	h.writeUserRateLimitError(w, retryAfter)
}

func (h *Handler) handleTokenExchangeError(
	w http.ResponseWriter, r *http.Request, err error,
	clientIP string, startTime time.Time, span trace.Span,
) {
	if errors.Is(err, server.ErrStorageUnavailable) {
		h.writeTokenStorageUnavailable(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return
	}
	if errors.Is(err, server.ErrProviderUnavailable) {
		h.writeTokenProviderUnavailable(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return
	}
	if errors.Is(err, server.ErrExchangeRateLimited) {
		h.writeExchangeRateLimited(w, r, startTime, span)
		return
	}
	if errors.Is(err, server.ErrExchangeClientRequired) {
		h.writeClientAuthenticationError(w, r, server.GrantTypeTokenExchange, span, startTime, err)
		return
	}
	if errors.Is(err, server.ErrInvalidTarget) {
		h.logger.Debug("token exchange: invalid target", "ip", clientIP)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidTarget)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "invalid target")
		h.writeError(w, constants.ErrorCodeInvalidTarget,
			"the requested resource cannot be served", http.StatusBadRequest)
		return
	}
	if errors.Is(err, server.ErrInvalidScope) {
		h.logger.Debug("token exchange: invalid scope", "ip", clientIP)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidScope)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "invalid scope")
		h.writeError(w, constants.ErrorCodeInvalidScope,
			"the requested scope cannot be granted", http.StatusBadRequest)
		return
	}
	var unsupported *server.TokenExchangeUnsupportedTypeError
	if errors.As(err, &unsupported) {
		h.logger.Debug("token exchange: unsupported "+unsupported.Role()+"_token_type",
			"type", unsupported.TokenType(), "ip", clientIP)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported "+unsupported.Role()+"_token_type")
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"no validator registered for "+unsupported.Role()+"_token_type "+unsupported.TokenType(),
			http.StatusBadRequest)
		return
	}
	h.logger.Debug("token exchange failed", "ip", clientIP, paramError, err)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.SetSpanError(span, "token exchange failed")
	h.writeError(w, constants.ErrorCodeInvalidRequest, "subject token invalid or rejected", http.StatusBadRequest)
}

func (h *Handler) writeTokenExchangeResponse(w http.ResponseWriter, result *server.TokenExchangeResult) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := max(int64(time.Until(result.ExpiresAt).Seconds()), 0)
	tokenType := result.TokenType
	if tokenType == "" {
		tokenType = tokenTypeBearer
	}

	response := map[string]any{
		"access_token":      result.AccessToken,
		"issued_token_type": result.IssuedTokenType,
		"token_type":        tokenType,
		"expires_in":        expiresIn,
	}
	if result.Scope != "" {
		response["scope"] = result.Scope
	}

	w.Header().Set("Content-Type", "application/json")
	h.writeJSON(w, response)
}
