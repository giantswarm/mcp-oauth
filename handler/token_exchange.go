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
	// An audience parameter selects the brokered flow (RFC 8693 audience →
	// downstream token via the host Exchanger). Without it, the self-issued flow
	// signs a JWT whose aud is the RFC 8707 resource, defaulting to the server's
	// resource identifier when none is supplied.
	if audience != "" {
		h.handleBrokeredTokenExchange(w, r, clientIP, subjectToken, subjectTokenType, actorToken, actorTokenType, audience, resource, scope, startTime, span)
		return
	}

	dpopJKT, err := h.extractDPoPJKT(r)
	if err != nil {
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "dpop proof invalid")
		if errors.Is(err, server.ErrDPoPNonceInvalid) {
			if provider := h.server.DPoPNonceProvider(); provider != nil {
				w.Header().Set("DPoP-Nonce", provider.Nonce(r.Context()))
			}
			h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_dpop_nonce_required",
				"token exchange: dpop nonce required")
			h.writeError(w, constants.ErrorCodeUseDPoPNonce, "A DPoP nonce is required.", http.StatusBadRequest)
			return
		}
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_dpop_proof_invalid",
			"token exchange: dpop proof invalid")
		h.writeError(w, constants.ErrorCodeInvalidDPoPProof, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.server.SelfIssuedExchange(r.Context(), server.SelfIssuedExchangeRequest{
		SubjectExchange: server.SubjectExchange{
			Subject:  server.TypedToken{Token: subjectToken, Type: subjectTokenType},
			Actor:    server.TypedToken{Token: actorToken, Type: actorTokenType},
			Resource: resource,
			Scope:    scope,
		},
		DPoPJKT: dpopJKT,
	})
	if err != nil {
		h.handleTokenExchangeError(w, r, err, clientIP, startTime, span)
		return
	}

	h.logger.Debug("token exchange successful", "ip", clientIP, "scope", result.Scope)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	h.writeTokenExchangeResponse(w, result)
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
	client, err := h.authenticateClient(r, r.Form.Get("client_id"), clientIP)
	if err != nil {
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		var oauthErr *oauth.Error
		if errors.As(err, &oauthErr) {
			h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, oauthErr.Code)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, oauthErr.Status, startTime)
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidClient)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
			h.writeError(w, constants.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	instrumentation.SetSpanAttributes(span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrGrantType, server.GrantTypeTokenExchange),
		attribute.String("oauth.token_exchange.audience", audience),
	)

	if !client.IsConfidential() {
		h.logAuthFailure(r.Context(), client.ClientID, clientIP, "token_exchange_public_client_audience",
			"brokered token exchange rejected: public client requested audience")
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeUnauthorizedClient)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "public client not allowed")
		h.writeError(w, constants.ErrorCodeUnauthorizedClient,
			"brokered token exchange requires a confidential client", http.StatusBadRequest)
		return
	}

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
		ClientID: client.ClientID,
		Audience: audience,
	})
	if err != nil {
		h.handleBrokeredTokenExchangeError(w, r, err, client.ClientID, clientIP, audience, startTime, span)
		return
	}

	h.logger.Debug("brokered token exchange successful",
		"client_id", client.ClientID, "audience", audience, "ip", clientIP, "scope", result.Scope)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	h.writeTokenExchangeResponse(w, result)
}

func (h *Handler) handleBrokeredTokenExchangeError(
	w http.ResponseWriter, r *http.Request, err error,
	clientID, clientIP, audience string,
	startTime time.Time, span trace.Span,
) {
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
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeUnsupportedGrantType)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported "+unsupported.Role()+"_token_type")
		h.writeError(w, constants.ErrorCodeUnsupportedGrantType,
			"no validator registered for "+unsupported.Role()+"_token_type "+unsupported.TokenType(), http.StatusBadRequest)
	default:
		h.logger.Debug("brokered token exchange failed",
			"client_id", clientID, "audience", audience, "ip", clientIP, "error", err)
		h.recordTokenFailure(r.Context(), server.GrantTypeTokenExchange, constants.ErrorCodeInvalidGrant)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "brokered exchange failed")
		// SECURITY: don't leak downstream-exchange detail to the client.
		h.writeError(w, constants.ErrorCodeInvalidGrant, "subject token invalid or rejected", http.StatusBadRequest)
	}
}

// writeExchangeRateLimited renders the 429 response for a token-exchange request
// rejected by the per-session issuance limiter (server.ErrExchangeRateLimited).
// Both the self-issued and brokered methods enforce that limiter in-process, so
// the sentinel is reachable on either path; without this mapping it falls through
// to a misleading 400 invalid_grant ("subject token invalid or rejected").
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
	if errors.Is(err, server.ErrExchangeRateLimited) {
		h.writeExchangeRateLimited(w, r, startTime, span)
		return
	}
	var unsupported *server.TokenExchangeUnsupportedTypeError
	if errors.As(err, &unsupported) {
		h.logger.Debug("token exchange: unsupported subject_token_type",
			"type", unsupported.TokenType(), "ip", clientIP)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported subject_token_type")
		h.writeError(w, constants.ErrorCodeUnsupportedGrantType,
			"no validator registered for subject_token_type "+unsupported.TokenType(),
			http.StatusBadRequest)
		return
	}
	h.logger.Debug("token exchange failed", "ip", clientIP, "error", err)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.SetSpanError(span, "token exchange failed")
	h.writeError(w, constants.ErrorCodeInvalidGrant, "subject token invalid or rejected", http.StatusBadRequest)
}

func (h *Handler) writeTokenExchangeResponse(w http.ResponseWriter, result *server.TokenExchangeResult) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := max(int64(time.Until(result.ExpiresAt).Seconds()), 0)

	response := map[string]any{
		"access_token":      result.AccessToken,
		"issued_token_type": result.IssuedTokenType,
		"token_type":        tokenTypeBearer,
		"expires_in":        expiresIn,
	}
	if result.Scope != "" {
		response["scope"] = result.Scope
	}

	w.Header().Set("Content-Type", "application/json")
	h.writeJSON(w, response)
}
