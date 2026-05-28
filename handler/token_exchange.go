package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func (h *Handler) handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()
	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_exchange_m2m")
	defer endSpan()

	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	resource := r.Form.Get("resource")
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
	if resource == "" {
		h.logAuthFailure(r.Context(), "", clientIP, "token_exchange_resource_missing",
			"token exchange: resource missing")
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "resource missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "resource is required (RFC 8707)", http.StatusBadRequest)
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

	result, err := h.server.ExchangeSubjectToken(r.Context(), subjectToken, subjectTokenType, resource, scope, dpopJKT)
	if err != nil {
		h.handleTokenExchangeError(w, r, err, clientIP, startTime, span)
		return
	}

	h.logger.Debug("token exchange successful", "ip", clientIP, "scope", result.Scope)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	h.writeTokenExchangeResponse(w, result)
}

func (h *Handler) handleTokenExchangeError(
	w http.ResponseWriter, r *http.Request, err error,
	clientIP string, startTime time.Time, span trace.Span,
) {
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Warn("Failed to encode token exchange response", "error", err)
	}
}
