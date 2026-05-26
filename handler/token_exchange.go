package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
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
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "subject_token missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "subject_token is required", http.StatusBadRequest)
		return
	}
	if subjectTokenType == "" {
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "subject_token_type missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "subject_token_type is required", http.StatusBadRequest)
		return
	}
	if resource == "" {
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "resource missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "resource is required (RFC 8707)", http.StatusBadRequest)
		return
	}

	result, err := h.server.ExchangeSubjectToken(r.Context(), subjectToken, subjectTokenType, resource, scope)
	if err != nil {
		h.handleTokenExchangeError(w, r, err, clientIP, startTime, span)
		return
	}

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
		h.writeError(w, oauth.ErrorCodeUnsupportedGrantType,
			"no validator registered for subject_token_type "+unsupported.TokenType(),
			http.StatusBadRequest)
		return
	}
	h.logger.Debug("token exchange failed", "ip", clientIP, "error", err)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.SetSpanError(span, "token exchange failed")
	h.writeError(w, oauth.ErrorCodeInvalidGrant, "subject token invalid or rejected", http.StatusBadRequest)
}

func (h *Handler) writeTokenExchangeResponse(w http.ResponseWriter, result *server.TokenExchangeResult) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := int64(time.Until(result.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

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
	_ = json.NewEncoder(w).Encode(response)
}
