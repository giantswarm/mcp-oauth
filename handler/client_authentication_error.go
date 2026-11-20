package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/server"
)

func (h *Handler) writeClientAuthenticationError(w http.ResponseWriter, r *http.Request, grant string, span trace.Span, started time.Time, err error) {
	h.writeEndpointClientAuthenticationError(w, r, endpointToken, grant, span, started, err)
}

func (h *Handler) writeEndpointClientAuthenticationError(w http.ResponseWriter, r *http.Request, endpoint, grant string, span trace.Span, started time.Time, err error) {
	if errors.Is(err, server.ErrStorageUnavailable) {
		if grant != "" {
			h.recordTokenFailure(r.Context(), grant, constants.ErrorCodeTemporarilyUnavailable)
		}
		h.writeStorageUnavailable(w, r, endpoint, http.MethodPost, span, started, err)
		return
	}
	instrumentation.RecordError(span, err)
	instrumentation.SetSpanError(span, "client authentication failed")
	code, description, status := constants.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized
	var oauthError *oauth.Error
	if errors.As(err, &oauthError) {
		code, description, status = oauthError.Code, oauthError.Description, oauthError.Status
	}
	authorization := r.Header.Get("Authorization")
	if status == http.StatusUnauthorized && (strings.EqualFold(authorization, "Basic") || strings.HasPrefix(strings.ToLower(authorization), "basic ")) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	if grant != "" {
		h.recordTokenFailure(r.Context(), grant, code)
	}
	h.recordHTTPMetrics(r.Context(), endpoint, http.MethodPost, status, started)
	h.writeError(w, code, description, status)
}
