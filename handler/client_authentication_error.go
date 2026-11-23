package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http/httpguts"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func (h *Handler) writeClientAuthenticationError(w http.ResponseWriter, r *http.Request, grant string, span trace.Span, started time.Time, err error) {
	h.writeEndpointClientAuthenticationError(w, r, endpointToken, grant, span, started, err)
}

func (h *Handler) auditMissingRefreshAuthentication(ctx context.Context, clientID, clientIP string) {
	h.server.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, ClientID: clientID,
		Details: map[string]any{
			auditDetailSeverity: "high", fieldClientType: "confidential", "auth_missing": true,
			"endpoint": grantTypeRefreshToken, "ip": clientIP, "oauth_spec": "OAuth 2.1 Section 6",
		},
	})
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
	if status == http.StatusUnauthorized && grant == server.GrantTypeTokenExchange && authorization == "" {
		status = http.StatusBadRequest
	}
	if status == http.StatusUnauthorized {
		if challenge := clientAuthenticationChallenge(authorization); challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
	}
	if grant != "" {
		h.recordTokenFailure(r.Context(), grant, code)
	}
	h.recordHTTPMetrics(r.Context(), endpoint, http.MethodPost, status, started)
	h.writeError(w, code, description, status)
}

func clientAuthenticationChallenge(authorization string) string {
	scheme, _, _ := strings.Cut(authorization, " ")
	if strings.EqualFold(scheme, "Basic") {
		return `Basic realm="oauth"`
	}
	if !httpguts.ValidHeaderFieldName(scheme) {
		return ""
	}
	return scheme + ` realm="oauth"`
}
