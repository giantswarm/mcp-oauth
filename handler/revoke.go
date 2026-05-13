package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
)

// authenticateRevocationClient resolves the client for /revoke. It enforces
// the RFC 6749 §2.3.1 Basic / form client_id agreement, validates Basic-Auth
// credentials when supplied, and returns (resolvedClientID, authenticated, ok).
// ok=false means the HTTP response has already been written; the caller must
// return immediately. RFC 7009 allows unauthenticated revocation for public
// clients, so a missing Basic header is not itself an error.
func (h *Handler) authenticateRevocationClient(w http.ResponseWriter, r *http.Request, formClientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, bool) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)

	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, formClientID, clientIP, endpointRevoke, "", span, startTime) {
		return "", false, false
	}

	if basicClientID == "" {
		return formClientID, false, true
	}

	if err := h.server.ValidateClientCredentials(r.Context(), basicClientID, basicClientSecret); err != nil {
		h.logger.Warn("Client authentication failed for revocation", "client_id", basicClientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(r.Context(), "", basicClientID, clientIP, "revocation_auth_failed")
		}
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		h.writeError(w, oauth.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		return "", false, false
	}
	return basicClientID, true, true
}

// ServeTokenRevocation handles the RFC 7009 token revocation endpoint
func (h *Handler) ServeTokenRevocation(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_revocation")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointRevoke, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "request body too large")
			h.writeError(w, oauth.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "parse form failed")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	clientID := r.Form.Get("client_id")

	if token == "" {
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "token missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "token is required", http.StatusBadRequest)
		return
	}

	resolvedClientID, clientAuthenticated, ok := h.authenticateRevocationClient(w, r, clientID, clientIP, startTime, span)
	if !ok {
		return
	}
	clientID = resolvedClientID

	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))

	// Post-auth rate limit for authenticated clients, keyed by client_id.
	if clientAuthenticated && h.checkUserRateLimit(w, r, clientID, clientIP) {
		h.recordRateLimitReject(r.Context(), span, endpointRevoke, http.MethodPost, startTime)
		return
	}

	// Revoke token
	if err := h.server.RevokeToken(r.Context(), token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		instrumentation.RecordError(span, err)
		// Per RFC 7009, don't fail the request even if revocation failed
	}
	// Per RFC 7009, return 200 even if revocation fails

	// Record token revoked metric
	h.recordTokenRevoked(r.Context(), clientID)

	h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeTokenIntrospection handles the RFC 7662 token introspection endpoint
// This allows resource servers to validate access tokens
// Security: Requires client authentication to prevent token scanning attacks
func (h *Handler) ServeTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.introspection")
	defer endSpan()

	if r.Method != http.MethodPost {
		instrumentation.SetSpanError(span, "method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointIntrospect, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			instrumentation.SetSpanError(span, "request body too large")
			h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, oauth.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		instrumentation.SetSpanError(span, "failed to parse request")
		h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusBadRequest, startTime)
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		instrumentation.SetSpanError(span, "token parameter missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
		return
	}

	tokenType := r.Form.Get("token_type_hint")
	if tokenType != "" && span != nil {
		instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrTokenType, tokenType))
	}

	// RFC 6749 §2.3.1: enforce Basic / form client_id agreement before the
	// per-endpoint authenticate function runs, so /introspect cannot become a
	// silent-override bypass for the same rule the token / refresh / revoke
	// paths enforce.
	basicClientID, _ := h.parseBasicAuth(r)
	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, r.Form.Get("client_id"), clientIP, endpointIntrospect, "", span, startTime) {
		return
	}

	clientID, err := h.authenticateIntrospectionClient(r, clientIP)
	if err != nil {
		instrumentation.SetSpanError(span, "client authentication failed")
		h.writeError(w, oauth.ErrorCodeInvalidClient, err.Error(), http.StatusUnauthorized)
		return
	}

	if span != nil {
		instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))
	}

	response := h.server.IntrospectToken(r.Context(), token, clientID)
	if active, _ := response["active"].(bool); !active {
		h.logger.Debug("Token introspection inactive", "ip", clientIP, "client_id", clientID)
	}

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
	h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
}

// authenticateIntrospectionClient validates client credentials for token introspection.
// Returns the client ID on success, or an error if authentication fails.
func (h *Handler) authenticateIntrospectionClient(r *http.Request, clientIP string) (string, error) {
	ctx := r.Context()
	authClientID, authClientSecret := h.parseBasicAuth(r)

	if authClientID != "" {
		if err := h.server.ValidateClientCredentials(ctx, authClientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for introspection", "client_id", authClientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure(ctx, "", authClientID, clientIP, "introspection_auth_failed")
			}
			return "", fmt.Errorf("client authentication failed")
		}
		return authClientID, nil
	}

	// No Basic Auth - check for client_id in form (but we still reject without credentials)
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		h.logger.Warn("Token introspection rejected: missing client authentication", "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", "", clientIP, "introspection_missing_auth")
		}
		return "", fmt.Errorf("client authentication required for token introspection")
	}

	h.logger.Warn("Token introspection rejected: client_id without credentials", "client_id", clientID, "ip", clientIP)
	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "introspection_missing_credentials")
	}
	return "", fmt.Errorf("client authentication required for token introspection")
}

// recordTokenRevoked records when a token is revoked.
func (h *Handler) recordTokenRevoked(ctx context.Context, clientID string) {
	h.server.Instrumentation.Metrics().RecordTokenRevocation(ctx, clientID)
}
