package handler

import (
	"context"
	_ "embed"
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
	"github.com/giantswarm/mcp-oauth/storage"
)

// authenticateRevocationClient resolves the client for /revoke. It enforces
// the RFC 6749 §2.3.1 Basic / form client_id agreement, validates Basic-Auth
// credentials when supplied, and returns (resolvedClientID, authenticated, ok).
// ok=false means the HTTP response has already been written; the caller must
// return immediately. RFC 7009 allows unauthenticated revocation for public
// clients, so a missing Basic header is not itself an error.
func (h *Handler) authenticateRevocationClient(w http.ResponseWriter, r *http.Request, formClientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, bool) {
	if err := validateClientCredentialShape(r); err != nil {
		h.logAuthFailure(r.Context(), formClientID, clientIP, "revocation_invalid_credentials", "Revocation client credentials rejected")
		h.writeEndpointClientAuthenticationError(w, r, endpointRevoke, "", span, startTime, err)
		return "", false, false
	}
	basicClientID, _ := h.parseBasicAuth(r)

	if !hasClientAssertion(r) && h.rejectBasicFormClientIDMismatch(w, r, basicClientID, formClientID, clientIP, endpointRevoke, "", span, startTime) {
		return "", false, false
	}

	if formClientID == "" && basicClientID == "" && !hasClientAssertion(r) {
		h.logAuthFailure(r.Context(), "", clientIP, "revocation_missing_auth", "Revocation client identification missing")
		h.writeEndpointClientAuthenticationError(w, r, endpointRevoke, "", span, startTime, oauth.ErrInvalidClient("Client identification required"))
		return "", false, false
	}
	client, err := h.authenticateClientWithLookup(r, formClientID, clientIP, func(ctx context.Context, clientID string) (*storage.Client, error) {
		return h.server.GetRevocationClient(ctx, clientID)
	})
	if err != nil {
		h.writeEndpointClientAuthenticationError(w, r, endpointRevoke, "", span, startTime, err)
		return "", false, false
	}
	return client.ClientID, client.IsConfidential(), true
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
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "parse form failed")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	clientID := r.Form.Get("client_id")

	if token == "" {
		h.failRequest(w, r, span, endpointRevoke, http.MethodPost, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "token is required", startTime)
		return
	}

	resolvedClientID, clientAuthenticated, ok := h.authenticateRevocationClient(w, r, clientID, clientIP, startTime, span)
	if !ok {
		return
	}
	clientID = resolvedClientID

	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))

	// Post-auth rate limit for authenticated clients, keyed by client_id.
	if clientAuthenticated {
		if retryAfter, limited := h.checkUserRateLimited(r.Context(), clientID, clientIP); limited {
			h.writeUserRateLimitError(w, retryAfter)
			h.recordRateLimitReject(r.Context(), span, endpointRevoke, http.MethodPost, startTime)
			return
		}
	}

	// Revoke token
	if err := h.server.RevokeToken(r.Context(), token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, paramError, err)
		instrumentation.RecordError(span, err)
		h.writeStorageUnavailable(w, r, endpointRevoke, http.MethodPost, span, startTime, err)
		return
	}
	// RFC 7009 returns success for unknown and already invalid tokens.

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
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		instrumentation.SetSpanError(span, "failed to parse request")
		h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusBadRequest, startTime)
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		instrumentation.SetSpanError(span, "token parameter missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
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
	if !hasClientAssertion(r) && h.rejectBasicFormClientIDMismatch(w, r, basicClientID, r.Form.Get("client_id"), clientIP, endpointIntrospect, "", span, startTime) {
		return
	}

	clientID, err := h.authenticateIntrospectionClient(r, clientIP)
	if err != nil {
		instrumentation.SetSpanError(span, "client authentication failed")
		h.writeEndpointClientAuthenticationError(w, r, endpointIntrospect, "", span, startTime, err)
		return
	}

	if span != nil {
		instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))
	}

	response, err := h.server.IntrospectToken(r.Context(), token, clientID)
	if err != nil {
		h.writeIntrospectionError(w, r, span, startTime, err)
		return
	}
	if active, _ := response["active"].(bool); !active {
		h.logger.Debug("Token introspection inactive", "ip", clientIP, "client_id", clientID)
	}

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	h.writeJSON(w, response)
	h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
}

// writeIntrospectionError answers an IntrospectToken error. A store or an
// identity provider that did not answer leaves the token neither active nor
// inactive, so it is 503: {"active": false} would
// tell the resource server the token is dead.
func (h *Handler) writeIntrospectionError(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, err error) {
	switch {
	case errors.Is(err, server.ErrStorageUnavailable):
		h.writeStorageUnavailable(w, r, endpointIntrospect, http.MethodPost, span, startTime, err)
	case errors.Is(err, server.ErrProviderUnavailable):
		h.writeProviderUnavailable(w, r, endpointIntrospect, http.MethodPost, span, startTime, err)
	default:
		h.failRequest(w, r, span, endpointIntrospect, http.MethodPost, http.StatusInternalServerError,
			constants.ErrorCodeServerError, "Token introspection failed", startTime)
	}
}

// authenticateIntrospectionClient validates client credentials for token introspection.
// Returns the client ID on success, or an error if authentication fails.
func (h *Handler) authenticateIntrospectionClient(r *http.Request, clientIP string) (string, error) {
	basicClientID, _ := h.parseBasicAuth(r)
	if r.Form.Get("client_id") == "" && basicClientID == "" && !hasClientAssertion(r) {
		h.logAuthFailure(r.Context(), "", clientIP, "introspection_missing_auth", "Introspection client authentication missing")
		return "", oauth.ErrInvalidClient("Client authentication required for token introspection")
	}
	client, err := h.authenticateRegisteredClient(r, r.Form.Get("client_id"), clientIP)
	if err != nil {
		return "", err
	}
	if !client.IsConfidential() {
		h.logAuthFailure(r.Context(), client.ClientID, clientIP, "introspection_missing_credentials", "Introspection requires confidential client authentication")
		return "", oauth.ErrInvalidClient("Client authentication required for token introspection")
	}
	return client.ClientID, nil
}

// recordTokenRevoked records when a token is revoked.
func (h *Handler) recordTokenRevoked(ctx context.Context, clientID string) {
	h.server.Instrumentation.Metrics().RecordTokenRevocation(ctx, clientID)
}
