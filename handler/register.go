package handler

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Registration auth gate names used in audit, tracing, and logs.
const (
	registrationAuthGateTrustedScheme      = "trusted_scheme"
	registrationAuthGateTrustedRedirectURI = "trusted_redirect_uri"
)

// clientRegistrationRequest represents the JSON request for client registration
type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
}

// checkClientRegistrationRateLimit checks if client registration is rate limited
// Returns true if request should be rejected, false if allowed
func (h *Handler) checkClientRegistrationRateLimit(ctx context.Context, w http.ResponseWriter, clientIP string, startTime time.Time) bool {
	if h.server.ClientRegistrationRateLimiter == nil {
		return false
	}

	if !h.server.ClientRegistrationRateLimiter.Allow(security.RateLimitBucket(clientIP)) {
		h.logger.Warn("Client registration rate limit exceeded",
			"ip", clientIP,
			"max_per_window", h.server.Config.MaxRegistrationsPerHour,
			"window", time.Duration(h.server.Config.RegistrationRateLimitWindow)*time.Second)
		h.server.Auditor.LogClientRegistrationRateLimitExceeded(ctx, clientIP)
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusTooManyRequests, startTime)
		retryAfter := int(h.server.ClientRegistrationRateLimiter.Window().Seconds())
		if retryAfter < 1 {
			retryAfter = 60
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"Client registration rate limit exceeded. Please try again later.",
			http.StatusTooManyRequests)
		return true
	}
	return false
}

// validateRegistrationToken validates the registration access token
// Returns true if valid token was provided
func (h *Handler) validateRegistrationToken(authHeader string) bool {
	if authHeader == "" || h.server.Config.RegistrationAccessToken == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(h.server.Config.RegistrationAccessToken)) == 1
}

// registrationAuthResult identifies which gate authorized a DCR request.
type registrationAuthResult struct {
	viaTrustedAllowlist bool
	gate                string
	matched             string
}

// authorizeClientRegistration checks whether a DCR request is authorized via the
// public-client flag, a registration access token, the trusted-scheme allowlist,
// or the trusted-redirect-URI allowlist (in that order).
func (h *Handler) authorizeClientRegistration(w http.ResponseWriter, r *http.Request, req *clientRegistrationRequest, clientIP string) (registrationAuthResult, bool) {
	var result registrationAuthResult

	if h.server.Config.AllowPublicClientRegistration {
		h.logger.Warn("Unauthenticated client registration (DoS risk)", "client_ip", clientIP)
		return result, true
	}

	authHeader := r.Header.Get("Authorization")
	if h.validateRegistrationToken(authHeader) {
		h.logger.Debug("Client registration authenticated with valid token")
		return result, true
	}

	if authHeader != "" {
		h.logger.Warn("Invalid registration token provided, falling back to trusted allowlists",
			"client_ip", clientIP,
			"has_trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0,
			"has_trusted_redirect_uris_configured", len(h.server.Config.TrustedPublicRegistrationRedirectURIs) > 0)
	}

	allowed, scheme, err := h.server.CanRegisterWithTrustedScheme(req.RedirectURIs)
	if err != nil {
		h.logger.Warn("Client registration rejected: invalid redirect URI", "client_ip", clientIP, "error", err)
		h.writeError(w, constants.ErrorCodeInvalidRequest, fmt.Sprintf("Invalid redirect URI: %v", err), http.StatusBadRequest)
		return result, false
	}
	if allowed {
		h.logger.Debug("Client registration authorized via trusted scheme",
			"scheme", scheme, "client_ip", clientIP, "strict_matching", !h.server.Config.DisableStrictSchemeMatching)
		return registrationAuthResult{viaTrustedAllowlist: true, gate: registrationAuthGateTrustedScheme, matched: scheme}, true
	}

	allowed, uri, _ := h.server.CanRegisterWithTrustedRedirectURI(req.RedirectURIs)
	if allowed {
		h.logger.Debug("Client registration authorized via trusted redirect URI",
			"redirect_uri", uri, "client_ip", clientIP)
		return registrationAuthResult{viaTrustedAllowlist: true, gate: registrationAuthGateTrustedRedirectURI, matched: uri}, true
	}

	h.logger.Warn("Client registration rejected: missing or invalid authorization",
		"client_ip", clientIP, "has_token", authHeader != "",
		"has_trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0,
		"has_trusted_redirect_uris_configured", len(h.server.Config.TrustedPublicRegistrationRedirectURIs) > 0)
	h.writeError(w, constants.ErrorCodeInvalidToken,
		"Registration requires authentication. Provide a valid registration token or use a trusted redirect URI or scheme.",
		http.StatusUnauthorized)
	return result, false
}

// validatePublicClientRegistration validates public client registration is allowed
// Returns true if allowed, false if rejected
func (h *Handler) validatePublicClientRegistration(ctx context.Context, w http.ResponseWriter, req *clientRegistrationRequest, clientIP string, auth registrationAuthResult, startTime time.Time, span trace.Span) bool {
	isPublicClientRequest := req.TokenEndpointAuthMethod == oauth.TokenEndpointAuthMethodNone || req.ClientType == oauth.ClientTypePublic
	if !isPublicClientRequest {
		return true
	}

	if !h.server.Config.AllowPublicClientRegistration && !auth.viaTrustedAllowlist {
		h.logger.Warn("Public client registration rejected (not allowed by configuration)",
			"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
			"client_type", req.ClientType, "ip", clientIP)
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusBadRequest, startTime)
		if span != nil {
			instrumentation.SetSpanAttributes(
				span,
				attribute.String("oauth.client_type", "public"),
				attribute.String("security.event", "public_client_registration_denied"),
			)
			instrumentation.SetSpanError(span, "public client registration not allowed")
		}
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"Public client registration is not enabled on this server. Contact the server administrator.",
			http.StatusBadRequest)
		return false
	}

	h.logger.Debug("Public client registration authorized",
		"token_endpoint_auth_method", req.TokenEndpointAuthMethod, "client_type", req.ClientType,
		"ip", clientIP, "via_trusted_allowlist", auth.viaTrustedAllowlist, "auth_gate", auth.gate)
	return true
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.client_registration")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointRegister, http.MethodPost, startTime)
	if !ok {
		return
	}

	if h.checkClientRegistrationRateLimit(r.Context(), w, clientIP, startTime) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)

	req, err := h.parseAndValidateRegistrationRequest(w, r, clientIP)
	if err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "request body too large")
		}
		return
	}

	auth, authorized := h.authorizeClientRegistration(w, r, req, clientIP)
	if !authorized {
		return
	}

	if !h.validatePublicClientRegistration(r.Context(), w, req, clientIP, auth, startTime, span) {
		return
	}

	h.recordTrustedAllowlistSpan(span, auth)

	maxClients := h.getMaxClientsPerIP()
	result, err := h.server.RegisterClientV2(r.Context(), req.ClientName, req.ClientType, req.TokenEndpointAuthMethod, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		h.handleRegistrationError(r.Context(), w, err, clientIP, startTime, span)
		return
	}

	h.recordClientRegistered(r.Context(), result.Client.ClientType)
	h.auditTrustedAllowlistRegistration(r.Context(), auth, result.Client, clientIP)
	h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusCreated, startTime)
	h.setRegistrationSpanSuccess(span, result.Client)
	h.writeRegistrationResponse(w, result.Client, result.ClientSecret, result.RegistrationToken)
}

// parseAndValidateRegistrationRequest parses the request and validates auth method.
func (h *Handler) parseAndValidateRegistrationRequest(w http.ResponseWriter, r *http.Request, clientIP string) (*clientRegistrationRequest, error) {
	var req clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, err
		}
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return nil, err
	}

	// Validate client_name to prevent potential stored XSS and log injection (defense-in-depth)
	if err := helpers.ValidateClientName(req.ClientName); err != nil {
		h.logger.Warn("Invalid client_name in registration request",
			"client_name_length", len(req.ClientName), "error", err, "ip", clientIP)
		h.writeError(w, constants.ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return nil, err
	}

	if req.TokenEndpointAuthMethod != "" && !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		h.logger.Warn("Unsupported token_endpoint_auth_method requested",
			"method", req.TokenEndpointAuthMethod, "supported_methods", oauth.SupportedTokenAuthMethods, "ip", clientIP)
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			fmt.Sprintf("Unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod),
			http.StatusBadRequest)
		return nil, fmt.Errorf("unsupported auth method")
	}

	return &req, nil
}

// getMaxClientsPerIP returns the max clients per IP with default.
func (h *Handler) getMaxClientsPerIP() int {
	if h.server.Config.MaxClientsPerIP == 0 {
		return 10
	}
	return h.server.Config.MaxClientsPerIP
}

// recordTrustedAllowlistSpan records the allowlist gate used in the span, if any.
func (h *Handler) recordTrustedAllowlistSpan(span trace.Span, auth registrationAuthResult) {
	if span == nil || !auth.viaTrustedAllowlist {
		return
	}
	switch auth.gate {
	case registrationAuthGateTrustedScheme:
		instrumentation.SetSpanAttributes(
			span,
			attribute.String("oauth.registration_method", auth.gate),
			attribute.String("oauth.trusted_scheme", auth.matched),
		)
	case registrationAuthGateTrustedRedirectURI:
		instrumentation.SetSpanAttributes(
			span,
			attribute.String("oauth.registration_method", auth.gate),
			attribute.String("oauth.trusted_redirect_uri", auth.matched),
		)
	default:
		h.logger.Warn("Skipping span attrs for unknown registration auth gate", "gate", auth.gate)
	}
}

// handleRegistrationError handles client registration errors.
func (h *Handler) handleRegistrationError(ctx context.Context, w http.ResponseWriter, err error, clientIP string, startTime time.Time, span trace.Span) {
	if errors.Is(err, storage.ErrClientIPLimitExceeded) {
		h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusTooManyRequests, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "registration limit exceeded")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
		return
	}

	h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
	h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusInternalServerError, startTime)
	instrumentation.RecordError(span, err)
	instrumentation.SetSpanError(span, "registration failed")
	h.writeError(w, constants.ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
}

// auditTrustedAllowlistRegistration logs unauthenticated DCR via either trusted
// allowlist (scheme or HTTPS redirect URI) for security monitoring.
func (h *Handler) auditTrustedAllowlistRegistration(ctx context.Context, auth registrationAuthResult, client *storage.Client, clientIP string) {
	if !auth.viaTrustedAllowlist {
		return
	}

	details := map[string]any{
		"client_type":   client.ClientType,
		"client_ip":     clientIP,
		"redirect_uris": client.RedirectURIs,
	}

	var eventType string
	switch auth.gate {
	case registrationAuthGateTrustedScheme:
		eventType = security.EventClientRegisteredViaTrustedScheme
		details["scheme"] = auth.matched
		details["strict_matching"] = !h.server.Config.DisableStrictSchemeMatching
		details["security_context"] = "unauthenticated_registration_via_trusted_scheme"
	case registrationAuthGateTrustedRedirectURI:
		eventType = security.EventClientRegisteredViaTrustedRedirectURI
		details["redirect_uri"] = auth.matched
		details["security_context"] = "unauthenticated_registration_via_trusted_redirect_uri"
	default:
		h.logger.Warn("Skipping audit for unknown registration auth gate",
			"gate", auth.gate, "client_id", client.ClientID, "client_ip", clientIP)
		return
	}

	h.server.Auditor.LogEvent(ctx, security.Event{
		Type:     eventType,
		ClientID: client.ClientID,
		Details:  details,
	})
}

// setRegistrationSpanSuccess sets success attributes on the span.
func (h *Handler) setRegistrationSpanSuccess(span trace.Span, client *storage.Client) {
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
	)
	instrumentation.SetSpanSuccess(span)
}

// writeRegistrationResponse writes the client registration response per
// RFC 7591 §3.2.1. `client_id_issued_at` is always present; for confidential
// clients the response also carries `client_secret` plus
// `client_secret_expires_at: 0` (the spec sentinel for "never expires").
// When EnableClientManagementEndpoint is on, `registration_access_token` and
// `registration_client_uri` are also included (RFC 7592 §3).
func (h *Handler) writeRegistrationResponse(w http.ResponseWriter, client *storage.Client, clientSecret, registrationToken string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	response := map[string]any{
		"client_id":                  client.ClientID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_name":                client.ClientName,
		"client_type":                client.ClientType,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
	}

	if clientSecret != "" {
		response["client_secret"] = clientSecret
		response["client_secret_expires_at"] = 0
	}

	if h.server.Config.EnableClientManagementEndpoint && registrationToken != "" {
		response["registration_access_token"] = registrationToken
		response["registration_client_uri"] = h.server.Config.Issuer + server.EndpointPathRegister + "/" + client.ClientID
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	h.writeJSON(w, response)
}

// Helper methods
