package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ServeToken handles the OAuth token endpoint
func (h *Handler) ServeToken(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointToken, r.Method, http.StatusMethodNotAllowed, startTime)
		instrumentation.SetSpanError(span, "method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointToken, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, clientIP)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r, clientIP)
	case server.GrantTypeTokenExchange:
		h.handleTokenExchangeGrant(w, r, clientIP)
	default:
		h.recordTokenFailure(r.Context(), grantType, constants.ErrorCodeUnsupportedGrantType)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported grant_type")
		h.writeError(w, constants.ErrorCodeUnsupportedGrantType, fmt.Sprintf("Grant type %s not supported", grantType), http.StatusBadRequest)
	}
}

// recordTokenFailure records a token-endpoint failure metric labelled by
// grant_type + RFC 6749 error_code. Unknown grant_types are coerced to
// "unknown" to bound label cardinality (a malformed client request with
// grant_type=<random> would otherwise mint a fresh series per probe).
func (h *Handler) recordTokenFailure(ctx context.Context, grantType, errorCode string) {
	switch grantType {
	case "authorization_code", "refresh_token", "client_credentials", "password", server.GrantTypeTokenExchange:
	default:
		grantType = "unknown"
	}
	h.server.Instrumentation.Metrics().RecordTokenEndpointFailure(ctx, grantType, errorCode)
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_exchange")
	defer endSpan()

	// Read from already-parsed form (ParseForm called by ServeToken)
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	resource := r.Form.Get("resource") // RFC 8707: Target resource server identifier
	codeVerifier := r.Form.Get("code_verifier")

	if code == "" {
		h.recordTokenFailure(r.Context(), "authorization_code", constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "code missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		// authenticateClient returns *Error; read its Status before recording
		// the HTTP metric so a 400 (client_id mismatch) is not mis-labelled as
		// 401 (unauthorized) in dashboards.
		var oauthErr *oauth.Error
		if errors.As(err, &oauthErr) {
			h.recordTokenFailure(r.Context(), "authorization_code", oauthErr.Code)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, oauthErr.Status, startTime)
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.recordTokenFailure(r.Context(), "authorization_code", constants.ErrorCodeInvalidClient)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
			h.writeError(w, constants.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Post-auth rate limit, keyed by client_id. Confidential-only: public
	// clients have no secret to compromise, and rate-limiting by a public
	// client_id is attacker-controllable. Public clients stay bounded by
	// the IP limit.
	if client.IsConfidential() {
		if retryAfter, limited := h.checkUserRateLimited(r.Context(), client.ClientID, clientIP); limited {
			h.writeUserRateLimitError(w, retryAfter)
			h.recordRateLimitReject(r.Context(), span, endpointToken, http.MethodPost, startTime)
			return
		}
	}

	// Add span attributes
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
		attribute.String(instrumentation.AttrGrantType, "authorization_code"),
	)

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(r.Context(), code, client.ClientID, redirectURI, resource, codeVerifier, dpopProofJKTFromContext(r.Context()))
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", client.ClientID, "ip", clientIP, "error", err)
		h.recordTokenFailure(r.Context(), "authorization_code", constants.ErrorCodeInvalidGrant)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "code exchange failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, constants.ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
		return
	}

	h.logger.Debug("Token exchange successful", "client_id", client.ClientID, "ip", clientIP)

	// Record code exchanged metric
	pkceMethod := ""
	if codeVerifier != "" {
		pkceMethod = constants.PKCEMethodS256
	}
	h.recordCodeExchanged(r.Context(), client.ClientID, pkceMethod)

	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_refresh")
	defer endSpan()

	// Read from already-parsed form (ParseForm called by ServeToken)
	refreshToken := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")

	if refreshToken == "" {
		h.recordTokenFailure(r.Context(), "refresh_token", constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "refresh_token missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// OAUTH 2.1 SECURITY: Authenticate client for refresh token grant
	// Confidential clients MUST authenticate; public clients may use client_id only
	clientID, clientAuthenticated, err := h.authenticateRefreshTokenClient(r.Context(), w, r, clientID, clientIP, startTime, span)
	if err != nil {
		// Error already written to response by authenticateRefreshTokenClient
		return
	}

	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, clientID),
		attribute.String(instrumentation.AttrGrantType, "refresh_token"),
	)
	if clientAuthenticated {
		instrumentation.SetSpanAttributes(span, attribute.Bool("oauth.client_authenticated", true))

		// Post-auth rate limit for confidential clients, keyed by client_id.
		// Public clients have no authentication step, only an IP-rate bound.
		if retryAfter, limited := h.checkUserRateLimited(r.Context(), clientID, clientIP); limited {
			h.writeUserRateLimitError(w, retryAfter)
			h.recordRateLimitReject(r.Context(), span, endpointToken, http.MethodPost, startTime)
			return
		}
	}

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(r.Context(), refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		h.recordTokenFailure(r.Context(), "refresh_token", constants.ErrorCodeInvalidGrant)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "token refresh failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, constants.ErrorCodeInvalidGrant, "Refresh token is invalid or expired", http.StatusBadRequest)
		return
	}

	// Record token refreshed metric (check if it was rotated)
	rotated := h.server.Config.AllowRefreshTokenRotation
	h.recordTokenRefreshed(r.Context(), clientID, rotated)

	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, "")
}

// authenticateRefreshTokenClient authenticates the client for refresh token grant.
// Per OAuth 2.1 Section 6, confidential clients MUST authenticate on refresh.
// Returns (clientID, clientAuthenticated, error).
// If error is returned, the HTTP response has already been written.
func (h *Handler) authenticateRefreshTokenClient(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, error) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)

	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, clientID, clientIP, endpointToken, "refresh_token", span, startTime) {
		return "", false, fmt.Errorf("client_id mismatch between Basic Authorization header and form parameter")
	}

	// Case 1: Basic Auth credentials provided - validate them
	if basicClientID != "" {
		clientID = basicClientID
		if err := h.server.ValidateClientCredentials(ctx, clientID, basicClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "refresh_client_authentication_failed")
			}
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, constants.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return "", false, err
		}
		return clientID, true, nil
	}

	// Case 2: No Basic Auth - check if client_id was provided
	if clientID == "" {
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return "", false, fmt.Errorf("client_id required")
	}

	// Case 3: client_id provided but no credentials - check if client is confidential
	client, err := h.server.GetClient(ctx, clientID)
	if err != nil {
		h.logger.Warn("Unknown client for refresh", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "refresh_unknown_client")
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.SetSpanError(span, "unknown client")
		h.writeError(w, constants.ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		return "", false, err
	}

	// OAUTH 2.1 SECURITY: Confidential clients MUST authenticate
	if client.IsConfidential() {
		h.logger.Warn("Confidential client attempted refresh without authentication",
			"client_id", clientID, "ip", clientIP,
			"security_event", "confidential_client_missing_auth",
			"oauth_spec", "OAuth 2.1 Section 6")
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "confidential_client_refresh_missing_auth")
			h.server.Auditor.LogEvent(ctx, security.Event{
				Type:     security.EventAuthFailure,
				ClientID: clientID,
				Details: map[string]any{
					"severity":     "high",
					"client_type":  "confidential",
					"auth_missing": true,
					"endpoint":     "refresh_token",
					"ip":           clientIP,
					"oauth_spec":   "OAuth 2.1 Section 6",
				},
			})
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.SetSpanError(span, "confidential client requires authentication")
		h.writeError(w, constants.ErrorCodeInvalidClient, "Client authentication required", http.StatusUnauthorized)
		return "", false, fmt.Errorf("confidential client requires authentication")
	}

	// Public client - authentication not required but client_id validated
	return clientID, false, nil
}

// parseBasicAuth returns the Basic Authorization credentials when the header
// is well-formed. A malformed Basic header (missing `Basic ` prefix, undecodable
// payload, missing colon) returns empty strings so the caller routes the
// request to the unauthenticated path rather than treating garbage as a
// silent client_id.
func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ""
	}
	return username, password
}

// rejectBasicFormClientIDMismatch enforces RFC 6749 §2.3.1: when both a Basic
// Authorization header and a form `client_id` are supplied they MUST identify
// the same client. On mismatch the response is written (400 invalid_client),
// the audit event is emitted, and the HTTP metric / span are recorded — the
// caller returns immediately on a true result. tokenFailureGrant is non-empty
// for /token-grant sites so the per-grant failure counter increments alongside
// the HTTP counter; /revoke and /introspect pass "".
func (h *Handler) rejectBasicFormClientIDMismatch(
	w http.ResponseWriter,
	r *http.Request,
	basicClientID, formClientID, clientIP, endpoint, tokenFailureGrant string,
	span trace.Span,
	startTime time.Time,
) bool {
	if basicClientID == "" || formClientID == "" || basicClientID == formClientID {
		return false
	}
	h.logger.Warn("client_id mismatch between Basic Authorization header and form parameter",
		"basic_client_id", basicClientID, "form_client_id", formClientID, "ip", clientIP, "endpoint", endpoint)
	if h.server.Auditor != nil {
		// Audit pins the Basic-Auth value: that is the authenticated identity
		// the request claimed, and forensics care about who tried to authenticate
		// rather than the form value the attacker may have synthesised.
		h.server.Auditor.LogAuthFailure(r.Context(), "", basicClientID, clientIP, "client_id_mismatch_basic_vs_form")
	}
	if tokenFailureGrant != "" {
		h.recordTokenFailure(r.Context(), tokenFailureGrant, constants.ErrorCodeInvalidClient)
	}
	h.recordHTTPMetrics(r.Context(), endpoint, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.SetSpanError(span, "client_id mismatch basic vs form")
	h.writeError(w, constants.ErrorCodeInvalidClient, "client_id in Basic Authorization header does not match form parameter", http.StatusBadRequest)
	return true
}

// authenticateClient validates client credentials from either Basic Auth or form parameters
// Returns the validated client or an error with the OAuth error code
func (h *Handler) authenticateClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)
	formClientID := clientID

	// RFC 6749 §2.3.1: if both Basic Auth and form client_id are supplied,
	// they MUST identify the same client.
	if basicClientID != "" && formClientID != "" && basicClientID != formClientID {
		h.logAuthFailure(r.Context(), basicClientID, clientIP, "client_id_mismatch_basic_vs_form", "client_id in Basic Authorization header does not match form parameter")
		return nil, oauth.NewError(constants.ErrorCodeInvalidClient, "client_id in Basic Authorization header does not match form parameter", http.StatusBadRequest)
	}

	authClientSecret := basicClientSecret
	if basicClientID != "" {
		clientID = basicClientID
	}

	if clientID == "" {
		return nil, oauth.ErrInvalidRequest("client_id is required")
	}

	client, err := h.server.GetClient(r.Context(), clientID)
	if err != nil {
		h.logAuthFailure(r.Context(), clientID, clientIP, constants.ErrorCodeInvalidClient, "Unknown client")
		return nil, oauth.ErrInvalidClient("Client authentication failed")
	}

	if err := h.validateConfidentialClient(r.Context(), client, authClientSecret, clientIP); err != nil {
		return nil, err
	}

	return client, nil
}

// validateConfidentialClient validates credentials for confidential clients.
func (h *Handler) validateConfidentialClient(ctx context.Context, client *storage.Client, secret, clientIP string) error {
	if !client.IsConfidential() {
		return nil
	}

	if secret == "" {
		h.logAuthFailure(ctx, client.ClientID, clientIP, "confidential_client_auth_required", "Confidential client missing credentials")
		return oauth.ErrInvalidClient("Client authentication required")
	}

	if err := h.server.ValidateClientCredentials(ctx, client.ClientID, secret); err != nil {
		h.logAuthFailure(ctx, client.ClientID, clientIP, "client_authentication_failed", "Client authentication failed")
		return oauth.ErrInvalidClient("Client authentication failed")
	}

	return nil
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token *oauth2.Token, scope string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := int64(time.Until(token.Expiry).Seconds())
	if expiresIn < 0 {
		expiresIn = 3600
	}

	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = tokenTypeBearer
	}

	response := map[string]any{
		"access_token": token.AccessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if token.RefreshToken != "" {
		response["refresh_token"] = token.RefreshToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	// OIDC Compliance: Include id_token in response if present
	// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token is REQUIRED
	// in token responses for OIDC flows. This enables clients to use
	// id_token_hint and login_hint for silent re-authentication.
	if idToken := server.ExtractIDToken(token); idToken != "" {
		response["id_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// isValidAuthMethod checks if the given token endpoint auth method is supported
func isValidAuthMethod(method string) bool {
	for _, supported := range oauth.SupportedTokenAuthMethods {
		if method == supported {
			return true
		}
	}
	return false
}

// recordCodeExchanged records when an authorization code is exchanged.
func (h *Handler) recordCodeExchanged(ctx context.Context, clientID, pkceMethod string) {
	h.server.Instrumentation.Metrics().RecordCodeExchange(ctx, clientID, pkceMethod)
}

// recordTokenRefreshed records when a token is refreshed.
func (h *Handler) recordTokenRefreshed(ctx context.Context, clientID string, rotated bool) {
	h.server.Instrumentation.Metrics().RecordTokenRefresh(ctx, clientID, rotated)
}
