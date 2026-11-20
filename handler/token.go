package handler

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// RFC 8707 §2 allows several resource parameters; this server issues tokens
// with a single audience, so it cannot honor more than one and refuses them.
const (
	auditReasonMultipleResources = "multiple_resources"
	multipleResourcesDescription = "Only one resource parameter is supported: this server issues single-audience tokens"
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

	if len(r.Form["resource"]) > 1 {
		h.logAuthFailure(r.Context(), "", clientIP, auditReasonMultipleResources, "Token request rejected: more than one resource parameter")
		h.recordTokenFailure(r.Context(), grantType, constants.ErrorCodeInvalidTarget)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "multiple resources")
		h.writeError(w, constants.ErrorCodeInvalidTarget, multipleResourcesDescription, http.StatusBadRequest)
		return
	}

	switch grantType {
	case grantTypeAuthorizationCode:
		h.handleAuthorizationCodeGrant(w, r, clientIP)
	case grantTypeRefreshToken:
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
	case grantTypeAuthorizationCode, grantTypeRefreshToken, "client_credentials", "password", server.GrantTypeTokenExchange:
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
		h.recordTokenFailure(r.Context(), grantTypeAuthorizationCode, constants.ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "code missing")
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		h.writeClientAuthenticationError(w, r, grantTypeAuthorizationCode, span, startTime, err)
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
		attribute.String(instrumentation.AttrGrantType, grantTypeAuthorizationCode),
	)

	dpopJKT, err := h.extractDPoPJKT(r)
	if err != nil {
		h.logger.Warn("Invalid DPoP proof on code exchange", "client_id", client.ClientID, "ip", clientIP, paramError, err)
		h.recordTokenFailure(r.Context(), grantTypeAuthorizationCode, constants.ErrorCodeInvalidDPoPProof)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "invalid dpop proof")
		h.writeError(w, constants.ErrorCodeInvalidDPoPProof, "DPoP proof validation failed", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(r.Context(), code, client.ClientID, redirectURI, resource, codeVerifier, dpopJKT)
	if err != nil {
		h.writeAuthorizationCodeExchangeError(w, r, span, startTime, client.ClientID, clientIP, err)
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

// writeAuthorizationCodeExchangeError answers a failed authorization code
// exchange: invalid_target for a resource this server does not serve, 503
// for unavailable storage, and a generic invalid_grant otherwise so the
// response does not reveal which check failed (details are audited by
// ExchangeAuthorizationCode).
func (h *Handler) writeAuthorizationCodeExchangeError(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, clientID, clientIP string, err error) {
	if errors.Is(err, server.ErrStorageUnavailable) {
		h.writeTokenStorageUnavailable(w, r, grantTypeAuthorizationCode, span, startTime, err)
		return
	}
	instrumentation.RecordError(span, err)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
	if errors.Is(err, server.ErrInvalidTarget) {
		h.recordTokenFailure(r.Context(), grantTypeAuthorizationCode, constants.ErrorCodeInvalidTarget)
		instrumentation.SetSpanError(span, "invalid resource")
		h.writeError(w, constants.ErrorCodeInvalidTarget, "The resource parameter does not name a resource this server issues tokens for", http.StatusBadRequest)
		return
	}
	h.logger.Error("Failed to exchange authorization code", "client_id", clientID, "ip", clientIP, paramError, err)
	h.recordTokenFailure(r.Context(), grantTypeAuthorizationCode, constants.ErrorCodeInvalidGrant)
	instrumentation.SetSpanError(span, "code exchange failed")
	h.writeError(w, constants.ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_refresh")
	defer endSpan()

	// Read from already-parsed form (ParseForm called by ServeToken)
	refreshToken := r.Form.Get(grantTypeRefreshToken)
	clientID := r.Form.Get("client_id")
	resource := r.Form.Get("resource")

	if refreshToken == "" {
		h.recordTokenFailure(r.Context(), grantTypeRefreshToken, constants.ErrorCodeInvalidRequest)
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
		attribute.String(instrumentation.AttrGrantType, grantTypeRefreshToken),
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
	tokenResponse, err := h.server.RefreshAccessTokenForResource(r.Context(), refreshToken, clientID, resource)
	if err != nil {
		if errors.Is(err, server.ErrStorageUnavailable) {
			h.writeTokenStorageUnavailable(w, r, grantTypeRefreshToken, span, startTime, err)
			return
		}
		if errors.Is(err, server.ErrProviderUnavailable) {
			h.writeTokenProviderUnavailable(w, r, grantTypeRefreshToken, span, startTime, err)
			return
		}
		if errors.Is(err, server.ErrInvalidTarget) {
			h.recordTokenFailure(r.Context(), grantTypeRefreshToken, constants.ErrorCodeInvalidTarget)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "invalid resource")
			h.writeError(w, constants.ErrorCodeInvalidTarget, "The resource parameter does not name the resource this refresh token was issued for", http.StatusBadRequest)
			return
		}
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, paramError, err)
		h.recordTokenFailure(r.Context(), grantTypeRefreshToken, constants.ErrorCodeInvalidGrant)
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
// If error is returned, the HTTP response has already been written; a client
// store that did not answer is written as 503.
func (h *Handler) authenticateRefreshTokenClient(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, error) {
	client, err := h.authenticateClient(r.WithContext(ctx), clientID, clientIP)
	if err != nil {
		h.writeClientAuthenticationError(w, r, grantTypeRefreshToken, span, startTime, err)
		return "", false, err
	}
	return client.ClientID, client.IsConfidential(), nil
}

// parseBasicAuth returns the Basic Authorization credentials when the header
// is well-formed. A malformed Basic header (missing `Basic ` prefix, undecodable
// payload, missing colon) returns empty strings so the caller routes the
// request to the unauthenticated path rather than treating garbage as a
// silent client_id.
//
// RFC 6749 §2.3.1 has clients form-encode the client ID and secret before
// Basic encoding them, so both are form-decoded; a value that does not decode
// is kept as sent.
func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ""
	}
	return formDecode(username), formDecode(password)
}

func formDecode(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

// validateBasicClientSecret checks clientID against the secret of the Basic
// Authorization header, form-decoded as parseBasicAuth decodes it. When that
// is refused and decoding altered the secret, the secret as sent is checked
// too: a client that does not form-encode its credentials sends a secret
// holding '+' or '%' unchanged.
func (h *Handler) validateBasicClientSecret(ctx context.Context, r *http.Request, clientID string) error {
	client, lookupError := h.server.GetRegisteredClient(ctx, clientID)
	if lookupError != nil {
		return lookupError
	}
	if client.TokenEndpointAuthMethod == server.TokenEndpointAuthMethodPrivateKeyJWT {
		h.logAuthFailure(ctx, client.ClientID, r.RemoteAddr, "assertion_required", "Client authentication failed")
		return oauth.ErrInvalidClient("Client authentication failed")
	}
	_, sent, _ := r.BasicAuth()
	decoded := formDecode(sent)
	err := h.server.ValidateClientCredentials(ctx, clientID, decoded)
	if decoded == sent || !errors.Is(err, storage.ErrInvalidClientCredentials) {
		return err
	}
	if err := h.server.ValidateClientCredentials(ctx, clientID, sent); err != nil {
		return err
	}
	h.logger.Info("Client authenticated with Basic credentials that are not form-encoded", "client_id", clientID)
	return nil
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
// Returns the validated client or an error with the OAuth error code. A client
// store that did not answer yields server.ErrStorageUnavailable, which callers
// answer with 503 rather than a client-authentication failure.
func (h *Handler) authenticateClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	return h.authenticateClientWithLookup(r, clientID, clientIP, h.server.GetClient)
}

func (h *Handler) authenticateRegisteredClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	return h.authenticateClientWithLookup(r, clientID, clientIP, h.server.GetRegisteredClient)
}

func (h *Handler) authenticateClientWithLookup(r *http.Request, clientID, clientIP string, lookup func(context.Context, string) (*storage.Client, error)) (*storage.Client, error) {
	if err := validateClientCredentialShape(r); err != nil {
		h.logAuthFailure(r.Context(), clientID, clientIP, "client_credentials_malformed", "Client authentication failed")
		return nil, err
	}
	if hasClientAssertion(r) {
		return h.authenticateAssertion(r, clientID, clientIP)
	}
	basicClientID, basicClientSecret := h.parseBasicAuth(r)
	formClientID := clientID

	// RFC 6749 §2.3.1: if both Basic Auth and form client_id are supplied,
	// they MUST identify the same client.
	if basicClientID != "" && formClientID != "" && basicClientID != formClientID {
		h.logAuthFailure(r.Context(), basicClientID, clientIP, "client_id_mismatch_basic_vs_form", "client_id in Basic Authorization header does not match form parameter")
		return nil, oauth.NewError(constants.ErrorCodeInvalidClient, "client_id in Basic Authorization header does not match form parameter", http.StatusBadRequest)
	}

	authClientSecret := basicClientSecret
	if r.PostForm.Has("client_secret") {
		authClientSecret = r.PostForm.Get("client_secret")
	}
	if basicClientID != "" {
		clientID = basicClientID
	}

	if clientID == "" {
		return nil, oauth.ErrInvalidRequest("client_id is required")
	}

	client, err := lookup(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, server.ErrStorageUnavailable) {
			return nil, err
		}
		reason := constants.ErrorCodeInvalidClient
		if r.Form.Get("grant_type") == grantTypeRefreshToken {
			reason = "refresh_unknown_client"
		}
		h.logAuthFailure(r.Context(), clientID, clientIP, reason, "Unknown client")
		return nil, oauth.ErrInvalidClient("Client authentication failed")
	}

	if err := h.validateConfidentialClient(r, client, authClientSecret, clientIP); err != nil {
		return nil, err
	}

	return client, nil
}

// validateConfidentialClient validates credentials for confidential clients.
func (h *Handler) validateConfidentialClient(r *http.Request, client *storage.Client, secret, clientIP string) error {
	ctx := r.Context()
	if client.TokenEndpointAuthMethod == server.TokenEndpointAuthMethodPrivateKeyJWT {
		h.logAuthFailure(ctx, client.ClientID, clientIP, "assertion_required", "Client authentication failed")
		return oauth.ErrInvalidClient("Client authentication failed")
	}
	if !client.IsConfidential() {
		return nil
	}

	if secret == "" {
		reason := "confidential_client_auth_required"
		if r.Form.Get("grant_type") == grantTypeRefreshToken && r.Header.Get("Authorization") == "" && !r.Form.Has("client_secret") {
			reason = "confidential_client_refresh_missing_auth"
		}
		h.logAuthFailure(ctx, client.ClientID, clientIP, reason, "Confidential client missing credentials")
		return oauth.ErrInvalidClient("Client authentication required")
	}

	var err error
	if r.PostForm.Get("client_secret") != "" {
		if client.TokenEndpointAuthMethod != "client_secret_post" {
			h.logAuthFailure(ctx, client.ClientID, clientIP, "client_authentication_method_mismatch", "Client authentication failed")
			return oauth.ErrInvalidClient("Client authentication failed")
		}
		err = h.server.ValidateClientCredentials(ctx, client.ClientID, secret)
	} else {
		if client.TokenEndpointAuthMethod == "client_secret_post" {
			h.logAuthFailure(ctx, client.ClientID, clientIP, "client_authentication_method_mismatch", "Client authentication failed")
			return oauth.ErrInvalidClient("Client authentication failed")
		}
		err = h.validateBasicClientSecret(ctx, r, client.ClientID)
	}
	if err != nil {
		if errors.Is(err, server.ErrStorageUnavailable) {
			return err
		}
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
		response[grantTypeRefreshToken] = token.RefreshToken
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
	h.writeJSON(w, response)
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
