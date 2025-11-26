package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	defaultCORSMaxAge = 3600 // 1 hour default for preflight cache
)

// Handler is a thin HTTP adapter for the OAuth Server.
// It handles HTTP requests and delegates to the Server for business logic.
type Handler struct {
	server *Server
	logger *slog.Logger
	tracer trace.Tracer // OpenTelemetry tracer for HTTP layer
}

// NewHandler creates a new HTTP handler
func NewHandler(server *Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handler{
		server: server,
		logger: logger,
	}

	// Initialize tracer if instrumentation is enabled
	if server.Instrumentation != nil {
		h.tracer = server.Instrumentation.Tracer("http")
	}

	return h
}

// ValidateToken is middleware that validates OAuth tokens
func (h *Handler) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP for rate limiting and logging
		clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

		// Apply IP-based rate limiting BEFORE token validation
		if h.server.RateLimiter != nil {
			if !h.server.RateLimiter.Allow(clientIP) {
				h.logger.Warn("Rate limit exceeded", "ip", clientIP)

				// Record rate limit exceeded metric
				if h.server.Instrumentation != nil {
					h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "ip")
				}

				if h.server.Auditor != nil {
					h.server.Auditor.LogEvent(security.Event{
						Type:      security.EventRateLimitExceeded,
						IPAddress: clientIP,
						Details: map[string]any{
							"endpoint": r.URL.Path,
						},
					})
					h.server.Auditor.LogRateLimitExceeded(clientIP, "")
				}
				w.Header().Set("Retry-After", "60")
				h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.writeError(w, ErrorCodeInvalidToken, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.writeError(w, ErrorCodeInvalidToken, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		accessToken := parts[1]

		// Validate token with server
		userInfo, err := h.server.ValidateToken(r.Context(), accessToken)
		if err != nil {
			h.logger.Warn("Token validation failed", "ip", clientIP, "error", err)
			// SECURITY: Don't leak internal error details to client
			// Log detailed error but return generic message
			h.writeError(w, ErrorCodeInvalidToken, "Token validation failed", http.StatusUnauthorized)
			return
		}

		// Apply per-user rate limiting AFTER authentication
		// This is a separate, higher limit for authenticated users
		if h.server.UserRateLimiter != nil {
			if !h.server.UserRateLimiter.Allow(userInfo.ID) {
				h.logger.Warn("User rate limit exceeded", "user_id", userInfo.ID, "ip", clientIP)

				// Record rate limit exceeded metric
				if h.server.Instrumentation != nil {
					h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "user")
				}

				if h.server.Auditor != nil {
					h.server.Auditor.LogRateLimitExceeded(clientIP, userInfo.ID)
				}
				w.Header().Set("Retry-After", "60")
				h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded for user. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		// Store user info in context
		ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ServeProtectedResourceMetadata serves RFC 9728 Protected Resource Metadata
func (h *Handler) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	metadata := map[string]any{
		"resource": h.server.Config.Issuer,
		"authorization_servers": []string{
			h.server.Config.Issuer,
		},
		"bearer_methods_supported": []string{"header"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// ServeAuthorizationServerMetadata serves RFC 8414 Authorization Server Metadata
func (h *Handler) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	metadata := map[string]any{
		"issuer":                           h.server.Config.Issuer,
		"authorization_endpoint":           h.server.Config.AuthorizationEndpoint(),
		"token_endpoint":                   h.server.Config.TokenEndpoint(),
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{PKCEMethodS256},
	}

	// Only advertise registration_endpoint if client registration is actually available
	// RFC 8414: registration_endpoint is OPTIONAL and should only be included if supported
	if h.server.Config.AllowPublicClientRegistration || h.server.Config.RegistrationAccessToken != "" {
		metadata["registration_endpoint"] = h.server.Config.RegistrationEndpoint()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// ServeAuthorization handles OAuth authorization requests
func (h *Handler) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create span if tracing is enabled
	var span trace.Span
	ctx := r.Context()
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.authorization")
		defer span.End()
		// Update request context to include span context
		r = r.WithContext(ctx)
	}

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if clientID == "" {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: State parameter is required for CSRF protection
	// Input validation at HTTP layer to return proper status codes
	if state == "" {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state missing")
		h.writeError(w, ErrorCodeInvalidRequest, "state parameter is required for CSRF protection", http.StatusBadRequest)
		return
	}
	if len(state) < MinStateLength {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Add attributes to span
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.pkce_method", codeChallengeMethod),
	)

	// Start authorization flow with client state (server also validates for defense in depth)
	authURL, err := h.server.StartAuthorizationFlow(ctx, clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, state)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusInternalServerError, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "authorization flow failed")
		h.writeError(w, ErrorCodeServerError, "Failed to start authorization flow", http.StatusInternalServerError)
		return
	}

	// Record authorization started metric
	h.recordAuthorizationStarted(clientID)

	h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusFound, startTime)
	instrumentation.SetSpanSuccess(span)

	// Redirect to provider
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ServeCallback handles the OAuth provider callback
func (h *Handler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.callback")
		defer span.End()
	}

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse callback parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	// Check for provider errors
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		h.logger.Warn("Provider returned error", "error", errorParam, "description", errorDesc)
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, errorParam)
		h.writeError(w, errorParam, errorDesc, http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: Validate state and code parameters
	// Input validation at HTTP layer to return proper status codes
	if state == "" || code == "" {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, "missing state or code")
		h.writeError(w, ErrorCodeInvalidRequest, "state and code are required", http.StatusBadRequest)
		return
	}
	if len(state) < MinStateLength {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Handle callback (state here is the provider state, not client state)
	// Server also validates state length for defense in depth
	authCode, clientState, err := h.server.HandleProviderCallback(ctx, state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "error", err)
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusInternalServerError, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "callback handling failed")
		h.writeError(w, ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
		return
	}

	// Record successful callback
	h.recordCallbackProcessed(authCode.ClientID, true)
	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", authCode.ClientID))
	instrumentation.SetSpanSuccess(span)

	h.recordHTTPMetrics("callback", http.MethodGet, http.StatusFound, startTime)

	// CRITICAL SECURITY: Redirect back to client with their original state parameter
	// This allows the client to verify the callback is for their original request (CSRF protection)
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authCode.RedirectURI, authCode.Code, clientState)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ServeToken handles the OAuth token endpoint
func (h *Handler) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		h.writeError(w, ErrorCodeUnsupportedGrantType, fmt.Sprintf("Grant type %s not supported", grantType), http.StatusBadRequest)
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_exchange")
		defer span.End()
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "code missing")
		h.writeError(w, ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		// authenticateClient returns OAuthError, extract details
		if oauthErr, ok := err.(*OAuthError); ok {
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Add span attributes
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", client.ClientID),
		attribute.String("oauth.client_type", client.ClientType),
	)

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(ctx, code, client.ClientID, redirectURI, codeVerifier)
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", client.ClientID, "ip", clientIP, "error", err)
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "code exchange failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
		return
	}

	h.logger.Info("Token exchange successful", "client_id", client.ClientID, "ip", clientIP)

	// Record code exchanged metric
	pkceMethod := ""
	if codeVerifier != "" {
		pkceMethod = PKCEMethodS256
	}
	h.recordCodeExchanged(client.ClientID, pkceMethod)

	h.recordHTTPMetrics("token", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_refresh")
		defer span.End()
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshToken == "" {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "refresh_token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			h.recordHTTPMetrics("token", http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", clientID))

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(ctx, refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "token refresh failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, ErrorCodeInvalidGrant, "Refresh token is invalid or expired", http.StatusBadRequest)
		return
	}

	// Record token refreshed metric (check if it was rotated)
	rotated := h.server.Config.AllowRefreshTokenRotation
	h.recordTokenRefreshed(clientID, rotated)

	h.recordHTTPMetrics("token", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, "")
}

// ServeTokenRevocation handles the RFC 7009 token revocation endpoint
func (h *Handler) ServeTokenRevocation(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_revocation")
		defer span.End()
	}

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "parse form failed")
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	clientID := r.FormValue("client_id")

	if token == "" {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for revocation", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "revocation_auth_failed")
			}
			h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", clientID))

	// Revoke token
	if err := h.server.RevokeToken(ctx, token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		instrumentation.RecordError(span, err)
		// Per RFC 7009, don't fail the request even if revocation failed
	}
	// Per RFC 7009, return 200 even if revocation fails

	// Record token revoked metric
	h.recordTokenRevoked(clientID)

	h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create span if tracing is enabled
	var span trace.Span
	ctx := r.Context()
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.client_registration")
		defer span.End()
		// Update request context to include span context
		r = r.WithContext(ctx)
	}

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Get client IP for DoS protection
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// OAuth 2.1: Require authentication for client registration (secure by default)
	// Only allow unauthenticated registration if explicitly configured
	if !h.server.Config.AllowPublicClientRegistration {
		// Check for registration access token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.logger.Warn("Client registration rejected: missing authorization",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken,
				"Registration access token required. "+
					"Set AllowPublicClientRegistration=true to disable authentication (NOT recommended).",
				http.StatusUnauthorized)
			return
		}

		// Verify Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.logger.Warn("Client registration rejected: invalid authorization header",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Validate registration access token
		providedToken := parts[1]
		if h.server.Config.RegistrationAccessToken == "" {
			h.logger.Error("RegistrationAccessToken not configured but AllowPublicClientRegistration=false")
			h.writeError(w, ErrorCodeServerError,
				"Server configuration error: registration token not configured",
				http.StatusInternalServerError)
			return
		}

		// SECURITY: Use constant-time comparison to prevent timing attacks
		// that could allow guessing the registration token character by character
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(h.server.Config.RegistrationAccessToken)) != 1 {
			h.logger.Warn("Client registration rejected: invalid registration token",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken, "Invalid registration access token", http.StatusUnauthorized)
			return
		}

		h.logger.Info("Client registration authenticated with valid token")
	} else {
		h.logger.Warn("⚠️  Unauthenticated client registration (DoS risk)",
			"client_ip", clientIP)
	}

	// SECURITY: Check time-windowed rate limit BEFORE processing request
	// This prevents resource exhaustion through repeated registration/deletion cycles
	if h.server.ClientRegistrationRateLimiter != nil {
		if !h.server.ClientRegistrationRateLimiter.Allow(clientIP) {
			h.logger.Warn("Client registration rate limit exceeded",
				"ip", clientIP,
				"max_per_window", h.server.Config.MaxRegistrationsPerHour,
				"window", time.Duration(h.server.Config.RegistrationRateLimitWindow)*time.Second)
			if h.server.Auditor != nil {
				h.server.Auditor.LogClientRegistrationRateLimitExceeded(clientIP)
			}
			h.writeError(w, ErrorCodeInvalidRequest,
				"Client registration rate limit exceeded. Please try again later.",
				http.StatusTooManyRequests)
			return
		}
	}

	// Check per-IP registration limit to prevent DoS attacks
	maxClients := h.server.Config.MaxClientsPerIP
	if maxClients == 0 {
		maxClients = 10 // Default limit
	}

	// Parse registration request
	var req struct {
		ClientName              string   `json:"client_name"`
		ClientType              string   `json:"client_type"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		RedirectURIs            []string `json:"redirect_uris"`
		Scopes                  []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// OAUTH 2.1 COMPLIANCE: Validate token_endpoint_auth_method
	// Per RFC 7591 Section 2, only these methods are standardized
	if req.TokenEndpointAuthMethod != "" && !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		h.logger.Warn("Unsupported token_endpoint_auth_method requested",
			"method", req.TokenEndpointAuthMethod,
			"supported_methods", SupportedTokenAuthMethods,
			"ip", clientIP)
		// SECURITY: Don't reveal full list of supported methods in error response
		// Supported methods are already advertised in /.well-known/oauth-authorization-server
		h.writeError(w, ErrorCodeInvalidRequest,
			fmt.Sprintf("Unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod),
			http.StatusBadRequest)
		return
	}

	// SECURITY: Validate public client registration is allowed
	// When client requests "none" auth method, they're requesting a public client
	// This is common for native/CLI apps that can't securely store secrets
	if req.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone || req.ClientType == ClientTypePublic {
		// CRITICAL: Enforce AllowPublicClientRegistration policy
		// Even with a valid registration access token, public client creation must be explicitly allowed
		if !h.server.Config.AllowPublicClientRegistration {
			h.logger.Warn("Public client registration rejected (not allowed by configuration)",
				"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
				"client_type", req.ClientType,
				"ip", clientIP,
				"recommendation", "Set AllowPublicClientRegistration=true to enable public client registration")
			h.recordHTTPMetrics("register", http.MethodPost, http.StatusBadRequest, startTime)
			if span != nil {
				instrumentation.SetSpanAttributes(span,
					attribute.String("oauth.client_type", "public"),
					attribute.String("security.event", "public_client_registration_denied"),
				)
				instrumentation.SetSpanError(span, "public client registration not allowed")
			}
			h.writeError(w, ErrorCodeInvalidRequest,
				"Public client registration is not enabled on this server. Contact the server administrator.",
				http.StatusBadRequest)
			return
		}

		h.logger.Info("Public client registration authorized",
			"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
			"client_type", req.ClientType,
			"ip", clientIP)
	}

	// Register client with IP tracking
	client, clientSecret, err := h.server.RegisterClient(ctx, req.ClientName, req.ClientType, req.TokenEndpointAuthMethod, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "registration limit") {
			h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
			h.recordHTTPMetrics("register", http.MethodPost, http.StatusTooManyRequests, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "registration limit exceeded")
			// SECURITY: Generic error message to prevent enumeration
			h.writeError(w, ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
			return
		}
		h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusInternalServerError, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "registration failed")
		// SECURITY: Don't leak internal error details
		h.writeError(w, ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
		return
	}

	// Record client registered metric
	h.recordClientRegistered(client.ClientType)

	h.recordHTTPMetrics("register", http.MethodPost, http.StatusCreated, startTime)
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", client.ClientID),
		attribute.String("oauth.client_type", client.ClientType),
	)
	instrumentation.SetSpanSuccess(span)

	// Build response
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	response := map[string]any{
		"client_id":                  client.ClientID,
		"client_name":                client.ClientName,
		"client_type":                client.ClientType,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
	}

	if clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, _ = r.BasicAuth()
	return
}

// authenticateClient validates client credentials from either Basic Auth or form parameters
// Returns the validated client or an error with the OAuth error code
func (h *Handler) authenticateClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	ctx := r.Context()

	// Get client credentials from Authorization header (if present)
	authClientID, authClientSecret := h.parseBasicAuth(r)
	if authClientID != "" {
		clientID = authClientID
	}

	if clientID == "" {
		return nil, ErrInvalidRequest("client_id is required")
	}

	// Fetch client
	client, err := h.server.GetClient(ctx, clientID)
	if err != nil {
		h.logger.Warn("Unknown client", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure("", clientID, clientIP, ErrorCodeInvalidClient)
		}
		return nil, ErrInvalidClient("Client authentication failed")
	}

	// CRITICAL SECURITY: Confidential clients MUST authenticate
	if client.ClientType == ClientTypeConfidential {
		if authClientSecret == "" {
			h.logger.Warn("Confidential client missing credentials", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "confidential_client_auth_required")
			}
			return nil, ErrInvalidClient("Client authentication required")
		}

		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			return nil, ErrInvalidClient("Client authentication failed")
		}
	}

	return client, nil
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token *oauth2.Token, scope string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := int64(time.Until(token.Expiry).Seconds())
	if expiresIn < 0 {
		expiresIn = 3600
	}

	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) writeError(w http.ResponseWriter, code, description string, status int) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	// MCP 2025-11-25: Include WWW-Authenticate header with resource_metadata for 401 responses
	// This helps clients discover the authorization server and required scopes
	if status == http.StatusUnauthorized {
		scope := ""
		if len(h.server.Config.DefaultChallengeScopes) > 0 {
			scope = strings.Join(h.server.Config.DefaultChallengeScopes, " ")
		}
		w.Header().Set("WWW-Authenticate", h.formatWWWAuthenticate(scope, code, description))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// formatWWWAuthenticate formats the WWW-Authenticate header value per RFC 6750 and RFC 9728
// It includes the resource_metadata URL for MCP 2025-11-25 compliance, along with optional
// scope, error, and error_description parameters.
//
// Parameters:
//   - scope: Space-separated list of scopes required (e.g., "files:read user:profile")
//   - error: OAuth error code (e.g., "invalid_token", "insufficient_scope")
//   - errorDesc: Human-readable error description
//
// Example output:
//
//	Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource",
//	       scope="files:read user:profile",
//	       error="invalid_token",
//	       error_description="Token has expired"
func (h *Handler) formatWWWAuthenticate(scope, error, errorDesc string) string {
	// Build the challenge parameters (excluding the Bearer scheme)
	var params []string

	// MUST: Include resource_metadata URL per MCP 2025-11-25
	resourceMetadataURL := h.server.Config.ProtectedResourceMetadataEndpoint()
	params = append(params, fmt.Sprintf(`resource_metadata="%s"`, resourceMetadataURL))

	// Optional: Include scope if configured
	if scope != "" {
		params = append(params, fmt.Sprintf(`scope="%s"`, scope))
	}

	// Optional: Include error code if provided
	if error != "" {
		params = append(params, fmt.Sprintf(`error="%s"`, error))
	}

	// Optional: Include error description if provided
	if errorDesc != "" {
		// Escape quotes in error description for proper formatting
		escapedDesc := strings.ReplaceAll(errorDesc, `"`, `\"`)
		params = append(params, fmt.Sprintf(`error_description="%s"`, escapedDesc))
	}

	// Format: "Bearer param1="value1", param2="value2"" per RFC 6750 Section 3
	// Note: Space after "Bearer", then comma-space between parameters
	return "Bearer " + strings.Join(params, ", ")
}

// ServeTokenIntrospection handles the RFC 7662 token introspection endpoint
// This allows resource servers to validate access tokens
// Security: Requires client authentication to prevent token scanning attacks
func (h *Handler) ServeTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
		return
	}

	// SECURITY: Require client authentication to prevent token scanning attacks
	// Per RFC 7662 Section 2.1: the authorization server MUST authenticate the client
	authClientID, authClientSecret := h.parseBasicAuth(r)
	var clientID string
	if authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for introspection", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "introspection_auth_failed")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	} else {
		// Try form parameter as fallback (but still require authentication)
		clientID = r.FormValue("client_id")
		if clientID == "" {
			// No client authentication provided - reject per RFC 7662 security considerations
			h.logger.Warn("Token introspection rejected: missing client authentication", "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", "", clientIP, "introspection_missing_auth")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication required for token introspection", http.StatusUnauthorized)
			return
		}
		// Client ID provided but no credentials - also reject
		h.logger.Warn("Token introspection rejected: client_id without credentials", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure("", clientID, clientIP, "introspection_missing_credentials")
		}
		h.writeError(w, ErrorCodeInvalidClient, "Client authentication required for token introspection", http.StatusUnauthorized)
		return
	}

	// Validate the token
	userInfo, err := h.server.ValidateToken(r.Context(), token)

	// Build introspection response per RFC 7662
	response := map[string]interface{}{
		"active": false,
	}

	if err == nil && userInfo != nil {
		// Token is valid and active
		response["active"] = true
		response["sub"] = userInfo.ID
		response["email"] = userInfo.Email
		response["email_verified"] = userInfo.EmailVerified

		// Optional claims
		if userInfo.Name != "" {
			response["name"] = userInfo.Name
		}
		if clientID != "" {
			response["client_id"] = clientID
		}
		response["token_type"] = "Bearer"
	} else {
		// Token is invalid or expired
		h.logger.Debug("Token introspection failed", "error", err, "ip", clientIP)
	}

	// Always return 200 OK per RFC 7662
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Context key for user info
type contextKey string

const userInfoKey contextKey = "user_info"

// UserInfoFromContext retrieves user info from the request context
func UserInfoFromContext(ctx context.Context) (*providers.UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoKey).(*providers.UserInfo)
	return userInfo, ok
}

// isValidAuthMethod checks if the given token endpoint auth method is supported
func isValidAuthMethod(method string) bool {
	for _, supported := range SupportedTokenAuthMethods {
		if method == supported {
			return true
		}
	}
	return false
}

// setCORSHeaders sets CORS headers if configured and the origin is allowed.
// Enables browser-based MCP clients to make cross-origin requests.
// Only applies if AllowedOrigins is configured, Origin header is present, and origin is allowed.
func (h *Handler) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	// Skip if CORS not configured
	if len(h.server.Config.CORS.AllowedOrigins) == 0 {
		return
	}

	// Skip if not a browser CORS request (no Origin header)
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Skip if origin not allowed
	if !h.isAllowedOrigin(origin) {
		h.logger.Debug("CORS request from disallowed origin", "origin", origin)
		return
	}

	// Set CORS headers for allowed origin
	// Echo back the specific origin rather than using "*" for security
	w.Header().Set("Access-Control-Allow-Origin", origin)

	// Set Vary header to ensure proper caching by browsers and CDNs
	// This prevents serving cached responses with wrong CORS headers to different origins
	w.Header().Add("Vary", "Origin")

	// Set credentials header if enabled (required for Bearer tokens)
	if h.server.Config.CORS.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Set preflight cache duration
	maxAge := h.server.Config.CORS.MaxAge
	if maxAge == 0 {
		maxAge = defaultCORSMaxAge
	}

	// Set allowed methods for preflight requests
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

	// Set allowed headers for preflight requests
	// Authorization: for Bearer tokens
	// Content-Type: for POST request bodies
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

	// Set max age for preflight cache
	w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", maxAge))
}

// isAllowedOrigin checks if the given origin is in the allowed origins list.
// Supports exact matching and wildcard "*" for development.
func (h *Handler) isAllowedOrigin(origin string) bool {
	// Check for wildcard (allow all origins)
	for _, allowed := range h.server.Config.CORS.AllowedOrigins {
		if allowed == "*" {
			h.logger.Warn("⚠️  CORS: Wildcard origin (*) allows ALL origins",
				"risk", "CSRF attacks possible from any website",
				"recommendation", "Use specific origins in production")
			return true
		}

		// Exact match (case-sensitive per CORS spec)
		if allowed == origin {
			return true
		}
	}

	return false
}

// ServePreflightRequest handles CORS preflight (OPTIONS) requests.
// Required for non-simple requests (POST with JSON, custom headers, etc.).
func (h *Handler) ServePreflightRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}

// recordHTTPMetrics records HTTP request metrics (total count and duration)
func (h *Handler) recordHTTPMetrics(endpoint, method string, status int, startTime time.Time) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	ctx := context.Background()

	// Record total requests with duration
	duration := time.Since(startTime).Seconds() * 1000 // convert to milliseconds
	metrics.RecordHTTPRequest(ctx, method, endpoint, status, duration)
}

// recordAuthorizationStarted records when an authorization flow is started
func (h *Handler) recordAuthorizationStarted(clientID string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordAuthorizationStarted(context.Background(), clientID)
}

// recordCallbackProcessed records when a callback is processed
func (h *Handler) recordCallbackProcessed(clientID string, success bool) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordCallbackProcessed(context.Background(), clientID, success)
}

// recordCodeExchanged records when an authorization code is exchanged
func (h *Handler) recordCodeExchanged(clientID, pkceMethod string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordCodeExchange(context.Background(), clientID, pkceMethod)
}

// recordTokenRefreshed records when a token is refreshed
func (h *Handler) recordTokenRefreshed(clientID string, rotated bool) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordTokenRefresh(context.Background(), clientID, rotated)
}

// recordTokenRevoked records when a token is revoked
func (h *Handler) recordTokenRevoked(clientID string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordTokenRevocation(context.Background(), clientID)
}

// recordClientRegistered records when a client is registered
func (h *Handler) recordClientRegistered(clientType string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordClientRegistration(context.Background(), clientType)
}
