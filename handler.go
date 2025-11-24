package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Handler is a thin HTTP adapter for the OAuth Server.
// It handles HTTP requests and delegates to the Server for business logic.
type Handler struct {
	server *Server
	logger *slog.Logger
}

// NewHandler creates a new HTTP handler
func NewHandler(server *Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		server: server,
		logger: logger,
	}
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
				if h.server.Auditor != nil {
					h.server.Auditor.LogEvent(security.Event{
						Type:      "rate_limit_exceeded",
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

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	metadata := map[string]any{
		"issuer":                           h.server.Config.Issuer,
		"authorization_endpoint":           h.server.Config.Issuer + "/oauth/authorize",
		"token_endpoint":                   h.server.Config.Issuer + "/oauth/token",
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// ServeAuthorization handles OAuth authorization requests
func (h *Handler) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if clientID == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: State parameter is required for CSRF protection
	// Enforce minimum length to prevent timing attacks and ensure sufficient entropy
	if state == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "state parameter is required for CSRF protection", http.StatusBadRequest)
		return
	}
	if len(state) < MinStateLength {
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Start authorization flow with client state
	authURL, err := h.server.StartAuthorizationFlow(clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, state)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		h.writeError(w, ErrorCodeServerError, "Failed to start authorization flow", http.StatusInternalServerError)
		return
	}

	// Redirect to provider
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ServeCallback handles the OAuth provider callback
func (h *Handler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse callback parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	// Check for provider errors
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		h.logger.Warn("Provider returned error", "error", errorParam, "description", errorDesc)
		h.writeError(w, errorParam, errorDesc, http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: Validate state and code parameters
	// State must meet minimum length requirements to prevent timing attacks
	if state == "" || code == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "state and code are required", http.StatusBadRequest)
		return
	}
	if len(state) < MinStateLength {
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Handle callback (state here is the provider state, not client state)
	authCode, clientState, err := h.server.HandleProviderCallback(r.Context(), state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "error", err)
		h.writeError(w, ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
		return
	}

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
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		// authenticateClient returns OAuthError, extract details
		if oauthErr, ok := err.(*OAuthError); ok {
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(r.Context(), code, client.ClientID, redirectURI, codeVerifier)
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", client.ClientID, "ip", clientIP, "error", err)
		// SECURITY: Don't leak internal error details to client
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
		return
	}

	h.logger.Info("Token exchange successful", "client_id", client.ClientID, "ip", clientIP)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshToken == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(r.Context(), refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		// SECURITY: Don't leak internal error details to client
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, ErrorCodeInvalidGrant, "Refresh token is invalid or expired", http.StatusBadRequest)
		return
	}

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, "")
}

// ServeTokenRevocation handles the RFC 7009 token revocation endpoint
func (h *Handler) ServeTokenRevocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	clientID := r.FormValue("client_id")

	if token == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for revocation", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "revocation_auth_failed")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	// Revoke token
	if err := h.server.RevokeToken(r.Context(), token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		// Per RFC 7009, return 200 even if revocation fails
	}

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
			w.Header().Set("WWW-Authenticate", "Bearer")
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
			w.Header().Set("WWW-Authenticate", "Bearer")
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

		if providedToken != h.server.Config.RegistrationAccessToken {
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

	// Check per-IP registration limit to prevent DoS attacks
	maxClients := h.server.Config.MaxClientsPerIP
	if maxClients == 0 {
		maxClients = 10 // Default limit
	}

	// Parse registration request
	var req struct {
		ClientName   string   `json:"client_name"`
		ClientType   string   `json:"client_type"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Register client with IP tracking
	client, clientSecret, err := h.server.RegisterClient(req.ClientName, req.ClientType, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "registration limit") {
			h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
			// SECURITY: Generic error message to prevent enumeration
			h.writeError(w, ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
			return
		}
		h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
		// SECURITY: Don't leak internal error details
		h.writeError(w, ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
		return
	}

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
	// Get client credentials from Authorization header (if present)
	authClientID, authClientSecret := h.parseBasicAuth(r)
	if authClientID != "" {
		clientID = authClientID
	}

	if clientID == "" {
		return nil, ErrInvalidRequest("client_id is required")
	}

	// Fetch client
	client, err := h.server.GetClient(clientID)
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
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// ServeTokenIntrospection handles the RFC 7662 token introspection endpoint
// This allows resource servers to validate access tokens
// Security: Requires client authentication to prevent token scanning attacks
func (h *Handler) ServeTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
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
