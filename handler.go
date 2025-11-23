package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
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
		// Apply IP-based rate limiting BEFORE token validation
		if h.server.rateLimiter != nil {
			clientIP := security.GetClientIP(r, h.server.config.TrustProxy)
			if !h.server.rateLimiter.Allow(clientIP) {
				h.logger.Warn("Rate limit exceeded", "ip", clientIP)
		if h.server.auditor != nil {
			h.server.auditor.LogEvent(security.Event{
				Type:      "rate_limit_exceeded",
				IPAddress: clientIP,
				Details: map[string]any{
					"endpoint": r.URL.Path,
				},
			})
			h.server.auditor.LogRateLimitExceeded(clientIP, "")
		}
				w.Header().Set("Retry-After", "60")
				h.writeError(w, "rate_limit_exceeded", "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.writeError(w, "missing_token", "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.writeError(w, "invalid_token", "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		accessToken := parts[1]

	// Validate token with server
	userInfo, err := h.server.ValidateToken(r.Context(), accessToken)
	if err != nil {
		clientIP := security.GetClientIP(r, h.server.config.TrustProxy)
		h.logger.Warn("Token validation failed", "ip", clientIP, "error", err)
		// Audit logging is already done in ValidateToken
		h.writeError(w, "invalid_token", fmt.Sprintf("Token validation failed: %v", err), http.StatusUnauthorized)
		return
	}

		// Apply per-user rate limiting AFTER authentication
		// This is a separate, higher limit for authenticated users
		// (Placeholder for future per-user rate limiting)

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

	security.SetSecurityHeaders(w, h.server.config.Issuer)
	metadata := map[string]any{
		"resource": h.server.config.Issuer,
		"authorization_servers": []string{
			h.server.config.Issuer,
		},
		"bearer_methods_supported": []string{"header"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// ServeAuthorizationServerMetadata serves RFC 8414 Authorization Server Metadata
func (h *Handler) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	security.SetSecurityHeaders(w, h.server.config.Issuer)
	metadata := map[string]any{
		"issuer":                h.server.config.Issuer,
		"authorization_endpoint": h.server.config.Issuer + "/oauth/authorize",
		"token_endpoint":        h.server.config.Issuer + "/oauth/token",
		"response_types_supported": []string{"code"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
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
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if clientID == "" {
		h.writeError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}

	// Start authorization flow
	authURL, err := h.server.StartAuthorizationFlow(clientID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		h.writeError(w, "server_error", err.Error(), http.StatusInternalServerError)
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

	if state == "" || code == "" {
		h.writeError(w, "invalid_request", "state and code are required", http.StatusBadRequest)
		return
	}

	// Handle callback
	authCode, err := h.server.HandleProviderCallback(r.Context(), state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "error", err)
		h.writeError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to client with authorization code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authCode.RedirectURI, authCode.Code, state)
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
		h.writeError(w, "invalid_request", "Failed to parse request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		h.writeError(w, "unsupported_grant_type", fmt.Sprintf("Grant type %s not supported", grantType), http.StatusBadRequest)
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r, h.server.config.TrustProxy)
	
	// Parse parameters
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.auditor != nil {
				h.server.auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			h.writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	if code == "" || clientID == "" {
		h.writeError(w, "invalid_request", "code and client_id are required", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(r.Context(), code, clientID, redirectURI, codeVerifier)
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", clientID, "ip", clientIP, "error", err)
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("Token exchange successful", "client_id", clientID, "ip", clientIP)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r, h.server.config.TrustProxy)
	
	// Parse parameters
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.auditor != nil {
				h.server.auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			h.writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	if refreshToken == "" {
		h.writeError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(r.Context(), refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
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

	clientIP := security.GetClientIP(r, h.server.config.TrustProxy)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	clientID := r.FormValue("client_id")

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for revocation", "client_id", clientID, "ip", clientIP)
			if h.server.auditor != nil {
				h.server.auditor.LogAuthFailure("", clientID, clientIP, "revocation_auth_failed")
			}
			h.writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	if token == "" {
		h.writeError(w, "invalid_request", "token is required", http.StatusBadRequest)
		return
	}

	// Revoke token
	if err := h.server.RevokeToken(r.Context(), token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		// Per RFC 7009, return 200 even if revocation fails
	}

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get client IP for DoS protection
	clientIP := security.GetClientIP(r, h.server.config.TrustProxy)

	// Check per-IP registration limit to prevent DoS attacks
	maxClients := h.server.config.MaxClientsPerIP
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
		h.writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Register client with IP tracking
	client, clientSecret, err := h.server.RegisterClient(req.ClientName, req.ClientType, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "registration limit") {
			h.logger.Warn("Client registration limit exceeded", "ip", clientIP)
			h.writeError(w, "invalid_request", err.Error(), http.StatusTooManyRequests)
			return
		}
		h.logger.Error("Failed to register client", "error", err)
		h.writeError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	// Build response
	security.SetSecurityHeaders(w, h.server.config.Issuer)
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
	json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, _ = r.BasicAuth()
	return
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token *providers.TokenResponse, scope string) {
	security.SetSecurityHeaders(w, h.server.config.Issuer)
	
	expiresIn := int64(token.ExpiresAt.Sub(time.Now()).Seconds())
	if expiresIn < 0 {
		expiresIn = 3600
	}

	response := map[string]any{
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"expires_in":   expiresIn,
	}

	if token.RefreshToken != "" {
		response["refresh_token"] = token.RefreshToken
	}

	if scope != "" {
		response["scope"] = scope
	} else if len(token.Scopes) > 0 {
		response["scope"] = strings.Join(token.Scopes, " ")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) writeError(w http.ResponseWriter, code, description string, status int) {
	security.SetSecurityHeaders(w, h.server.config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// Context key for user info
type contextKey string

const userInfoKey contextKey = "user_info"

// UserInfoFromContext retrieves user info from the request context
func UserInfoFromContext(ctx context.Context) (*providers.UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoKey).(*providers.UserInfo)
	return userInfo, ok
}

