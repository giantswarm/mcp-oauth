package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// ServeAuthorizationServerMetadata serves the OAuth 2.0 Authorization Server Metadata (RFC 8414)
// This endpoint tells MCP clients about the authorization server endpoints
func (h *Handler) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := AuthorizationServerMetadata{
		Issuer:                            h.config.Resource,
		AuthorizationEndpoint:             h.config.Resource + "/oauth/authorize",
		TokenEndpoint:                     h.config.Resource + "/oauth/token",
		RegistrationEndpoint:              h.config.Resource + "/oauth/register",
		ScopesSupported:                   h.config.SupportedScopes,
		ResponseTypesSupported:            DefaultResponseTypes,
		GrantTypesSupported:               DefaultGrantTypes,
		TokenEndpointAuthMethodsSupported: SupportedTokenAuthMethods,
		CodeChallengeMethodsSupported:     SupportedCodeChallengeMethods,
	}

	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		h.logger.Error("Failed to encode authorization server metadata", "error", err)
	}
}

// ServeDynamicClientRegistration handles Dynamic Client Registration (RFC 7591)
func (h *Handler) ServeDynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// OAuth 2.1: Require authentication for client registration (secure by default)
	// Only allow unauthenticated registration if explicitly configured
	if !h.config.Security.AllowPublicClientRegistration {
		// Check for registration access token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.logger.Warn("Client registration rejected: missing authorization",
				"client_ip", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", "Bearer")
			h.writeError(w, "invalid_token",
				"Registration access token required. "+
					"Set AllowPublicClientRegistration=true to disable authentication (NOT recommended).",
				http.StatusUnauthorized)
			return
		}

		// Verify Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.logger.Warn("Client registration rejected: invalid authorization header",
				"client_ip", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", "Bearer")
			h.writeError(w, "invalid_token", "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Validate registration access token
		providedToken := parts[1]
		if h.config.Security.RegistrationAccessToken == "" {
			h.logger.Error("RegistrationAccessToken not configured but AllowPublicClientRegistration=false")
			h.writeError(w, "server_error",
				"Server configuration error: registration token not configured",
				http.StatusInternalServerError)
			return
		}

		if providedToken != h.config.Security.RegistrationAccessToken {
			h.logger.Warn("Client registration rejected: invalid registration token",
				"client_ip", r.RemoteAddr)
			h.writeError(w, "invalid_token", "Invalid registration access token", http.StatusUnauthorized)
			return
		}

		h.logger.Info("Client registration authenticated with valid token")
	} else {
		h.logger.Warn("⚠️  Unauthenticated client registration (DoS risk)",
			"client_ip", r.RemoteAddr)
	}

	// Parse registration request
	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid_request", "Failed to parse registration request", http.StatusBadRequest)
		return
	}

	// Validate redirect URIs (at least one required for authorization_code flow)
	if len(req.RedirectURIs) == 0 {
		h.writeError(w, "invalid_redirect_uri", "At least one redirect_uri is required", http.StatusBadRequest)
		return
	}

	// Validate redirect URIs with comprehensive security checks
	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri, h.config.Resource, h.config.Security.AllowCustomRedirectSchemes, h.config.Security.AllowedCustomSchemes); err != nil {
			h.writeError(w, "invalid_redirect_uri", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Check per-IP client registration limit for DoS protection
	clientIP := getClientIP(r, h.config.RateLimit.TrustProxy)
	if err := h.clientStore.CheckIPLimit(clientIP, h.config.Security.MaxClientsPerIP); err != nil {
		h.logger.Warn("Client registration limit exceeded",
			"client_ip", clientIP,
			"limit", h.config.Security.MaxClientsPerIP)
		h.writeError(w, "invalid_request",
			fmt.Sprintf("Client registration limit exceeded for your IP address (%d max)", h.config.Security.MaxClientsPerIP),
			http.StatusTooManyRequests)
		return
	}

	// Register the client
	resp, err := h.clientStore.RegisterClient(&req, clientIP)
	if err != nil {
		h.logger.Error("Failed to register client", "error", err)
		h.writeError(w, "server_error", "Failed to register client", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Client registered successfully",
		"client_id", resp.ClientID,
		"client_name", resp.ClientName,
	)

	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// ServeAuthorization handles the OAuth authorization endpoint
// This proxies the authorization request to Google
func (h *Handler) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if Google OAuth is configured
	if h.googleConfig == nil {
		h.logger.Error("Google OAuth not configured")
		h.writeError(w, "server_error", "OAuth proxy not configured", http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	scope := query.Get("scope")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")
	nonce := query.Get("nonce")

	// Validate required parameters
	if clientID == "" {
		h.writeError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}

	if redirectURI == "" {
		h.writeError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}

	// OAuth 2.1: state is REQUIRED for CSRF protection (secure by default)
	// Only allow missing state if explicitly configured (NOT recommended)
	if state == "" {
		if !h.config.Security.AllowInsecureAuthWithoutState {
			h.logger.Warn("Authorization request rejected: missing state parameter",
				"client_id", clientID,
				"redirect_uri", redirectURI)
			h.writeError(w, "invalid_request",
				"state parameter is required for CSRF protection. "+
					"Set Security.AllowInsecureAuthWithoutState=true to disable this check (NOT recommended for production).",
				http.StatusBadRequest)
			return
		}
		// Config allows insecure auth without state (user accepted the risk)
		h.logger.Warn("⚠️  Authorization request without state parameter (CSRF protection weakened)",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"security_risk", "CSRF attacks possible")
	}

	// Validate requested scopes
	if scope != "" {
		if err := h.validateScopes(scope); err != nil {
			h.writeError(w, "invalid_scope", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Validate client exists
	client, err := h.clientStore.GetClient(clientID)
	if err != nil {
		h.logger.Warn("Invalid client_id", "client_id", clientID, "error", err)
		h.writeError(w, "invalid_client", "Invalid client_id", http.StatusUnauthorized)
		return
	}

	// Validate redirect_uri
	if err := h.clientStore.ValidateRedirectURI(clientID, redirectURI); err != nil {
		h.logger.Warn("Invalid redirect_uri",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"error", err,
		)
		h.writeError(w, "invalid_request", "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// OAuth 2.1 requires PKCE for public clients
	if codeChallenge == "" && client.TokenEndpointAuthMethod == "none" {
		h.writeError(w, "invalid_request", "PKCE is required for public clients", http.StatusBadRequest)
		return
	}

	// Validate code challenge method if PKCE is used
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain" // Default to plain if not specified
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			h.writeError(w, "invalid_request", "Invalid code_challenge_method", http.StatusBadRequest)
			return
		}
	}

	// Generate Google state parameter
	googleState, err := generateSecureToken(StateTokenLength)
	if err != nil {
		h.logger.Error("Failed to generate state", "error", err)
		h.writeError(w, "server_error", "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Save authorization state
	now := time.Now().Unix()
	authState := &AuthorizationState{
		State:               state,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		GoogleState:         googleState,
		CreatedAt:           now,
		ExpiresAt:           now + int64(DefaultAuthorizationCodeTTL.Seconds()),
		Nonce:               nonce,
	}

	if err := h.flowStore.SaveAuthorizationState(authState); err != nil {
		h.logger.Error("Failed to save authorization state", "error", err)
		h.writeError(w, "server_error", "Failed to save state", http.StatusInternalServerError)
		return
	}

	// Build Google authorization URL
	googleAuthURL := h.googleConfig.AuthCodeURL(googleState,
		oauth2.AccessTypeOffline, // Request refresh token
		oauth2.ApprovalForce,     // Always show consent screen
	)

	h.logger.Info("Redirecting to Google for authorization",
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"google_state", googleState,
	)

	// Redirect to Google
	http.Redirect(w, r, googleAuthURL, http.StatusFound)
}

// ServeGoogleCallback handles the callback from Google OAuth
func (h *Handler) ServeGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	googleState := query.Get("state")
	code := query.Get("code")
	errorParam := query.Get("error")

	// Check for error from Google
	if errorParam != "" {
		errorDesc := query.Get("error_description")
		h.logger.Warn("Google OAuth error",
			"error", errorParam,
			"description", errorDesc,
		)
		http.Error(w, fmt.Sprintf("Google OAuth error: %s - %s", errorParam, errorDesc), http.StatusBadRequest)
		return
	}

	// Validate state and retrieve authorization state
	authState, err := h.flowStore.GetAuthorizationState(googleState)
	if err != nil {
		h.logger.Error("Invalid or expired state", "google_state", googleState, "error", err)
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for Google token
	ctx := context.Background()
	googleToken, err := h.googleConfig.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("Failed to exchange code for Google token", "error", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Get user info from Google
	userInfo, err := h.fetchGoogleUserInfo(ctx, googleToken.AccessToken)
	if err != nil {
		h.logger.Error("Failed to fetch Google user info", "error", err)
		http.Error(w, "Failed to fetch user information", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Google OAuth successful",
		"user_email", userInfo.Email,
		"client_id", authState.ClientID,
	)

	// Generate authorization code for the MCP client
	authCode, err := generateSecureToken(StateTokenLength)
	if err != nil {
		h.logger.Error("Failed to generate authorization code", "error", err)
		http.Error(w, "Failed to generate authorization code", http.StatusInternalServerError)
		return
	}

	// Save authorization code
	now := time.Now().Unix()
	authCodeData := &AuthorizationCode{
		Code:                authCode,
		ClientID:            authState.ClientID,
		RedirectURI:         authState.RedirectURI,
		Scope:               authState.Scope,
		CodeChallenge:       authState.CodeChallenge,
		CodeChallengeMethod: authState.CodeChallengeMethod,
		GoogleAccessToken:   googleToken.AccessToken,
		GoogleRefreshToken:  googleToken.RefreshToken,
		GoogleTokenExpiry:   googleToken.Expiry.Unix(),
		UserEmail:           userInfo.Email,
		CreatedAt:           now,
		ExpiresAt:           now + int64(DefaultAuthorizationCodeTTL.Seconds()),
		Used:                false,
	}

	if err := h.flowStore.SaveAuthorizationCode(authCodeData); err != nil {
		h.logger.Error("Failed to save authorization code", "error", err)
		http.Error(w, "Failed to save authorization code", http.StatusInternalServerError)
		return
	}

	// Clean up authorization state
	h.flowStore.DeleteAuthorizationState(googleState)

	// Build redirect URL with authorization code
	redirectURL, err := url.Parse(authState.RedirectURI)
	if err != nil {
		h.logger.Error("Invalid redirect URI", "redirect_uri", authState.RedirectURI, "error", err)
		http.Error(w, "Invalid redirect URI", http.StatusInternalServerError)
		return
	}

	redirectQuery := redirectURL.Query()
	redirectQuery.Set("code", authCode)
	// Only include state if the client provided one (OAuth 2.1 CSRF protection)
	if authState.State != "" {
		redirectQuery.Set("state", authState.State)
	}
	redirectURL.RawQuery = redirectQuery.Encode()

	h.logger.Info("Redirecting back to MCP client",
		"client_id", authState.ClientID,
		"redirect_uri", authState.RedirectURI,
	)

	// Redirect back to MCP client
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
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

// handleAuthorizationCodeGrant handles the authorization_code grant type
// Refactored to use helper functions for better readability and maintainability
func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	// Parse request parameters
	params, oauthErr := h.parseAuthCodeRequest(r)
	if oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Retrieve and validate authorization code
	authCode, oauthErr := h.validateAndRetrieveAuthCode(params)
	if oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Determine client ID (either from params or auth code)
	clientID := params.ClientID
	if clientID == "" {
		clientID = authCode.ClientID
	}

	// Validate PKCE if required
	if oauthErr := h.validatePKCE(authCode, params.CodeVerifier, clientID); oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Authenticate client
	_, oauthErr = h.authenticateClient(r, clientID)
	if oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Ensure Google token is fresh (refresh if needed)
	googleToken, oauthErr := h.ensureFreshGoogleToken(r.Context(), authCode)
	if oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Generate access token
	accessToken, err := generateSecureToken(AccessTokenLength)
	if err != nil {
		h.logger.Error("Failed to generate access token", "error", err)
		oauthErr := ErrServerError("Failed to generate access token")
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	// Store tokens (Google token and access token mapping)
	if oauthErr := h.storeTokens(authCode, googleToken, accessToken); oauthErr != nil {
		h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		return
	}

	h.logger.Info("Issued access token",
		"client_id", clientID,
		"user_email", authCode.UserEmail,
		"scope", authCode.Scope)

	// Calculate token expiry
	expiresIn := googleToken.Expiry.Unix() - time.Now().Unix()
	if expiresIn < 0 {
		expiresIn = int64(DefaultAccessTokenTTL.Seconds())
	}

	// Build token response
	tokenResp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       authCode.Scope,
	}

	// Issue refresh token if available
	if refreshToken, err := h.issueRefreshToken(authCode); err == nil && refreshToken != "" {
		tokenResp.RefreshToken = refreshToken
	}

	// Return token response
	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp)
}

// handleRefreshTokenGrant handles the refresh_token grant type
func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	// Validate required parameters
	if refreshToken == "" {
		h.writeError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Retrieve user email from refresh token
	userEmail, err := h.store.GetRefreshToken(refreshToken)
	if err != nil {
		h.logger.Warn("Invalid refresh token", "error", err)
		h.writeError(w, "invalid_grant", "Invalid or expired refresh token", http.StatusBadRequest)
		return
	}

	// Get the stored Google token for this user
	googleToken, err := h.store.GetGoogleToken(userEmail)
	if err != nil {
		h.logger.Warn("No Google token found for refresh",
			"email", userEmail,
			"error", err)
		h.writeError(w, "invalid_grant", "User token not found. Please re-authenticate.", http.StatusBadRequest)
		return
	}

	// Validate client if client_id provided
	if clientID != "" {
		// Authenticate client
		_, err := h.clientStore.GetClient(clientID)
		if err != nil {
			h.logger.Warn("Invalid client_id in refresh", "client_id", clientID, "error", err)
			h.writeError(w, "invalid_client", "Invalid client", http.StatusUnauthorized)
			return
		}

		// For confidential clients, validate client secret
		// (similar to authorization code grant)
		// For now, we accept public clients without secret validation
	}

	// Attempt to refresh the Google token if needed
	if h.CanRefreshTokens() && googleToken.RefreshToken != "" {
		newToken, refreshErr := refreshGoogleToken(r.Context(), googleToken, h.googleConfig, h.httpClient)
		if refreshErr == nil {
			// Successfully refreshed - use the new token
			h.logger.Info("Google token refreshed via refresh_token grant", "email", userEmail)
			googleToken = newToken
			// Save the refreshed Google token
			if saveErr := h.store.SaveGoogleToken(userEmail, newToken); saveErr != nil {
				h.logger.Warn("Failed to save refreshed Google token",
					"email", userEmail,
					"error", saveErr)
			}
		} else {
			// Refresh failed - token might be revoked
			h.logger.Warn("Failed to refresh Google token",
				"email", userEmail,
				"error", refreshErr)
			h.writeError(w, "invalid_grant", "Token refresh failed. Please re-authenticate.", http.StatusBadRequest)
			return
		}
	}

	// Generate new access token
	accessToken, err := generateSecureToken(AccessTokenLength)
	if err != nil {
		h.logger.Error("Failed to generate access token", "error", err)
		h.writeError(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Calculate token expiry
	expiresIn := int64(DefaultAccessTokenTTL.Seconds())
	if !googleToken.Expiry.IsZero() {
		expiresIn = googleToken.Expiry.Unix() - time.Now().Unix()
		if expiresIn < 0 {
			expiresIn = int64(DefaultAccessTokenTTL.Seconds())
		}
	}

	// Map the new access token to the Google token
	if err := h.store.SaveGoogleToken(accessToken, googleToken); err != nil {
		h.logger.Error("Failed to map access token", "error", err)
		h.writeError(w, "server_error", "Failed to store token", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Issued new access token via refresh_token grant",
		"email", userEmail)

	// Return token response
	tokenResp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}

	// OAuth 2.1: Implement refresh token rotation (secure by default)
	// Issue a new refresh token and invalidate the old one
	if !h.config.Security.DisableRefreshTokenRotation {
		// Generate new refresh token
		newRefreshToken, rotateErr := generateSecureToken(RefreshTokenLength)
		if rotateErr == nil {
			// Calculate new refresh token expiry
			refreshTokenExpiresAt := time.Now().Add(h.config.Security.RefreshTokenTTL).Unix()

			// Invalidate old refresh token
			h.store.DeleteRefreshToken(refreshToken)

			// Store new refresh token
			if saveErr := h.store.SaveRefreshToken(newRefreshToken, userEmail, refreshTokenExpiresAt); saveErr != nil {
				h.logger.Warn("Failed to store rotated refresh token",
					"email", userEmail,
					"error", saveErr)
				// Fall back to old refresh token
				tokenResp.RefreshToken = refreshToken
			} else {
				tokenResp.RefreshToken = newRefreshToken
				h.logger.Info("Refresh token rotated (OAuth 2.1 security)",
					"email", userEmail,
					"expires_at", time.Unix(refreshTokenExpiresAt, 0))
			}
		} else {
			h.logger.Warn("Failed to generate rotated refresh token",
				"email", userEmail,
				"error", rotateErr)
			// Fall back to old refresh token
			tokenResp.RefreshToken = refreshToken
		}
	} else {
		// Rotation disabled - return the same refresh token (insecure)
		h.logger.Warn("⚠️  Refresh token rotation DISABLED - returning same token (security risk)",
			"email", userEmail)
		tokenResp.RefreshToken = refreshToken
	}

	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp)
}

// validateScopes validates that requested Google API scopes are supported
// Non-Google scopes (e.g., mcp:tools, openid) are logged but not rejected
func (h *Handler) validateScopes(scope string) error {
	if scope == "" {
		return nil // Empty scope is valid
	}

	// Split space-separated scopes
	requestedScopes := strings.Split(scope, " ")

	for _, requested := range requestedScopes {
		requested = strings.TrimSpace(requested)
		if requested == "" {
			continue
		}

		// Only validate Google API scopes (start with https://)
		// Other scopes (like mcp:tools, openid) are ignored since we don't enforce them
		isGoogleScope := len(requested) > 8 && requested[:8] == "https://"
		if !isGoogleScope {
			// Non-Google scope - log but don't reject
			// MCP clients may send protocol scopes we don't enforce
			h.logger.Debug("Ignoring non-Google scope",
				"scope", requested,
				"reason", "not enforced by this server")
			continue
		}

		// Validate Google API scopes against our supported list
		found := false
		for _, supported := range h.config.SupportedScopes {
			if requested == supported {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("unsupported Google API scope: %s", requested)
		}
	}

	return nil
}

// validateRedirectURI validates a redirect URI according to OAuth 2.0 Security Best Current Practice
func validateRedirectURI(uri string, serverResource string, allowCustomSchemes bool, allowedSchemes []string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %s", uri)
	}

	// Reject fragments (OAuth 2.0 Security BCP Section 4.1.3)
	if parsed.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain fragments: %s", uri)
	}

	// Must have a scheme
	if parsed.Scheme == "" {
		return fmt.Errorf("redirect_uri must have a scheme: %s", uri)
	}

	// Handle custom schemes (for native apps like com.example.app:// or myapp://callback)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		if !allowCustomSchemes {
			return fmt.Errorf("custom redirect_uri schemes not allowed (only http/https permitted). Set AllowCustomRedirectSchemes=true to enable")
		}

		// Validate against dangerous schemes
		schemeLower := strings.ToLower(parsed.Scheme)
		for _, dangerous := range DangerousSchemes {
			if schemeLower == dangerous {
				return fmt.Errorf("redirect_uri scheme '%s' is not allowed for security reasons", parsed.Scheme)
			}
		}

		// Validate against allowed patterns
		if len(allowedSchemes) > 0 {
			schemeValid := false
			for _, pattern := range allowedSchemes {
				// Use simple pattern matching (for now, exact match or regex)
				matched, matchErr := regexp.MatchString(pattern, schemeLower)
				if matchErr != nil {
					return fmt.Errorf("invalid scheme pattern '%s': %w", pattern, matchErr)
				}
				if matched {
					schemeValid = true
					break
				}
			}
			if !schemeValid {
				return fmt.Errorf("redirect_uri scheme '%s' does not match allowed patterns (must match one of: %v)",
					parsed.Scheme, allowedSchemes)
			}
		}

		// Custom scheme is valid
		return nil
	}

	// For http/https schemes, require host
	if parsed.Host == "" {
		return fmt.Errorf("http/https redirect_uri must have a host: %s", uri)
	}

	// Determine if we're in production (not localhost)
	serverURL, err := url.Parse(serverResource)
	if err != nil {
		// If we can't parse server resource, be conservative
		return fmt.Errorf("cannot validate redirect_uri: invalid server resource")
	}

	isProduction := !isLoopback(serverURL.Hostname())

	// OAuth 2.0 Security BCP: Loopback redirect URIs are always allowed for local development
	// even in production environments (they can't be intercepted since they're local)
	isLoopbackRedirect := isLoopback(parsed.Hostname())

	if isProduction && !isLoopbackRedirect {
		// In production, require HTTPS for non-localhost redirect URIs
		if parsed.Scheme != "https" {
			return fmt.Errorf("redirect_uri must use HTTPS in production (non-localhost redirects): %s", uri)
		}
	}

	return nil
}

// isLoopback checks if a hostname is a loopback address
func isLoopback(hostname string) bool {
	// Normalize hostname (remove brackets for IPv6)
	hostname = strings.Trim(hostname, "[]")

	// Check against recognized loopback addresses
	for _, loopback := range LoopbackAddresses {
		if hostname == loopback {
			return true
		}
	}

	// Also check for 127.x.x.x range and localhost with port
	return strings.HasPrefix(hostname, "127.") || strings.HasPrefix(hostname, "localhost:")
}

// fetchGoogleUserInfo fetches user info from Google
func (h *Handler) fetchGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google userinfo returned status %d", resp.StatusCode)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}
