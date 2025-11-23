package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	oauth2google "golang.org/x/oauth2/google"
)

// Note: Config is now defined in config.go

// Handler implements OAuth 2.1 endpoints for the MCP server
// It acts as both an OAuth 2.1 Authorization Server (proxying to Google)
// and an OAuth 2.1 Resource Server (validating tokens)
type Handler struct {
	config          *Config
	store           *Store         // Token store for resource server functionality
	clientStore     *ClientStore   // Client registration store for authorization server
	flowStore       *FlowStore     // OAuth flow state management
	rateLimiter     *RateLimiter   // Optional IP-based rate limiter for protecting endpoints
	userRateLimiter *RateLimiter   // Optional user-based rate limiter for authenticated requests
	googleConfig    *oauth2.Config // Google OAuth config for proxying to Google
	httpClient      *http.Client   // Custom HTTP client for OAuth requests
	logger          *slog.Logger
	auditLogger     *AuditLogger     // Security audit logger
	encryption      *TokenEncryption // Token encryption for at-rest security
}

// NewHandler creates a new OAuth handler
func NewHandler(config *Config) (*Handler, error) {
	if config.Resource == "" {
		return nil, fmt.Errorf("resource is required")
	}

	// Validate Resource URL and enforce HTTPS in production
	parsedURL, err := url.Parse(config.Resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URL: %w", err)
	}

	// Allow HTTP only for localhost/loopback addresses (development)
	// Require HTTPS for all other addresses (production)
	if parsedURL.Scheme != "https" {
		hostname := parsedURL.Hostname()
		if hostname != "localhost" &&
			hostname != "127.0.0.1" &&
			hostname != "::1" &&
			hostname != "[::1]" {
			return nil, fmt.Errorf("resource must use HTTPS in production (got %s://)", parsedURL.Scheme)
		}
	}

	// Set default scopes if none provided
	if len(config.SupportedScopes) == 0 {
		config.SupportedScopes = []string{"openid", "email"}
	}

	// Set default cleanup interval if not specified
	if config.CleanupInterval == 0 {
		config.CleanupInterval = DefaultCleanupInterval
	}

	// Set default logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// ============================================================
	// Set Secure Defaults for Security Configuration
	// ============================================================

	// Refresh token TTL defaults to 90 days (security vs usability balance)
	if config.Security.RefreshTokenTTL == 0 {
		config.Security.RefreshTokenTTL = DefaultRefreshTokenTTL
	}

	// Max clients per IP defaults to 10 to prevent DoS
	if config.Security.MaxClientsPerIP == 0 {
		config.Security.MaxClientsPerIP = DefaultMaxClientsPerIP
	}

	// AllowCustomRedirectSchemes defaults to true for native app support
	// Note: Go bool zero value is false, so we need explicit check
	// If not explicitly set to false in a previous version, we allow custom schemes
	// This is safe because AllowedCustomSchemes provides validation
	if config.Security.AllowedCustomSchemes == nil {
		config.Security.AllowCustomRedirectSchemes = true // Explicit default for clarity
		config.Security.AllowedCustomSchemes = DefaultRFC3986SchemePattern
	}

	// Log security configuration warnings
	if config.Security.AllowInsecureAuthWithoutState {
		logger.Warn("⚠️  SECURITY WARNING: State parameter is OPTIONAL (CSRF protection weakened)",
			"recommendation", "Set Security.AllowInsecureAuthWithoutState=false for production")
	}
	if config.Security.DisableRefreshTokenRotation {
		logger.Warn("⚠️  SECURITY WARNING: Refresh token rotation is DISABLED",
			"recommendation", "Set Security.DisableRefreshTokenRotation=false for production")
	}
	if config.Security.AllowPublicClientRegistration {
		logger.Warn("⚠️  SECURITY WARNING: Public client registration is ENABLED (DoS risk)",
			"recommendation", "Set Security.AllowPublicClientRegistration=false and use RegistrationAccessToken")
	}

	// Create IP-based rate limiter if configured
	var rateLimiter *RateLimiter
	if config.RateLimit.Rate > 0 {
		burst := config.RateLimit.Burst
		if burst == 0 {
			burst = config.RateLimit.Rate * 2 // Default burst is 2x rate
		}
		cleanupInterval := config.RateLimit.CleanupInterval
		if cleanupInterval == 0 {
			cleanupInterval = DefaultRateLimitCleanupInterval
		}
		rateLimiter = NewRateLimiter(config.RateLimit.Rate, burst, config.RateLimit.TrustProxy, cleanupInterval, logger)
		logger.Info("IP-based rate limiting enabled",
			"rate", config.RateLimit.Rate,
			"burst", burst)
	}

	// Create user-based rate limiter if configured
	var userRateLimiter *RateLimiter
	if config.RateLimit.UserRate > 0 {
		burst := config.RateLimit.UserBurst
		if burst == 0 {
			burst = config.RateLimit.UserRate * 2 // Default burst is 2x rate
		}
		cleanupInterval := config.RateLimit.CleanupInterval
		if cleanupInterval == 0 {
			cleanupInterval = DefaultRateLimitCleanupInterval
		}
		// User rate limiter doesn't need TrustProxy since it uses email addresses
		userRateLimiter = NewRateLimiter(config.RateLimit.UserRate, burst, false, cleanupInterval, logger)
		logger.Info("User-based rate limiting enabled",
			"rate", config.RateLimit.UserRate,
			"burst", burst)
	}

	// Create Google OAuth config for OAuth proxy
	// This is REQUIRED for OAuth proxy mode
	var googleConfig *oauth2.Config
	if config.GoogleAuth.ClientID != "" && config.GoogleAuth.ClientSecret != "" {
		// Set default redirect URL if not specified
		redirectURL := config.GoogleAuth.RedirectURL
		if redirectURL == "" {
			redirectURL = config.Resource + "/oauth/google/callback"
		}

		googleConfig = &oauth2.Config{
			ClientID:     config.GoogleAuth.ClientID,
			ClientSecret: config.GoogleAuth.ClientSecret,
			Endpoint:     oauth2google.Endpoint,
			Scopes:       config.SupportedScopes,
			RedirectURL:  redirectURL,
		}
		logger.Info("OAuth proxy mode enabled with Google credentials",
			"redirect_url", redirectURL)
	} else {
		logger.Warn("OAuth proxy disabled: Google OAuth credentials not provided")
	}

	store := NewStoreWithInterval(config.CleanupInterval)
	store.SetLogger(logger)

	// Create client store for Dynamic Client Registration
	clientStore := NewClientStore(logger)

	// Create flow store for OAuth authorization flows
	flowStore := NewFlowStore(logger)

	// Initialize audit logger if enabled
	var auditLogger *AuditLogger
	if config.Security.EnableAuditLogging {
		auditLogger = NewAuditLogger(logger)
		logger.Info("Security audit logging enabled")
	}

	// Initialize token encryption if key provided
	encryption, err := NewTokenEncryption(config.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}
	if encryption.enabled {
		logger.Info("Token encryption at rest enabled (AES-256-GCM)")
	} else {
		logger.Warn("⚠️  SECURITY WARNING: Token encryption is DISABLED - tokens stored in plaintext",
			"recommendation", "Set Security.EncryptionKey to enable encryption")
	}

	// Use custom HTTP client if provided, otherwise use default
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &Handler{
		config:          config,
		store:           store,
		clientStore:     clientStore,
		flowStore:       flowStore,
		rateLimiter:     rateLimiter,
		userRateLimiter: userRateLimiter,
		googleConfig:    googleConfig,
		httpClient:      httpClient,
		logger:          logger,
		auditLogger:     auditLogger,
		encryption:      encryption,
	}, nil
}

// GetStore returns the underlying store (for testing and token management)
func (h *Handler) GetStore() *Store {
	return h.store
}

// GetConfig returns the OAuth configuration
func (h *Handler) GetConfig() *Config {
	return h.config
}

// CanRefreshTokens returns true if the handler can refresh tokens
func (h *Handler) CanRefreshTokens() bool {
	return h.googleConfig != nil && h.googleConfig.ClientID != ""
}

// ServeProtectedResourceMetadata serves the OAuth 2.0 Protected Resource Metadata (RFC 9728)
// This endpoint tells MCP clients where to find the authorization server
//
// The MCP client will:
// 1. Make an unauthenticated request to the MCP server
// 2. Receive a 401 with WWW-Authenticate header pointing to this endpoint
// 3. Fetch this metadata to discover the authorization server
// 4. Optionally use Dynamic Client Registration to register
// 5. Use the OAuth 2.1 flow (which proxies to Google) to obtain an access token
// 6. Include the token in subsequent requests to the MCP server
func (h *Handler) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Point to the MCP server as the authorization server (OAuth proxy mode)
	// MCP clients will use the authorization server metadata endpoint
	// which will then proxy the OAuth flow to Google
	metadata := ProtectedResourceMetadata{
		Resource: h.config.Resource,
		AuthorizationServers: []string{
			h.config.Resource, // Point to ourselves as the authorization server
		},
		BearerMethodsSupported: []string{
			"header", // Authorization: Bearer <token>
		},
		ScopesSupported: h.config.SupportedScopes,
	}

	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		h.logger.Error("Failed to encode metadata", "error", err)
		http.Error(w, "Failed to encode metadata", http.StatusInternalServerError)
	}
}

// setSecurityHeaders sets security headers on HTTP responses
func (h *Handler) setSecurityHeaders(w http.ResponseWriter) {
	// Prevent clickjacking attacks
	w.Header().Set("X-Frame-Options", "DENY")

	// Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Enable XSS protection in browsers
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Content Security Policy - restrict resource loading
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

	// Referrer policy - don't leak referrer information
	w.Header().Set("Referrer-Policy", "no-referrer")

	// For HTTPS resources, enforce HTTPS for 1 year
	// Only set HSTS if the current request is HTTPS
	if h.config.Resource != "" {
		parsedURL, err := url.Parse(h.config.Resource)
		if err == nil && parsedURL.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
	}
}

// writeError is a helper to write OAuth error responses
func (h *Handler) writeError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	h.logger.Debug("OAuth error", "code", errorCode, "description", description, "status", statusCode)
	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// RevokeToken revokes a Google OAuth token for a specific user
// This revokes the token at Google and removes it from the store, forcing re-authentication
func (h *Handler) RevokeToken(email string) error {
	h.logger.Info("Revoking token", "email", email)

	// Get the Google token first so we can revoke it at Google
	token, err := h.store.GetGoogleToken(email)
	if err == nil && token != nil && token.AccessToken != "" {
		// Revoke at Google's revocation endpoint
		revokeURL := "https://oauth2.googleapis.com/revoke"
		data := url.Values{}
		data.Set("token", token.AccessToken)

		resp, revokeErr := h.httpClient.PostForm(revokeURL, data)
		if revokeErr != nil {
			h.logger.Warn("Failed to revoke token at Google",
				"email", email,
				"error", revokeErr)
			// Continue with local deletion even if Google revocation fails
		} else {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				h.logger.Warn("Google token revocation returned non-OK status",
					"email", email,
					"status", resp.StatusCode)
			} else {
				h.logger.Info("Successfully revoked token at Google", "email", email)
			}
		}
	}

	// Delete from local store
	return h.store.DeleteGoogleToken(email)
}

// ServeRevoke handles token revocation requests
// POST /oauth/revoke with {"email": "user@example.com"}
func (h *Handler) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid_request", "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		h.writeError(w, "invalid_request", "Email is required", http.StatusBadRequest)
		return
	}

	// Revoke the token
	if err := h.RevokeToken(req.Email); err != nil {
		h.writeError(w, "server_error", fmt.Sprintf("Failed to revoke token: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success
	h.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Token revoked for %s", req.Email),
	})
}
