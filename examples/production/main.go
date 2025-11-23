// Package main demonstrates production-ready OAuth 2.1 setup for MCP servers.
//
// This example includes all security features enabled:
// - Token encryption at rest (AES-256-GCM)
// - Refresh token rotation
// - Comprehensive audit logging
// - Rate limiting (per-IP and per-user)
// - Secure client registration
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
)

func main() {
	// Setup structured logging for production
	logger := setupLogger()

	// Load or generate encryption key
	encryptionKey, err := loadEncryptionKey()
	if err != nil {
		log.Fatalf("Failed to load encryption key: %v", err)
	}

	// Generate secure registration token
	registrationToken := getEnvOrGenerate("OAUTH_REGISTRATION_TOKEN")

	// Production configuration with all security features
	config := &oauth.Config{
		// Resource identifier (must be HTTPS in production)
		Resource: getEnvOrDefault("MCP_RESOURCE", "https://mcp.example.com"),

		// Google API scopes
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/drive.readonly",
			"https://www.googleapis.com/auth/calendar.readonly",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},

		// Google OAuth credentials
		GoogleAuth: oauth.GoogleAuthConfig{
			ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
			ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  getEnvOrDefault("GOOGLE_REDIRECT_URL", ""),
		},

		// Rate limiting configuration
		RateLimit: oauth.RateLimitConfig{
			Rate:            10,   // 10 requests/second per IP
			Burst:           20,   // Allow bursts up to 20
			UserRate:        100,  // 100 requests/second per authenticated user
			UserBurst:       200,  // Allow user bursts up to 200
			TrustProxy:      getBoolEnv("TRUST_PROXY", false),
			CleanupInterval: 5 * time.Minute,
		},

		// Security configuration (production-ready)
		Security: oauth.SecurityConfig{
			// Enable token encryption at rest
			EncryptionKey: encryptionKey,

			// Enable comprehensive audit logging
			EnableAuditLogging: true,

			// Enable refresh token rotation (OAuth 2.1)
			DisableRefreshTokenRotation: false,

			// Require authentication for client registration
			AllowPublicClientRegistration: false,
			RegistrationAccessToken:       registrationToken,

			// Token TTL settings
			RefreshTokenTTL: 90 * 24 * time.Hour, // 90 days

			// Security limits
			MaxClientsPerIP: 10,

			// Allow custom redirect schemes for native apps
			AllowCustomRedirectSchemes: true,

			// State parameter required (CSRF protection)
			AllowInsecureAuthWithoutState: false,
		},

		// Token cleanup interval
		CleanupInterval: 1 * time.Minute,

		// Structured logger
		Logger: logger,

		// Custom HTTP client with timeouts
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Create OAuth handler
	handler, err := oauth.NewHandler(config)
	if err != nil {
		log.Fatalf("Failed to create OAuth handler: %v", err)
	}

	// Setup HTTP routes
	mux := setupRoutes(handler, logger)

	// HTTP server configuration
	server := &http.Server{
		Addr:         getEnvOrDefault("LISTEN_ADDR", ":8443"),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Log startup information
	logger.Info("Starting MCP server",
		"addr", server.Addr,
		"encryption", "enabled",
		"audit_logging", "enabled",
		"rate_limiting", "enabled",
		"registration_token", registrationToken[:8]+"...",
	)

	// Start server (use TLS in production)
	if tlsCert := os.Getenv("TLS_CERT_FILE"); tlsCert != "" {
		tlsKey := getEnvOrFail("TLS_KEY_FILE")
		logger.Info("Starting HTTPS server", "cert", tlsCert)
		log.Fatal(server.ListenAndServeTLS(tlsCert, tlsKey))
	} else {
		logger.Warn("Starting HTTP server - use HTTPS in production!")
		log.Fatal(server.ListenAndServe())
	}
}

func setupRoutes(handler *oauth.Handler, logger *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()

	// OAuth metadata endpoints
	mux.HandleFunc("/.well-known/oauth-protected-resource",
		logRequest(logger, handler.ServeProtectedResourceMetadata))
	mux.HandleFunc("/.well-known/oauth-authorization-server",
		logRequest(logger, handler.ServeAuthorizationServerMetadata))

	// OAuth endpoints
	mux.HandleFunc("/oauth/authorize",
		logRequest(logger, handler.ServeAuthorization))
	mux.HandleFunc("/oauth/token",
		logRequest(logger, handler.ServeToken))
	mux.HandleFunc("/oauth/google/callback",
		logRequest(logger, handler.ServeGoogleCallback))
	mux.HandleFunc("/oauth/register",
		logRequest(logger, handler.ServeClientRegistration))
	mux.HandleFunc("/oauth/revoke",
		logRequest(logger, handler.ServeTokenRevocation))

	// Protected MCP endpoint
	mux.Handle("/mcp", handler.ValidateGoogleToken(mcpHandler(logger)))

	// Health and readiness checks
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/ready", readinessHandler)

	// Metrics endpoint (optional)
	if getBoolEnv("ENABLE_METRICS", false) {
		mux.HandleFunc("/metrics", metricsHandler)
	}

	return mux
}

func mcpHandler(logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := oauth.UserInfoFromContext(r.Context())
		if !ok {
			logger.Error("No user info in context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		logger.Info("MCP request",
			"user", userInfo.Email,
			"method", r.Method,
			"path", r.URL.Path,
		)

		// Your MCP logic here
		response := map[string]interface{}{
			"message": "Welcome to production MCP server",
			"user": map[string]string{
				"email": userInfo.Email,
				"name":  userInfo.Name,
				"id":    userInfo.Sub,
			},
			"timestamp": time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		fmt.Fprintf(w, `{"message":"%s","user":{"email":"%s","name":"%s","id":"%s"}}`,
			response["message"], userInfo.Email, userInfo.Name, userInfo.Sub)
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// Add actual readiness checks here (database, external services, etc.)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Implement metrics export (Prometheus, etc.)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("# HELP oauth_requests_total Total OAuth requests\n"))
	w.Write([]byte("# TYPE oauth_requests_total counter\n"))
	w.Write([]byte("oauth_requests_total 0\n"))
}

// Helper functions

func setupLogger() *slog.Logger {
	var handler slog.Handler
	
	if getBoolEnv("LOG_JSON", true) {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(),
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(),
		})
	}
	
	return slog.New(handler)
}

func getLogLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func loadEncryptionKey() ([]byte, error) {
	// Try to load from environment (base64 encoded)
	if keyStr := os.Getenv("OAUTH_ENCRYPTION_KEY"); keyStr != "" {
		return oauth.EncryptionKeyFromBase64(keyStr)
	}

	// Try to load from file
	if keyFile := os.Getenv("OAUTH_ENCRYPTION_KEY_FILE"); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		return oauth.EncryptionKeyFromBase64(string(data))
	}

	// Generate new key (development only!)
	log.Println("WARNING: Generating new encryption key - tokens won't persist across restarts")
	log.Println("For production, set OAUTH_ENCRYPTION_KEY environment variable")
	
	key, err := oauth.GenerateEncryptionKey()
	if err != nil {
		return nil, err
	}
	
	log.Printf("Generated encryption key: %s", oauth.EncryptionKeyToBase64(key))
	return key, nil
}

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvOrGenerate(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	
	// Generate secure random token
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	
	generated := base64.URLEncoding.EncodeToString(token)
	log.Printf("Generated %s: %s", key, generated)
	log.Printf("Set this in your environment to persist: export %s='%s'", key, generated)
	
	return generated
}

func getBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

func logRequest(logger *slog.Logger, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Info("Request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		handler(w, r)
		logger.Info("Response",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
		)
	}
}

