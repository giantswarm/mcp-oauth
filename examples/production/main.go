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
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// Setup structured logging for production
	logger := setupLogger()

	// Load or generate encryption key
	encryptionKey, err := loadEncryptionKey()
	if err != nil {
		log.Fatalf("Failed to load encryption key: %v", err)
	}

	// 1. Create provider (Google in this case)
	googleProvider, err := google.NewProvider(&google.Config{
		ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
		ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  getEnvOrDefault("GOOGLE_REDIRECT_URL", "http://localhost:8443/oauth/callback"),
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/drive.readonly",
			"https://www.googleapis.com/auth/calendar.readonly",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create Google provider: %v", err)
	}

	// 2. Create storage (in-memory with custom cleanup interval for production)
	store := memory.NewWithInterval(1 * time.Minute)
	defer store.Stop()

	// 3. Create OAuth server with production-grade security configuration
	// SECURITY: This demonstrates secure-by-default configuration.
	// All security features are enabled by default and can be selectively
	// disabled ONLY if needed for backward compatibility with legacy clients.
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer: getEnvOrDefault("MCP_RESOURCE", "https://mcp.example.com"),

			// Secure defaults (enabled automatically):
			// RequirePKCE: true              - Mandatory PKCE for all clients (OAuth 2.1)
			// AllowPKCEPlain: false          - Only S256 method allowed
			// AllowRefreshTokenRotation: true - Token rotation (OAuth 2.1)
			// TrustProxy: false              - Don't trust proxy headers by default

			// Optional: Override defaults for backward compatibility
			// ONLY enable these if you have legacy clients that don't support PKCE
			// RequirePKCE: getBoolEnv("OAUTH_REQUIRE_PKCE", true),
			// AllowPKCEPlain: getBoolEnv("OAUTH_ALLOW_PKCE_PLAIN", false),

			// Proxy configuration (only enable if behind trusted reverse proxy)
			TrustProxy:        getBoolEnv("TRUST_PROXY", false), // Secure by default
			TrustedProxyCount: getIntEnv("TRUSTED_PROXY_COUNT", 1),

			// Token lifetimes
			RefreshTokenTTL:      90 * 24 * 60 * 60, // 90 days in seconds
			ClockSkewGracePeriod: 5,                 // 5 seconds grace period

			// Rate limiting
			MaxClientsPerIP: 10,

			// Scope validation (optional)
			SupportedScopes: []string{
				"openid",
				"email",
				"profile",
				"https://www.googleapis.com/auth/gmail.readonly",
				"https://www.googleapis.com/auth/drive.readonly",
				"https://www.googleapis.com/auth/calendar.readonly",
			},

			// OpenTelemetry instrumentation for observability (metrics and tracing)
			// Enable this in production to monitor OAuth operations
			Instrumentation: oauth.InstrumentationConfig{
				Enabled:         getBoolEnv("ENABLE_INSTRUMENTATION", true),
				ServiceName:     getEnvOrDefault("SERVICE_NAME", "mcp-oauth-production"),
				ServiceVersion:  getEnvOrDefault("SERVICE_VERSION", "1.0.0"),
				MetricsExporter: getEnvOrDefault("METRICS_EXPORTER", "prometheus"),  // "prometheus", "stdout", "none"
				TracesExporter:  getEnvOrDefault("TRACES_EXPORTER", "otlp"),         // "otlp", "stdout", "none"
				OTLPEndpoint:    getEnvOrDefault("OTLP_ENDPOINT", "localhost:4318"), // For OTLP traces
			},

			// CORS configuration (optional, only for browser-based clients)
			// Uncomment and configure if you have browser-based MCP clients
			// CORS: oauth.CORSConfig{
			// 	AllowedOrigins: []string{
			// 		"https://app.example.com",
			// 		"https://dashboard.example.com",
			// 	},
			// 	AllowCredentials: true,  // Required for OAuth with credentials
			// 	MaxAge:           3600,  // 1 hour preflight cache
			// },
		},
		logger,
	)
	if err != nil {
		log.Fatalf("Failed to create OAuth server: %v", err)
	}

	// 4. Add security features
	// Enable token encryption
	encryptor, err := security.NewEncryptor(encryptionKey)
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}
	server.SetEncryptor(encryptor)

	// Enable audit logging
	auditor := security.NewAuditor(logger, true)
	server.SetAuditor(auditor)

	// Enable rate limiting (multi-layered approach)
	// 1. IP-based rate limiting (prevents DoS from external sources)
	rateLimiter := security.NewRateLimiter(10, 20, logger) // 10 req/s per IP, burst 20
	defer rateLimiter.Stop()                               // Important: cleanup background goroutines
	server.SetRateLimiter(rateLimiter)

	// 2. User-based rate limiting (prevents abuse from authenticated users)
	userRateLimiter := security.NewRateLimiter(100, 200, logger) // 100 req/s per user, burst 200
	defer userRateLimiter.Stop()                                 // Important: cleanup background goroutines
	server.SetUserRateLimiter(userRateLimiter)

	// 3. Security event rate limiting (prevents log flooding from attack attempts)
	// This limits logging of security events like code reuse, token reuse detection
	// to prevent attackers from causing DoS via excessive logging
	securityEventRateLimiter := security.NewRateLimiter(1, 5, logger) // 1 event/s per user+client, burst 5
	defer securityEventRateLimiter.Stop()                             // Important: cleanup background goroutines
	server.SetSecurityEventRateLimiter(securityEventRateLimiter)

	// 4. Client registration rate limiting (prevents registration/deletion cycle DoS)
	// Time-windowed rate limiting to prevent resource exhaustion through
	// repeated client registration/deletion cycles
	clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger) // 10 registrations per hour per IP
	defer clientRegRateLimiter.Stop()                                         // Important: cleanup background goroutines
	server.SetClientRegistrationRateLimiter(clientRegRateLimiter)

	// 5. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// Setup HTTP routes
	mux := setupRoutes(handler, logger)

	// HTTP server configuration
	httpServer := &http.Server{
		Addr:         getEnvOrDefault("LISTEN_ADDR", ":8443"),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Log startup information
	logger.Info("Starting MCP server with enhanced security",
		"addr", httpServer.Addr,
		"encryption", "enabled",
		"audit_logging", "enabled",
		"rate_limiting", "enabled (IP, user, security events, client registration)",
		"pkce_enforced", "true",
		"refresh_token_rotation", "enabled",
		"token_introspection", "enabled",
		"provider_revocation_timeout", "30s",
		"revoked_family_retention", "90 days",
		"provider", googleProvider.Name(),
	)

	// Start server (use TLS in production)
	if tlsCert := os.Getenv("TLS_CERT_FILE"); tlsCert != "" {
		tlsKey := getEnvOrFail("TLS_KEY_FILE")
		logger.Info("Starting HTTPS server", "cert", tlsCert)
		log.Fatal(httpServer.ListenAndServeTLS(tlsCert, tlsKey))
	} else {
		logger.Warn("Starting HTTP server - use HTTPS in production!")
		log.Fatal(httpServer.ListenAndServe())
	}
}

func setupRoutes(handler *oauth.Handler, logger *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()

	// OAuth metadata endpoints
	// Note: RegisterProtectedResourceMetadataRoutes registers both root and sub-path endpoints.
	// To use a logging wrapper, register endpoints manually instead.
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")

	mux.HandleFunc("/.well-known/oauth-authorization-server",
		logRequest(logger, handler.ServeAuthorizationServerMetadata))

	// OAuth endpoints
	mux.HandleFunc("/oauth/authorize",
		logRequest(logger, handler.ServeAuthorization))
	mux.HandleFunc("/oauth/token",
		logRequest(logger, handler.ServeToken))
	mux.HandleFunc("/oauth/callback",
		logRequest(logger, handler.ServeCallback))
	mux.HandleFunc("/oauth/register",
		logRequest(logger, handler.ServeClientRegistration))
	mux.HandleFunc("/oauth/revoke",
		logRequest(logger, handler.ServeTokenRevocation))
	mux.HandleFunc("/oauth/introspect",
		logRequest(logger, handler.ServeTokenIntrospection))

	// NOTE: If CORS is enabled, you need to handle OPTIONS preflight requests:
	// mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
	// 	if r.Method == http.MethodOptions {
	// 		handler.ServePreflightRequest(w, r)
	// 		return
	// 	}
	// 	handler.ServeToken(w, r)
	// })
	// Repeat for other endpoints that browser clients will call

	// Protected MCP endpoint
	mux.Handle("/mcp", handler.ValidateToken(mcpHandler(logger)))

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
				"id":    userInfo.ID,
			},
			"timestamp": time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		fmt.Fprintf(w, `{"message":"%s","user":{"email":"%s","name":"%s","id":"%s"}}`,
			response["message"], userInfo.Email, userInfo.Name, userInfo.ID)
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
		return security.KeyFromBase64(keyStr)
	}

	// Try to load from file
	if keyFile := os.Getenv("OAUTH_ENCRYPTION_KEY_FILE"); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		return security.KeyFromBase64(string(data))
	}

	// Generate new key (development only!)
	log.Println("WARNING: Generating new encryption key - tokens won't persist across restarts")
	log.Println("For production, set OAUTH_ENCRYPTION_KEY environment variable")

	key, err := security.GenerateKey()
	if err != nil {
		return nil, err
	}

	log.Printf("Generated encryption key: %s", security.KeyToBase64(key))
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

func getBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

func getIntEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	var intVal int
	if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
		return intVal
	}
	return defaultValue
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
