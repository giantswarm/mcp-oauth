package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// 1. Create a provider (Google in this case)
	googleProvider, err := google.NewProvider(&google.Config{
		ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
		ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/oauth/callback",
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create storage (in-memory for simplicity)
	store := memory.New()
	defer store.Stop()

	// 3. Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 4. Create OAuth server
	// Security: Secure by default! PKCE (S256 only) is enabled by default.
	// All security settings follow OAuth 2.1 best practices.
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)
			// Secure defaults (applied automatically if not set):
			// - RequirePKCE: true (mandatory PKCE)
			// - AllowPKCEPlain: false (only S256 method)
			// - AllowRefreshTokenRotation: true (token rotation)
			// - TrustProxy: false (don't trust proxy headers)

			// Optional: Enable OpenTelemetry instrumentation for observability
			// Uncomment to enable metrics and distributed tracing:
			// Instrumentation: oauth.InstrumentationConfig{
			//     Enabled:         true,
			//     ServiceName:     "mcp-oauth-basic",
			//     ServiceVersion:  "1.0.0",
			//     MetricsExporter: "stdout",  // Options: "prometheus", "stdout", "none"
			//     TracesExporter:  "stdout",  // Options: "otlp", "stdout", "none"
			//     OTLPEndpoint:    "localhost:4318", // Required if TracesExporter="otlp"
			// },
		},
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Optional: Add security features
	encKeyB64 := os.Getenv("OAUTH_ENCRYPTION_KEY")
	if encKeyB64 != "" {
		encKey, err := security.KeyFromBase64(encKeyB64)
		if err != nil {
			log.Fatalf("Invalid encryption key: %v", err)
		}
		encryptor, _ := security.NewEncryptor(encKey)
		server.SetEncryptor(encryptor)
		logger.Info("Token encryption enabled")
	}

	auditor := security.NewAuditor(logger, true)
	server.SetAuditor(auditor)

	rateLimiter := security.NewRateLimiter(10, 20, logger)
	defer rateLimiter.Stop() // Important: cleanup background goroutines
	server.SetRateLimiter(rateLimiter)

	// 6. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// 7. Setup routes
	mux := http.NewServeMux()

	// === OAuth Discovery Endpoints (MCP 2025-11-25) ===

	// Protected Resource Metadata (RFC 9728)
	// RegisterProtectedResourceMetadataRoutes creates TWO discovery endpoints:
	//   1. /.well-known/oauth-protected-resource (standard RFC 9728)
	//   2. /mcp/.well-known/oauth-protected-resource (MCP 2025-11-25 sub-path)
	//
	// Clients use these endpoints to discover:
	//   - Which authorization server protects this resource
	//   - What scopes are supported
	//   - How to send bearer tokens
	//
	// Example discovery flow:
	//   1. Client → GET /mcp (unauthorized)
	//   2. Server → 401 + WWW-Authenticate: resource_metadata=".../.well-known/oauth-protected-resource"
	//   3. Client → GET /.well-known/oauth-protected-resource
	//   4. Client → Discovers authorization server and scopes
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")

	// Authorization Server Metadata (RFC 8414)
	// Describes OAuth server capabilities, endpoints, and supported features
	// Clients use this to discover:
	//   - OAuth endpoints (authorization, token, etc.)
	//   - Supported grant types and response types
	//   - PKCE methods supported
	//   - Available scopes
	mux.HandleFunc("/.well-known/oauth-authorization-server", handler.ServeAuthorizationServerMetadata)

	// OAuth Flow Endpoints
	mux.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	mux.HandleFunc("/oauth/callback", handler.ServeCallback)
	mux.HandleFunc("/oauth/token", handler.ServeToken)
	mux.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	mux.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// Protected MCP endpoint
	// ValidateToken middleware:
	//   - Validates Bearer token from Authorization header
	//   - Returns 401 with WWW-Authenticate header if invalid/missing (MCP 2025-11-25)
	//   - Adds UserInfo to request context if valid
	//   - Validates token scopes if EndpointScopeRequirements configured
	mux.Handle("/mcp", handler.ValidateToken(mcpHandler()))

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - Provider: %s\n", googleProvider.Name())
	})

	// Start server
	addr := ":8080"
	log.Printf("🚀 Starting MCP OAuth Server on %s", addr)
	log.Printf("📦 Provider: %s", googleProvider.Name())
	log.Printf("🔐 Security: encryption=%v, audit=%v, ratelimit=%v",
		encKeyB64 != "", true, true)
	log.Printf("\nEndpoints:")
	log.Printf("  Discovery (MCP 2025-11-25):")
	log.Printf("    /.well-known/oauth-protected-resource")
	log.Printf("    /mcp/.well-known/oauth-protected-resource (sub-path)")
	log.Printf("    /.well-known/oauth-authorization-server")
	log.Printf("  OAuth Flow:")
	log.Printf("    /oauth/authorize")
	log.Printf("    /oauth/token")
	log.Printf("    /oauth/callback")
	log.Printf("    /oauth/register")
	log.Printf("    /oauth/revoke")
	log.Printf("  Protected:")
	log.Printf("    /mcp")
	log.Printf("\nMCP 2025-11-25 Features:")
	log.Printf("  - Protected Resource Metadata discovery")
	log.Printf("  - Enhanced WWW-Authenticate headers with scope guidance")
	log.Printf("  - OAuth 2.1 security (PKCE, token rotation)")
	log.Fatal(http.ListenAndServe(addr, mux))
}

func mcpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user info from context
		userInfo, ok := oauth.UserInfoFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Your MCP logic here
		response := fmt.Sprintf(`{
  "message": "Welcome to MCP server",
  "user": {
    "id": "%s",
    "email": "%s",
    "name": "%s"
  }
}`, userInfo.ID, userInfo.Email, userInfo.Name)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	})
}

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}
