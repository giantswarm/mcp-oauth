// Package main demonstrates MCP 2025-11-25 OAuth specification features.
//
// This example showcases the advanced OAuth features from the MCP 2025-11-25
// specification including Protected Resource Metadata, scope selection,
// and enhanced WWW-Authenticate headers.
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

	// 4. Create OAuth server with MCP 2025-11-25 features
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)

			// === MCP 2025-11-25 Features ===

			// Feature 1: Scope Configuration
			// List all scopes your resource server supports
			// This appears in Protected Resource Metadata (/.well-known/oauth-protected-resource)
			SupportedScopes: []string{
				"mcp:access",   // General MCP access
				"files:read",   // Read files
				"files:write",  // Write/modify files
				"admin:access", // Administrative access
				"user:profile", // User profile information
			},

			// Feature 2: WWW-Authenticate Scope Guidance
			// Default scopes to advertise in 401 Unauthorized responses
			// Per MCP 2025-11-25: Helps clients discover required scopes
			DefaultChallengeScopes: []string{
				"mcp:access", // Basic scope for general access
			},

			// Feature 3: Enhanced WWW-Authenticate Headers (enabled by default)
			// When false: Full MCP 2025-11-25 compliance with discovery support
			// - Includes resource_metadata URL for authorization server discovery
			// - Includes scope parameter (from DefaultChallengeScopes or endpoint-specific)
			// - Includes error and error_description parameters
			DisableWWWAuthenticateMetadata: false, // default: false (metadata ENABLED)

			// Feature 4: Endpoint-Specific Scope Requirements
			// Define which scopes are required for specific API endpoints
			// When a token lacks required scopes, server returns 403 with insufficient_scope error
			EndpointScopeRequirements: map[string][]string{
				"/api/files/*": {"files:read", "files:write"},
				"/api/admin/*": {"admin:access"},
				"/api/profile": {"user:profile"},
			},

			// Feature 5: Method-Specific Scope Requirements
			// Different HTTP methods can require different scopes
			EndpointMethodScopeRequirements: map[string]map[string][]string{
				"/api/files/*": {
					"GET":    {"files:read"},                   // Read-only
					"POST":   {"files:write"},                  // Create new
					"PUT":    {"files:write"},                  // Modify existing
					"DELETE": {"files:delete", "admin:access"}, // Delete requires admin
				},
			},

			// Feature 6: Resource Parameter (RFC 8707) - Token Audience Binding
			// Set ResourceIdentifier to bind tokens to this resource server
			// ResourceIdentifier: "http://localhost:8080",

			// Feature 7: Client ID Metadata Documents
			// Enable distributed client verification via HTTPS metadata URLs
			// EnableClientIDMetadataDocuments: true,
			// ClientMetadataCacheTTL: 5 * time.Minute,   // Cache metadata
			// ClientMetadataFetchTimeout: 10 * time.Second, // Fetch timeout

			// === OAuth 2.1 Security (enabled by default) ===
			// RequirePKCE: true,                   // Mandatory PKCE
			// AllowPKCEPlain: false,                // Only S256 method
			// AllowRefreshTokenRotation: true,      // Token rotation
		},
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Add security features (optional but recommended)
	auditor := security.NewAuditor(logger, true)
	server.SetAuditor(auditor)

	rateLimiter := security.NewRateLimiter(10, 20, logger)
	defer rateLimiter.Stop()
	server.SetRateLimiter(rateLimiter)

	// 6. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// 7. Setup routes
	mux := http.NewServeMux()

	// === Discovery Endpoints (MCP 2025-11-25) ===

	// Protected Resource Metadata (RFC 9728)
	// Registers the Protected Resource Metadata discovery endpoint:
	// - /.well-known/oauth-protected-resource (standard)
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")

	// Authorization Server Metadata (RFC 8414)
	// Automatically registers all discovery endpoints including multi-tenant path insertion
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	// === OAuth Flow Endpoints ===
	mux.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	mux.HandleFunc("/oauth/callback", handler.ServeCallback)
	mux.HandleFunc("/oauth/token", handler.ServeToken)
	mux.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	mux.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// === Protected MCP Endpoints ===

	// Basic MCP endpoint (requires DefaultChallengeScopes)
	mux.Handle("/mcp", handler.ValidateToken(mcpHandler("Basic MCP Endpoint")))

	// Files endpoint (requires files:read and files:write per EndpointScopeRequirements)
	mux.Handle("/api/files/", handler.ValidateToken(mcpHandler("Files API")))

	// Admin endpoint (requires admin:access per EndpointScopeRequirements)
	mux.Handle("/api/admin/", handler.ValidateToken(mcpHandler("Admin API")))

	// Profile endpoint (requires user:profile per EndpointScopeRequirements)
	mux.Handle("/api/profile", handler.ValidateToken(mcpHandler("User Profile API")))

	// Health check (unprotected)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - Provider: %s\n", googleProvider.Name())
	})

	// Start server
	addr := ":8080"
	log.Printf("🚀 Starting MCP 2025-11-25 OAuth Server on %s", addr)
	log.Printf("📦 Provider: %s", googleProvider.Name())
	log.Println("\n=== MCP 2025-11-25 Features Enabled ===")
	log.Println("✅ Protected Resource Metadata Discovery")
	log.Println("✅ Enhanced WWW-Authenticate Headers")
	log.Println("✅ Scope Selection Strategy")
	log.Println("✅ Endpoint-Specific Scope Requirements")
	log.Println("✅ Insufficient Scope Error Handling")
	log.Println("\n=== Endpoints ===")
	log.Println("Discovery:")
	log.Println("  /.well-known/oauth-protected-resource")
	log.Println("  /.well-known/oauth-authorization-server")
	log.Println("\nOAuth Flow:")
	log.Println("  /oauth/authorize")
	log.Println("  /oauth/callback")
	log.Println("  /oauth/token")
	log.Println("  /oauth/revoke")
	log.Println("  /oauth/register")
	log.Println("\nProtected Resources:")
	log.Println("  /mcp               → requires: mcp:access")
	log.Println("  /api/files/*       → requires: files:read, files:write")
	log.Println("  /api/admin/*       → requires: admin:access")
	log.Println("  /api/profile       → requires: user:profile")
	log.Println("\n=== Testing ===")
	log.Println("Try accessing protected endpoints without auth:")
	log.Println("  curl -i http://localhost:8080/mcp")
	log.Println("  curl -i http://localhost:8080/api/files/doc.txt")
	log.Println("\nCheck WWW-Authenticate headers in 401 responses for:")
	log.Println("  - resource_metadata parameter (discovery URL)")
	log.Println("  - scope parameter (required scopes)")
	log.Println("  - error and error_description")
	log.Println("\nFetch discovery metadata:")
	log.Println("  curl http://localhost:8080/.well-known/oauth-protected-resource")
	log.Println("  curl http://localhost:8080/.well-known/oauth-authorization-server")
	log.Println()

	log.Fatal(http.ListenAndServe(addr, mux))
}

func mcpHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user info from context
		userInfo, ok := oauth.UserInfoFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get token scopes from context (available after scope validation)
		// This is useful if you need to check specific scopes within your handler
		// Note: Endpoint-level scope validation already happened in ValidateToken middleware

		response := fmt.Sprintf(`{
  "endpoint": "%s",
  "message": "Successfully accessed protected resource",
  "user": {
    "id": "%s",
    "email": "%s",
    "name": "%s"
  },
  "mcp_2025_11_25": {
    "features": [
      "Protected Resource Metadata Discovery",
      "WWW-Authenticate Scope Guidance",
      "Endpoint-Specific Scope Requirements",
      "Insufficient Scope Error Handling"
    ]
  }
}`, name, userInfo.ID, userInfo.Email, userInfo.Name)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
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
