// Package main demonstrates basic OAuth 2.1 setup for MCP servers.
//
// This example shows the minimal setup required to get an OAuth-protected
// MCP server running with Google as the identity provider.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	oauthhandler "github.com/giantswarm/mcp-oauth/handler"
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

	// 4. Construct optional dependencies. Build everything first so we can
	// pass them as functional options to NewServer in a single call.
	auditor := security.NewAuditor(logger, true)
	rateLimiter := security.NewRateLimiter(10, 20, logger)
	defer rateLimiter.Stop() // Important: cleanup background goroutines

	opts := []oauth.ServerOption{
		oauth.WithAuditor(auditor),
		oauth.WithRateLimiter(rateLimiter),
	}

	encKeyB64 := os.Getenv("OAUTH_ENCRYPTION_KEY")
	if encKeyB64 != "" {
		encKey, err := security.KeyFromBase64(encKeyB64)
		if err != nil {
			log.Fatalf("Invalid encryption key: %v", err)
		}
		encryptor, _ := security.NewEncryptor(encKey)
		opts = append(opts, oauth.WithEncryptor(encryptor))
		logger.Info("Token encryption enabled")
	}

	// 5. Create OAuth server with secure defaults plus optional dependencies.
	// PKCE S256, refresh-token rotation, and the rest of the OAuth 2.1
	// hardening apply automatically.
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)

			// To enable OpenTelemetry instrumentation:
			//
			//   inst, _ := instrumentation.New(instrumentation.Config{
			//       Enabled:         true,
			//       ServiceName:     "mcp-oauth-basic",
			//       ServiceVersion:  "1.0.0",
			//       MetricsExporter: "stdout",
			//       TracesExporter:  "stdout",
			//   })
			//   opts = append(opts, oauth.WithInstrumentation(inst))
			//
			// See examples/prometheus and examples/production for a full
			// instrumentation setup.
		},
		logger,
		opts...,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 6. Create HTTP handler
	handler := oauthhandler.New(server, logger)

	// 7. Setup routes
	mux := http.NewServeMux()

	// === OAuth Discovery Endpoints (MCP 2025-11-25) ===

	// Protected Resource Metadata (RFC 9728)
	// Registers the discovery endpoint at /.well-known/oauth-protected-resource
	//
	// Clients use this endpoint to discover:
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
	// This automatically registers all discovery endpoints, including multi-tenant
	// path insertion variants for path-based issuers (MCP 2025-11-25)
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

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
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK - Provider: %s\n", googleProvider.Name())
	})

	// Start server
	addr := ":8080"
	log.Printf("🚀 Starting MCP OAuth Server on %s", addr)
	log.Printf("📦 Provider: %s", googleProvider.Name())
	log.Printf("🔐 Security: encryption=%v, audit=%v, ratelimit=%v", //nolint:gosec // G706: values are booleans derived from env var presence, not injected strings
		encKeyB64 != "", true, true)
	log.Printf("\nEndpoints:")
	log.Printf("  Discovery (MCP 2025-11-25):")
	log.Printf("    /.well-known/oauth-protected-resource")
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
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// mcpResponse represents the JSON response from the MCP endpoint.
// Using a struct with json.Marshal prevents JSON injection vulnerabilities
// that can occur when using fmt.Sprintf with user-controlled data.
type mcpResponse struct {
	Message string  `json:"message"`
	User    mcpUser `json:"user"`
}

type mcpUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func mcpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user info from context
		userInfo, ok := oauthhandler.UserInfoFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Build response using proper JSON marshaling to prevent injection
		response := mcpResponse{
			Message: "Welcome to MCP server",
			User: mcpUser{
				ID:    userInfo.ID,
				Email: userInfo.Email,
				Name:  userInfo.Name,
			},
		}

		// Set security headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Use json.NewEncoder for safe JSON serialization
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})
}

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}
