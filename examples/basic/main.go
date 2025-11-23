// Package main demonstrates basic OAuth 2.1 setup for MCP servers.
//
// This example shows minimal configuration to get started with OAuth authentication.
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	oauth "github.com/giantswarm/mcp-oauth"
)

func main() {
	// Basic configuration with required fields only
	config := &oauth.Config{
		// Resource identifier for your MCP server
		Resource: getEnvOrDefault("MCP_RESOURCE", "http://localhost:8080"),

		// Google API scopes your MCP server needs
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},

		// Google OAuth credentials from environment
		GoogleAuth: oauth.GoogleAuthConfig{
			ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
			ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
			// RedirectURL defaults to {Resource}/oauth/google/callback
		},

		// Optional: Use custom logger
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}

	// Create OAuth handler
	handler, err := oauth.NewHandler(config)
	if err != nil {
		log.Fatalf("Failed to create OAuth handler: %v", err)
	}

	// Setup HTTP routes
	setupRoutes(handler)

	// Start server
	addr := ":8080"
	log.Printf("Starting MCP server on %s", addr)
	log.Printf("OAuth endpoints:")
	log.Printf("  - Authorization: http://localhost:8080/oauth/authorize")
	log.Printf("  - Token: http://localhost:8080/oauth/token")
	log.Printf("  - Register: http://localhost:8080/oauth/register")
	log.Printf("  - Metadata: http://localhost:8080/.well-known/oauth-protected-resource")
	log.Fatal(http.ListenAndServe(addr, nil))
}

func setupRoutes(handler *oauth.Handler) {
	// OAuth metadata endpoints (RFC 9728, RFC 8414)
	http.HandleFunc("/.well-known/oauth-protected-resource",
		handler.ServeProtectedResourceMetadata)
	http.HandleFunc("/.well-known/oauth-authorization-server",
		handler.ServeAuthorizationServerMetadata)

	// OAuth endpoints
	http.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	http.HandleFunc("/oauth/token", handler.ServeToken)
	http.HandleFunc("/oauth/google/callback", handler.ServeGoogleCallback)
	http.HandleFunc("/oauth/register", handler.ServeClientRegistration)
	http.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)

	// Protected MCP endpoint
	http.Handle("/mcp", handler.ValidateGoogleToken(mcpHandler()))

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// mcpHandler is your MCP endpoint handler
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
    "email": "%s",
    "name": "%s",
    "id": "%s"
  }
}`, userInfo.Email, userInfo.Name, userInfo.Sub)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	})
}

// Helper functions

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

