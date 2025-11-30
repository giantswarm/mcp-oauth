package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// Get configuration from environment variables
	issuerURL := os.Getenv("DEX_ISSUER_URL")
	if issuerURL == "" {
		log.Fatal("DEX_ISSUER_URL environment variable is required")
	}

	clientID := os.Getenv("DEX_CLIENT_ID")
	if clientID == "" {
		log.Fatal("DEX_CLIENT_ID environment variable is required")
	}

	clientSecret := os.Getenv("DEX_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("DEX_CLIENT_SECRET environment variable is required")
	}

	// Optional: connector_id to skip Dex connector selection screen
	connectorID := os.Getenv("DEX_CONNECTOR_ID") // e.g., "github", "ldap", "oidc"

	// Create Dex provider with optional connector_id
	dexProvider, err := dex.NewProvider(&dex.Config{
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/oauth/callback",
		ConnectorID:  connectorID, // Optional: skip connector selection if set
		// Scopes are optional - defaults to: openid, profile, email, groups, offline_access
	})
	if err != nil {
		log.Fatalf("Failed to create Dex provider: %v", err)
	}

	log.Printf("Created Dex provider for issuer: %s", issuerURL)
	if connectorID != "" {
		log.Printf("Using connector: %s (will skip Dex connector selection)", connectorID)
	}

	// Create in-memory storage (use persistent storage in production)
	store := memory.New()
	defer store.Stop()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create OAuth server
	server, err := oauth.NewServer(
		dexProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)
		},
		logger,
	)
	if err != nil {
		log.Fatalf("Failed to create OAuth server: %v", err)
	}

	// Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// Setup routes
	mux := http.NewServeMux()

	// OAuth Flow Endpoints
	mux.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	mux.HandleFunc("/oauth/callback", handler.ServeCallback)
	mux.HandleFunc("/oauth/token", handler.ServeToken)
	mux.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	mux.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// Discovery endpoints (MCP 2025-11-25)
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/api")
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	// Protected endpoint demonstrating group access
	resourceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user info from context (set by ValidateToken middleware)
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		// Check if user is in required group (example: "developers")
		hasAccess := false
		for _, group := range userInfo.Groups {
			if group == "developers" || group == "admins" {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			http.Error(w, "Forbidden: requires 'developers' or 'admins' group", http.StatusForbidden)
			return
		}

		// Return user information
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"message": "Access granted",
			"user": map[string]interface{}{
				"id":     userInfo.ID,
				"email":  userInfo.Email,
				"name":   userInfo.Name,
				"groups": userInfo.Groups,
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	// Wrap with ValidateToken middleware
	mux.Handle("/api/resource", handler.ValidateToken(resourceHandler))

	// Home page with login link
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Dex OAuth Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .info { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .button { background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; }
    </style>
</head>
<body>
    <h1>Dex OAuth Example</h1>
    <div class="info">
        <h2>About This Example</h2>
        <p>This example demonstrates the Dex OAuth provider with the following features:</p>
        <ul>
            <li><strong>OIDC Discovery:</strong> Automatically discovers Dex endpoints</li>
            <li><strong>Connector Selection:</strong> Can bypass Dex connector selection with connector_id</li>
            <li><strong>Groups Claim:</strong> Retrieves user group memberships</li>
            <li><strong>Refresh Tokens:</strong> Handles Dex's refresh token rotation</li>
        </ul>
        <p><strong>Issuer:</strong> ` + issuerURL + `</p>
        ` + (func() string {
			if connectorID != "" {
				return `<p><strong>Connector:</strong> ` + connectorID + ` (connector selection will be skipped)</p>`
			}
			return `<p><strong>Connector:</strong> None specified (Dex will show connector selection)</p>`
		})() + `
    </div>
    <a href="/oauth/authorize?client_id=demo-client&response_type=code&scope=openid+profile+email+groups" class="button">
        Sign in with Dex
    </a>
    <h2>Try the Protected API</h2>
    <p>After logging in, access: <a href="/api/resource">/api/resource</a></p>
    <p><em>Note: You need to be in the 'developers' or 'admins' group to access this resource.</em></p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := dexProvider.HealthCheck(ctx); err != nil {
			log.Printf("Health check failed: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "unhealthy: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "healthy")
	})

	// Start server
	addr := ":8080"
	log.Printf("Starting server on http://localhost%s", addr)
	log.Printf("Visit http://localhost%s to sign in with Dex", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
