// Package main demonstrates OAuth setup with the GitHub OAuth provider.
//
// This example shows how to authenticate users via GitHub with optional
// organization restrictions.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/github"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// Get configuration from environment variables
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		log.Fatal("GITHUB_CLIENT_ID environment variable is required")
	}

	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("GITHUB_CLIENT_SECRET environment variable is required")
	}

	// Optional: restrict to specific organizations
	var allowedOrgs []string
	if orgs := os.Getenv("GITHUB_ALLOWED_ORGANIZATIONS"); orgs != "" {
		allowedOrgs = strings.Split(orgs, ",")
		for i := range allowedOrgs {
			allowedOrgs[i] = strings.TrimSpace(allowedOrgs[i])
		}
	}

	// Create GitHub provider
	githubProvider, err := github.NewProvider(&github.Config{
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		RedirectURL:          "http://localhost:8080/oauth/callback",
		AllowedOrganizations: allowedOrgs,
		// Default scopes: user:email, read:user
		// read:org is automatically added when AllowedOrganizations is set
	})
	if err != nil {
		log.Fatalf("Failed to create GitHub provider: %v", err)
	}

	log.Printf("Created GitHub OAuth provider")
	if len(allowedOrgs) > 0 {
		log.Printf("Restricting login to organizations: %v", allowedOrgs)
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
		githubProvider,
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

	// Protected endpoint demonstrating GitHub user info
	resourceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user info from context (set by ValidateToken middleware)
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		// Return user information
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"message": "Access granted",
			"user": map[string]interface{}{
				"id":             userInfo.ID,
				"email":          userInfo.Email,
				"email_verified": userInfo.EmailVerified,
				"name":           userInfo.Name,
				"picture":        userInfo.Picture,
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	// Wrap with ValidateToken middleware
	mux.Handle("/api/resource", handler.ValidateToken(resourceHandler))

	// Home page with login link
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		orgInfo := ""
		if len(allowedOrgs) > 0 {
			orgInfo = fmt.Sprintf(`<p><strong>Allowed Organizations:</strong> %s</p>
            <p><em>Only members of these organizations can log in.</em></p>`, strings.Join(allowedOrgs, ", "))
		} else {
			orgInfo = `<p><strong>Organization restriction:</strong> None (any GitHub user can log in)</p>`
		}

		html := `<!DOCTYPE html>
<html>
<head>
    <title>GitHub OAuth Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .info { background: #f6f8fa; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #e1e4e8; }
        .button { background: #24292e; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; }
        .button:hover { background: #2f363d; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>GitHub OAuth Example</h1>
    <div class="info">
        <h2>About This Example</h2>
        <p>This example demonstrates the GitHub OAuth provider with the following features:</p>
        <ul>
            <li><strong>GitHub Authentication:</strong> Sign in with GitHub OAuth</li>
            <li><strong>Organization Restriction:</strong> Optionally restrict to specific organizations</li>
            <li><strong>User Info:</strong> Retrieve user profile and email</li>
            <li><strong>PKCE Support:</strong> Secure authorization with code challenge</li>
        </ul>
        ` + orgInfo + `
    </div>
    <a href="/oauth/authorize?client_id=demo-client&response_type=code&scope=user:email+read:user" class="button">
        Sign in with GitHub
    </a>
    <h2>Try the Protected API</h2>
    <p>After logging in, access: <a href="/api/resource">/api/resource</a></p>
    
    <h2>API Documentation</h2>
    <ul>
        <li><code>GET /.well-known/oauth-authorization-server</code> - Authorization server metadata</li>
        <li><code>GET /.well-known/oauth-protected-resource</code> - Protected resource metadata</li>
        <li><code>POST /oauth/authorize</code> - Start authorization flow</li>
        <li><code>POST /oauth/token</code> - Exchange code for token</li>
        <li><code>POST /oauth/register</code> - Dynamic client registration</li>
    </ul>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	// Health check endpoint
	// SECURITY: Do not expose internal error details to clients
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := githubProvider.HealthCheck(ctx); err != nil {
			// Log error for internal monitoring, but don't expose details to clients
			log.Printf("Health check failed: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "unhealthy")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "healthy")
	})

	// Start server
	addr := ":8080"
	log.Printf("Starting server on http://localhost%s", addr)
	log.Printf("Visit http://localhost%s to sign in with GitHub", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
