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

	// 4. Create OAuth server with CIMD enabled
	//
	// Client ID Metadata Documents (CIMD) allow clients to use HTTPS URLs as
	// their client identifiers. The authorization server dynamically discovers
	// client metadata by fetching a JSON document from the URL.
	//
	// This is ideal for MCP scenarios where servers and clients have no
	// pre-existing relationship.
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)

			// ========== CIMD Configuration ==========

			// Enable Client ID Metadata Documents support (MCP 2025-11-25)
			// When enabled, clients can use HTTPS URLs as their client_id
			// and the server will fetch client metadata from that URL.
			EnableClientIDMetadataDocuments: true,

			// Timeout for fetching metadata from client URLs (default: 10s)
			// Protects against slow or unresponsive metadata endpoints.
			ClientMetadataFetchTimeout: 10 * time.Second,

			// How long to cache fetched client metadata (default: 5 minutes)
			// HTTP Cache-Control headers may override this value.
			// Cached entries reduce latency and external requests.
			ClientMetadataCacheTTL: 5 * time.Minute,

			// ========== Security Features ==========
			// The following security features are automatically enabled:
			// - SSRF protection (blocks private/internal IPs)
			// - DNS rebinding protection (validates IPs at connection time)
			// - PKCE required for all CIMD clients (public clients)
			// - Rate limiting per domain
			// - Negative caching for failed fetches
		},
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Add security features
	auditor := security.NewAuditor(logger, true)
	server.SetAuditor(auditor)

	rateLimiter := security.NewRateLimiter(10, 20, logger)
	defer rateLimiter.Stop()
	server.SetRateLimiter(rateLimiter)

	// 6. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// 7. Setup routes
	mux := http.NewServeMux()

	// Discovery endpoints
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	// OAuth flow endpoints
	mux.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	mux.HandleFunc("/oauth/callback", handler.ServeCallback)
	mux.HandleFunc("/oauth/token", handler.ServeToken)
	mux.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	mux.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// Protected MCP endpoint
	mux.Handle("/mcp", handler.ValidateToken(mcpHandler()))

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - Provider: %s, CIMD: enabled\n", googleProvider.Name())
	})

	// Start server
	addr := ":8080"
	log.Printf("Starting MCP OAuth Server with CIMD support on %s", addr)
	log.Printf("Provider: %s", googleProvider.Name())
	log.Printf("CIMD: enabled (Client ID Metadata Documents)")
	log.Printf("\nEndpoints:")
	log.Printf("  Discovery:")
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
	log.Printf("\nCIMD Features:")
	log.Printf("  - Clients can use HTTPS URLs as client_id")
	log.Printf("  - Server fetches and caches client metadata")
	log.Printf("  - SSRF protection with DNS rebinding prevention")
	log.Printf("  - PKCE required for all URL-based clients")
	log.Printf("\nExample usage with CIMD:")
	log.Printf("  client_id=https://example.com/oauth/client.json")
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
  "message": "Welcome to MCP server with CIMD support",
  "user": {
    "id": "%s",
    "email": "%s",
    "name": "%s"
  }
}`, userInfo.ID, userInfo.Email, userInfo.Name)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	})
}

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}
