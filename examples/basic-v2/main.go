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
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:                    "http://localhost:8080",
			RequirePKCE:               true,
			AllowRefreshTokenRotation: true,
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
	server.SetRateLimiter(rateLimiter)

	// 6. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	// 7. Setup routes

	// OAuth Metadata Endpoints (RFC 8414, RFC 9728)
	http.HandleFunc("/.well-known/oauth-protected-resource", handler.ServeProtectedResourceMetadata)
	http.HandleFunc("/.well-known/oauth-authorization-server", handler.ServeAuthorizationServerMetadata)

	// OAuth Flow Endpoints
	http.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	http.HandleFunc("/oauth/callback", handler.ServeCallback)
	http.HandleFunc("/oauth/token", handler.ServeToken)
	http.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	http.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// Protected MCP endpoint
	http.Handle("/mcp", handler.ValidateToken(mcpHandler()))

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK - Provider: %s\n", googleProvider.Name())
	})

	// Start server
	addr := ":8080"
	log.Printf("🚀 Starting MCP OAuth Server on %s", addr)
	log.Printf("📦 Provider: %s", googleProvider.Name())
	log.Printf("🔐 Security: encryption=%v, audit=%v, ratelimit=%v",
		encKeyB64 != "", true, true)
	log.Printf("\nEndpoints:")
	log.Printf("  Metadata:      /.well-known/oauth-protected-resource")
	log.Printf("  Authorization: /oauth/authorize")
	log.Printf("  Token:         /oauth/token")
	log.Printf("  Callback:      /oauth/callback")
	log.Printf("  Register:      /oauth/register")
	log.Printf("  Revoke:        /oauth/revoke")
	log.Printf("  Protected MCP: /mcp")
	log.Fatal(http.ListenAndServe(addr, nil))
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
