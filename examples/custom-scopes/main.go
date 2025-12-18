// Package main demonstrates OAuth setup with multiple Google API scopes.
//
// This example shows how to work with various Google services:
// - Gmail (read emails)
// - Google Drive (read files)
// - Google Calendar (read events)
// - Google Contacts (read contacts)
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// Multiple Google API scopes
	// Each scope grants access to specific Google services
	scopes := []string{
		"openid",
		"email",
		"profile",
		// Gmail scopes
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/gmail.modify",
		"https://www.googleapis.com/auth/gmail.labels",
		"https://www.googleapis.com/auth/gmail.metadata",
		// Google Drive scopes
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/drive.file",
		"https://www.googleapis.com/auth/drive.metadata.readonly",
		// Google Calendar scopes
		"https://www.googleapis.com/auth/calendar.readonly",
		"https://www.googleapis.com/auth/calendar.events.readonly",
		// Google Contacts scopes
		"https://www.googleapis.com/auth/contacts.readonly",
	}

	// 1. Create provider
	googleProvider, err := google.NewProvider(&google.Config{
		ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
		ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/oauth/callback",
		Scopes:       scopes,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create storage
	store := memory.New()
	defer store.Stop()

	// 3. Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 4. Create OAuth server
	// Note: PKCE is now mandatory for all clients (OAuth 2.1)
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:                    getEnvOrDefault("MCP_RESOURCE", "http://localhost:8080"),
			AllowInsecureHTTP:         true, // Required for HTTP on localhost (development only)
			AllowRefreshTokenRotation: true,
			SupportedScopes:           scopes, // Validate requested scopes
		},
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Create HTTP handler
	handler := oauth.NewHandler(server, logger)

	setupRoutes(handler)

	addr := ":8080"
	log.Printf("Starting MCP server on %s", addr)
	log.Printf("Supported scopes:")
	for _, scope := range scopes {
		log.Printf("  - %s", scope)
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}

func setupRoutes(handler *oauth.Handler) {
	// OAuth metadata endpoints
	http.HandleFunc("/.well-known/oauth-protected-resource",
		handler.ServeProtectedResourceMetadata)

	// Authorization Server Metadata (multi-tenant aware)
	handler.RegisterAuthorizationServerMetadataRoutes(http.DefaultServeMux)

	// OAuth endpoints
	http.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	http.HandleFunc("/oauth/token", handler.ServeToken)
	http.HandleFunc("/oauth/callback", handler.ServeCallback)
	http.HandleFunc("/oauth/register", handler.ServeClientRegistration)
	http.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)

	// Protected endpoints demonstrating different scopes
	http.Handle("/api/gmail", handler.ValidateToken(gmailHandler()))
	http.Handle("/api/drive", handler.ValidateToken(driveHandler()))
	http.Handle("/api/calendar", handler.ValidateToken(calendarHandler()))
	http.Handle("/api/contacts", handler.ValidateToken(contactsHandler()))

	// General MCP endpoint
	http.Handle("/mcp", handler.ValidateToken(mcpHandler()))

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// Handler for Gmail API requests
func gmailHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		// In production, use the access token to call Gmail API
		// token := oauth.AccessTokenFromContext(r.Context())
		// Call Gmail API with token...

		response := map[string]interface{}{
			"service": "Gmail API",
			"user":    userInfo.Email,
			"message": "Access Gmail API here with the user's token",
			"example": "GET https://gmail.googleapis.com/gmail/v1/users/me/messages",
		}

		writeJSON(w, response)
	})
}

// Handler for Google Drive API requests
func driveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		response := map[string]interface{}{
			"service": "Google Drive API",
			"user":    userInfo.Email,
			"message": "Access Google Drive API here with the user's token",
			"example": "GET https://www.googleapis.com/drive/v3/files",
		}

		writeJSON(w, response)
	})
}

// Handler for Google Calendar API requests
func calendarHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		response := map[string]interface{}{
			"service": "Google Calendar API",
			"user":    userInfo.Email,
			"message": "Access Google Calendar API here with the user's token",
			"example": "GET https://www.googleapis.com/calendar/v3/calendars/primary/events",
		}

		writeJSON(w, response)
	})
}

// Handler for Google Contacts API requests
func contactsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		response := map[string]interface{}{
			"service": "Google Contacts API",
			"user":    userInfo.Email,
			"message": "Access Google Contacts API here with the user's token",
			"example": "GET https://people.googleapis.com/v1/people/me/connections",
		}

		writeJSON(w, response)
	})
}

// General MCP handler
func mcpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauth.UserInfoFromContext(r.Context())

		response := map[string]interface{}{
			"message": "MCP server with multiple Google API scopes",
			"user": map[string]string{
				"email": userInfo.Email,
				"name":  userInfo.Name,
				"id":    userInfo.ID,
			},
			"available_apis": []string{
				"/api/gmail",
				"/api/drive",
				"/api/calendar",
				"/api/contacts",
			},
		}

		writeJSON(w, response)
	})
}

// Helper functions

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
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
