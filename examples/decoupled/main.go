// Package main demonstrates how to use the mcp-oauth library components separately.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// 1. Create a provider (Google)
	googleProvider, err := google.NewProvider(&google.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
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

	// 2. Create storage (in-memory)
	store := memory.New()
	defer store.Stop()

	// 3. Use them together
	demonstrateProviderInterface(googleProvider)
	demonstrateStorage(store, googleProvider)
}

func demonstrateProviderInterface(provider providers.Provider) {
	fmt.Printf("Provider: %s\n", provider.Name())

	// Generate authorization URL (with PKCE)
	authURL := provider.AuthorizationURL("random-state", "example-challenge", "S256")

	fmt.Printf("Authorization URL: %s\n", authURL)
}

func demonstrateStorage(store *memory.Store, _ providers.Provider) {
	// The store works with any provider's token (oauth2.Token)
	token := &oauth2.Token{
		AccessToken:  "example-access-token",
		RefreshToken: "example-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}

	// Save token
	if err := store.SaveToken("user-123", token); err != nil {
		log.Printf("Error saving token: %v", err)
	}

	// Retrieve token
	retrieved, err := store.GetToken("user-123")
	if err != nil {
		log.Printf("Error retrieving token: %v", err)
	} else {
		fmt.Printf("Retrieved token for user-123: %s\n", retrieved.AccessToken)
	}
}
