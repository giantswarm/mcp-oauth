// Package server implements the core OAuth 2.1 server logic.
//
// This package provides the OAuth authorization server implementation with
// support for the authorization code flow, PKCE, token refresh, and client
// registration. It coordinates between OAuth providers, storage backends,
// and security features while remaining provider-agnostic.
//
// The Server type delegates to specialized modules:
//   - Provider integration (providers package)
//   - Token and client storage (storage package)
//   - Security features (security package)
//
// Key Features:
//   - OAuth 2.1 compliance with mandatory PKCE
//   - Refresh token rotation with reuse detection
//   - Dynamic client registration (RFC 7591)
//   - Comprehensive security auditing
//   - Rate limiting (IP and user-based)
//   - Token encryption at rest
//
// Example usage:
//
//	provider := google.NewProvider(clientID, clientSecret, redirectURL)
//	store := memory.NewStore()
//
//	config := &server.Config{
//	    Issuer: "https://auth.example.com",
//	    RequirePKCE: true,
//	}
//
//	srv, err := server.New(provider, store, store, store, config, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
package server
