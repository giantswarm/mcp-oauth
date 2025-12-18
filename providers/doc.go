// Package providers defines the OAuth provider interface and types for user information.
//
// This package contains the Provider interface that must be implemented by all OAuth
// identity providers, as well as the UserInfo type that represents authenticated user data.
//
// Implementations are provided in subpackages:
//   - providers/google: Google OAuth 2.0 provider
//   - providers/github: GitHub OAuth provider
//   - providers/dex: Dex OIDC provider (supports multiple connectors)
//   - providers/mock: Mock provider for testing
//   - providers/oidc: Generic OIDC discovery and validation utilities
//
// Provider implementations handle:
//   - OAuth authorization URL generation with PKCE support
//   - Authorization code exchange
//   - Token validation and user info retrieval
//   - Token refresh
//   - Token revocation
//   - Health checks
//
// Example usage:
//
//	provider, err := google.NewProvider(&google.Config{
//	    ClientID:     "your-client-id",
//	    ClientSecret: "your-client-secret",
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use provider with OAuth server
//	server, _ := oauth.NewServer(provider, tokenStore, clientStore, flowStore, config, logger)
package providers
