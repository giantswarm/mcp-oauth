// Package providers defines the OAuth provider interface and types for user information.
//
// This package contains the Provider interface that must be implemented by all OAuth
// identity providers, as well as the UserInfo type that represents authenticated user data.
//
// # Interfaces
//
// Provider is the core interface that all OAuth identity providers must implement.
// It handles the complete OAuth flow including authorization, token exchange,
// validation, refresh, and revocation.
//
// JWKSProvider is an optional interface for providers that support JWKS-based
// JWT validation. This enables SSO token forwarding where ID tokens from upstream
// servers can be validated via JWKS signature verification instead of calling
// the userinfo endpoint. Providers that implement this interface can participate
// in federated authentication scenarios.
//
// # Implementations
//
// Implementations are provided in subpackages:
//   - providers/google: Google OAuth 2.0 provider (implements JWKSProvider)
//   - providers/github: GitHub OAuth provider
//   - providers/dex: Dex OIDC provider (implements JWKSProvider, supports multiple connectors)
//   - providers/mock: Mock provider for testing (implements JWKSProvider)
//   - providers/oidc: Generic OIDC discovery and validation utilities
//
// # Provider Capabilities
//
// All Provider implementations handle:
//   - OAuth authorization URL generation with PKCE support
//   - Authorization code exchange
//   - Token validation and user info retrieval
//   - Token refresh
//   - Token revocation
//   - Health checks
//
// JWKSProvider implementations additionally support:
//   - JWKS URI discovery for JWT signature verification
//   - Issuer URL for JWT issuer validation
//
// # Example Usage
//
// Basic provider usage:
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
//
// # SSO Token Forwarding
//
// When using TrustedAudiences with a JWKSProvider, the server can validate
// forwarded ID tokens from upstream MCP servers:
//
//	config := &server.Config{
//	    TrustedAudiences: []string{"upstream-client-id"},
//	    // ... other config
//	}
//
// The server will:
//  1. Check if the Bearer token is a JWT with a matching audience
//  2. Validate the JWT signature using the provider's JWKS
//  3. Extract user info from the validated ID token claims
package providers
