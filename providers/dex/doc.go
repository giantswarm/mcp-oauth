// Package dex provides a Dex OAuth provider implementation with OIDC support.
//
// Dex (https://dexidp.io/) is an identity service that uses OpenID Connect to drive
// authentication for other apps. It acts as a portal to other identity providers through
// "connectors" like LDAP, SAML, GitHub, GitLab, Google, etc.
//
// # Features
//
// This package implements Dex-specific optimizations beyond generic OIDC:
//
//   - connector_id Support: Bypass Dex's connector selection UI by specifying a connector
//   - Groups Claim: Automatically includes the 'groups' scope to retrieve user group memberships
//   - Refresh Token Rotation: Properly handles Dex's strict refresh token rotation policy
//   - OIDC Discovery: Dynamically fetches endpoints via OIDC discovery with SSRF protection
//
// # Security Features
//
//   - SSRF Protection: Validates issuer URLs to block private IPs and localhost
//   - HTTPS Enforcement: All endpoints must use HTTPS
//   - Input Validation: Validates connector_id and groups claim for security
//   - Discovery Caching: Caches OIDC discovery documents with TTL
//
// # Example Usage
//
//	// Create Dex provider with connector_id to skip selection UI
//	dexProvider, err := dex.NewProvider(&dex.Config{
//	    IssuerURL:    "https://dex.example.com",
//	    ClientID:     "my-client-id",
//	    ClientSecret: "my-client-secret",
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	    ConnectorID:  "github", // Optional: skip connector selection
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use with mcp-oauth server
//	server, err := mcpoauth.NewServer(&mcpoauth.ServerConfig{
//	    Provider: dexProvider,
//	    // ... other config ...
//	})
//
// # Dex-Specific Configuration
//
// Connector ID:
//
//	The connector_id parameter allows bypassing Dex's connector selection screen.
//	This is useful when you have a single connector or want to direct users to
//	a specific authentication method.
//
//	Reference: https://dexidp.io/docs/configuration/custom-scopes-claims-clients/#authentication-through-connector_id
//
// Groups Claim:
//
//	Dex requires the 'groups' scope to return group memberships in the userinfo response.
//	This provider includes 'groups' in the default scopes automatically.
//
//	Groups are validated for security (max 100 groups, max 256 chars per group name).
//
// Refresh Token Rotation:
//
//	Dex implements strict refresh token rotation - each token refresh returns a NEW
//	refresh token and invalidates the old one. This provider handles rotation correctly
//	by returning the complete oauth2.Token with the new refresh token.
//
//	Reference: https://dexidp.io/docs/configuration/custom-scopes-claims-clients/#refresh-token-rotation
//
// # Default Scopes
//
// The provider uses the following default scopes if none are specified:
//
//   - openid: Required for OIDC authentication
//   - profile: User profile information (name, picture, etc.)
//   - email: User email address
//   - groups: User group memberships (Dex-specific)
//   - offline_access: Refresh token support
//
// You can override these by providing custom Scopes in the Config.
package dex
