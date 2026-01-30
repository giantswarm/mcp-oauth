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
//   - Cross-Client Audience Scopes: Helper functions for SSO token forwarding to multiple clients
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
//
// # Cross-Client Audience Scopes
//
// Dex supports a cross-client token issuance pattern where a token can be made valid
// for multiple clients by requesting special audience scopes. This is useful for SSO
// scenarios where a user authenticates once but needs access to multiple downstream
// services (e.g., Kubernetes OIDC via dex-k8s-authenticator).
//
// Use the audience helper functions to format these scopes:
//
//	// Format a single audience scope (returns error for invalid input)
//	scope, err := dex.FormatAudienceScope("dex-k8s-authenticator")
//	if err != nil {
//	    return fmt.Errorf("invalid audience: %w", err)
//	}
//	// scope = "audience:server:client_id:dex-k8s-authenticator"
//
//	// Format multiple audience scopes
//	scopes, err := dex.FormatAudienceScopes([]string{"k8s-auth", "api-gateway"})
//	if err != nil {
//	    return fmt.Errorf("invalid audiences: %w", err)
//	}
//	// scopes = ["audience:server:client_id:k8s-auth", "audience:server:client_id:api-gateway"]
//
//	// Append audience scopes to existing OAuth scopes
//	allScopes, err := dex.AppendAudienceScopes("openid profile email", []string{"k8s-auth"})
//	if err != nil {
//	    return fmt.Errorf("invalid audiences: %w", err)
//	}
//	// allScopes = "openid profile email audience:server:client_id:k8s-auth"
//
//	// Check if a scope is an audience scope using the exported constant
//	if strings.HasPrefix(scope, dex.AudienceScopePrefix) {
//	    // handle audience scope
//	}
//
//	// Validate an audience string before use (optional, functions validate internally)
//	if err := dex.ValidateAudience("k8s-auth"); err != nil {
//	    return fmt.Errorf("invalid audience: %w", err)
//	}
//
// # Audience Scope Security
//
// All audience helper functions validate input to prevent scope injection attacks.
// OAuth scopes are space-delimited (RFC 6749 Section 3.3), so an unvalidated audience
// string containing spaces could inject additional scopes into the OAuth request.
//
// Security measures:
//   - Character whitelist: Only alphanumeric, hyphens, and underscores allowed
//   - Length limit: Maximum 256 characters per audience
//   - Count limit: Maximum 50 audiences per call
//   - Empty string handling: Filtered out (not treated as error)
//
// Reference: https://dexidp.io/docs/custom-scopes-claims-clients/#cross-client-trust-and-authorized-party
package dex
