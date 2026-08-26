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
// # Scope Filtering
//
// The provider drops every scope outside an allowlist before it builds the
// authorization request, because an IdP that receives one scope it does not
// know rejects the whole request. The built-in allowlist is openid, profile,
// email, offline_access, groups and federated:id. Cross-client audience scopes
// pass as well.
//
// The drop is silent, so a scope an IdP needs but the allowlist does not hold
// never reaches it. Config.AllowedScopes replaces the list. "openid" always
// passes.
//
// A second set decides which entries of Scopes are merged into a request that
// names scopes of its own. It is openid, profile, email, groups,
// offline_access and the audience scopes, and Config.MandatoryScopes replaces
// it. Configure the two together: an IdP scope outside the built-in mandatory
// set, a Keycloak "roles" for example, otherwise reaches the IdP only for a
// client that names no scopes at all.
//
// # Other OIDC Issuers
//
// This provider is generic OIDC discovery plus a set of Dex conventions, so it
// also drives an issuer that is not Dex: Keycloak and Entra ID complete the
// authorization-code flow through it. The Dex conventions are the part to
// configure away:
//
//   - The groups scope. Dex defines it. A Keycloak realm needs a client scope
//     named groups with a group-membership mapper before it accepts the scope
//     at all, and Entra ID has no equivalent. Set Config.Scopes,
//     Config.AllowedScopes and Config.MandatoryScopes to the vocabulary of the
//     issuer.
//   - Cross-client audience scopes. The audience:server:client_id: shape is a
//     Dex extension. Keycloak and Entra ID reject an authorization request that
//     carries one. Set Config.DisableCrossClientAudienceScopes.
//   - The connector_id parameter. Dex reads it, other issuers ignore it. Leave
//     Config.ConnectorID empty.
//
// Everything else is standard OIDC: discovery, PKCE, the userinfo endpoint, and
// refresh. The user identity is the sub claim from userinfo, whatever the
// issuer.
//
// # Cross-Client Audience Scopes
//
// Dex supports a cross-client token issuance pattern where a token can be made valid
// for multiple clients by requesting special audience scopes. This is useful for SSO
// scenarios where a user authenticates once but needs access to multiple downstream
// services (e.g., Kubernetes OIDC via dex-k8s-authenticator).
//
// # IMPORTANT: Mandatory Scope Merging
//
// When audience scopes (prefixed with "audience:server:client_id:") are configured in
// the provider's default scopes, they are AUTOMATICALLY MERGED into ALL authorization
// requests. This behavior is intentional to ensure SSO token forwarding works correctly.
//
// Administrator implications:
//   - Tokens will ALWAYS include the configured audience claims
//   - Clients CANNOT opt out of these audiences by requesting custom scopes
//   - This affects token size and validation on downstream services
//   - The server logs configured audience scopes at startup for visibility
//
// Example configuration with mandatory audience:
//
//	provider, err := dex.NewProvider(&dex.Config{
//	    IssuerURL:    "https://dex.example.com",
//	    ClientID:     "mcp-oauth",
//	    ClientSecret: "secret",
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	    Scopes: []string{
//	        "openid", "profile", "email", "groups", "offline_access",
//	        "audience:server:client_id:dex-k8s-authenticator", // Always merged
//	    },
//	})
//
// With this configuration, even if a client requests only ["openid", "email"], the
// resulting authorization request will include "audience:server:client_id:dex-k8s-authenticator".
//
// # Audiences That Are Not Known At Startup
//
// Scopes is a snapshot: the provider reads it when NewProvider runs, and never
// again. An audience that the caller learns about later never reaches an
// authorization request, so the minted ID token carries only the provider's own
// client and every downstream service that expects the missing audience rejects
// it.
//
// Set Config.AudienceResolver for such an audience set. The provider calls it
// per authorization request and merges the audiences it reports into both
// DefaultScopes() and AuthorizationURL():
//
//	provider, err := dex.NewProvider(&dex.Config{
//	    IssuerURL:    "https://dex.example.com",
//	    ClientID:     "mcp-oauth",
//	    ClientSecret: "secret",
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	    // Reads the current backend registry on every login.
//	    AudienceResolver: registry.RequiredAudiences,
//	})
//
// The resolver runs on request goroutines, so it must be safe for concurrent
// use. It can also run more than once for a single authorization request,
// because both DefaultScopes() and AuthorizationURL() consult it, and it takes
// no context: read cached state and return, do not block on a network call.
//
// Duplicates cost nothing. Invalid audiences are skipped and logged once each,
// so one bad value costs only its own scope. The merged scope set stays within
// oidc.MaxScopeCount, the bound NewProvider enforces on Scopes, and an audience
// that does not fit is skipped and logged.
//
// A server that sets a supported-scopes allowlist must list the resulting
// audience scopes, because DefaultScopes() feeds that allowlist. The server
// validates that allowlist against provider defaults at startup, so an audience
// the resolver reports later is not covered by that check.
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
