// Package oauth provides an OAuth 2.1 authorization server for MCP applications.
//
// This package implements an OAuth 2.1 authorization server that fronts an
// upstream identity provider (Google, GitHub, Dex, generic OIDC, ...) and
// issues access and refresh tokens to MCP clients. It is provider-agnostic
// at the type level; the upstream IdP is injected via the
// [providers.Provider] interface.
//
// The package implements the Model Context Protocol authorization
// specification dated 2025-11-25 and the 2025-06-18 revision; both are
// supported on the same endpoints.
//
// Architecture:
//   - MCP Server: OAuth 2.1 Resource Server (advertises this library's issuer)
//   - This library: OAuth 2.1 Authorization Server (issues bearers, validates them)
//   - Upstream IdP: handles end-user authentication via the chosen [providers.Provider]
//   - MCP Client: OAuth 2.1 Client (runs the auth-code-with-PKCE flow)
//
// Key features:
//   - Authorization Code flow with mandatory PKCE (S256 only by default)
//   - Refresh token rotation with reuse detection
//   - Dynamic client registration (RFC 7591) with rate limiting
//   - Authorization Server Metadata (RFC 8414) and Protected Resource Metadata (RFC 9728)
//   - Token revocation (RFC 7009) and introspection (RFC 7662, opt-in)
//   - Optional self-issued JWT access tokens (RFC 9068) with published JWKS
//   - Optional token-at-rest encryption (AES-256-GCM) via [WithEncryptor]
//   - SSO token forwarding via Config.TrustedAudiences (validates upstream
//     ID tokens directly when an aggregator forwards them as Bearer credentials)
//
// Compliance:
//   - OAuth 2.1 Draft
//   - RFC 6749, RFC 6750, RFC 7009, RFC 7591, RFC 7636 (S256), RFC 7662 (opt-in),
//     RFC 8414, RFC 9068 (JWT mode), RFC 9728
//
// Example usage:
//
//	import (
//	    oauth "github.com/giantswarm/mcp-oauth"
//	    "github.com/giantswarm/mcp-oauth/providers/google"
//	    "github.com/giantswarm/mcp-oauth/storage/memory"
//	)
//
//	provider, err := google.NewProvider(&google.Config{
//	    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	    RedirectURL:  "https://your-domain.com/oauth/callback",
//	    Scopes:       []string{"openid", "email", "profile"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	store := memory.New()
//	defer store.Stop()
//
//	server, err := oauth.NewServer(
//	    provider,
//	    store, // TokenStore
//	    store, // ClientStore
//	    store, // FlowStore
//	    &oauth.ServerConfig{
//	        Issuer:          "https://your-domain.com",
//	        SupportedScopes: []string{"openid", "email", "profile"},
//	    },
//	    nil, // logger
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	handler := oauth.NewHandler(server, nil)
//	mux := http.NewServeMux()
//	handler.RegisterOAuthRoutes(mux, oauth.OAuthRoutesOptions{
//	    MCPPath:         "/mcp",
//	    IncludeMetadata: true,
//	})
//	mux.Handle("/mcp", handler.ValidateToken(mcpHandler))
//
// See docs/getting-started.md for a runnable end-to-end example and
// docs/security.md for the production checklist (encryption, rate
// limiters, audit logging — all wired via With* options on
// [NewServer]).
package oauth
