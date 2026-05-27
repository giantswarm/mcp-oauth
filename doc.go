// Package oauth provides an OAuth 2.1 / OIDC authorization server library
// intended to back an MCP server, aligned with the MCP 2025-11-25 OAuth
// profile. It implements the Protected-Resource role (token validation +
// metadata) and the Authorization-Server role (authorize / token / revoke /
// introspect / register / userinfo / discovery endpoints).
//
// # Architecture
//
// The package is split into:
//   - [github.com/giantswarm/mcp-oauth/server] — the protocol engine
//     ([server.Server], state machines for the authorization-code flow,
//     PKCE, refresh-token rotation, JWKS, introspection).
//   - [github.com/giantswarm/mcp-oauth/providers] — pluggable upstream IdP
//     adapters (built-in: [providers/dex], [providers/google],
//     [providers/github]).
//   - [github.com/giantswarm/mcp-oauth/storage] — persistence interfaces;
//     in-tree backends in [storage/memory] and [storage/valkey].
//   - [github.com/giantswarm/mcp-oauth/security] — primitives:
//     [security.Encryptor] (AES-256-GCM at rest with KeyRing seam),
//     [security.Auditor], [security.RateLimiter], scopes / WWW-Authenticate
//     helpers.
//   - [github.com/giantswarm/mcp-oauth/oauthconfig] — env-driven loaders
//     ([oauthconfig.FromEnv], [oauthconfig.NewEncryptorFromEnv]) for
//     standard `OAUTH_*` environment variables.
//   - [github.com/giantswarm/mcp-oauth/handler] — the HTTP adapter
//     ([handler.Handler]) that translates `*server.Server` into routes via
//     [handler.Handler.RegisterOAuthRoutes] /
//     [handler.Handler.RegisterProtectedResourceMetadataRoutes].
//   - This root package — protocol-level types ([Error], [TokenResponse],
//     [ProtectedResourceMetadata], …) and thin re-exports / convenience
//     constructors for [server.Server] ([NewServer], …).
//
// # Security defaults
//
// Library defaults aim for spec-compliant secure-by-default behaviour:
//   - PKCE required; only S256 accepted (RFC 7636 + OAuth 2.1).
//   - Refresh-token rotation on; reuse detection revokes the family.
//   - `state` parameter required and length-bounded (configurable via
//     [server.Config.MinStateLength] / [server.Config.MaxStateLength]).
//   - Per-IP and per-user rate limiters guard hot endpoints.
//   - Bearer-token comparisons are constant-time.
//   - Token-at-rest encryption available via [security.NewEncryptor] +
//     [memory.WithEncryptor] / [valkey.WithEncryptor]; the ciphertext
//     envelope is versioned with a 1-byte `kid` for future rotation.
//   - OIDC `nonce` is required end-to-end when scoped `openid` (CWE-294).
//   - SSRF protection on the client-metadata-document and discovery
//     fetchers.
//
// Insecure opt-outs (e.g. [server.Config.AllowNoStateParameter],
// [server.Config.AllowInsecureHTTP]) emit a startup WARN.
//
// # Compliance
//
// Implemented:
//   - RFC 6749 (OAuth 2.0 / OAuth 2.1 draft)
//   - RFC 6750 (Bearer token usage + WWW-Authenticate)
//   - RFC 7009 (Token revocation)
//   - RFC 7517 / 7518 / 7519 (JWS / JWA / JWT) via go-jose/v4
//   - RFC 7591 (Dynamic Client Registration; response includes
//     `client_id_issued_at`, `client_secret_expires_at`)
//   - RFC 7636 (PKCE — S256 only)
//   - RFC 7662 (Token introspection §2.2 shape + cross-client gate)
//   - RFC 8414 (Authorization Server Metadata + Cache-Control)
//   - RFC 8707 (Resource indicators + audience binding)
//   - RFC 9068 (JWT-profile access tokens)
//   - RFC 9207 (`iss` response parameter)
//   - RFC 9728 (Protected Resource Metadata)
//   - OIDC Core 1.0 §3 + §5.3 (`/userinfo`)
//   - OIDC Discovery 1.0 §3 (subject_types_supported,
//     id_token_signing_alg_values_supported, claims_supported)
//
// # Example
//
// A minimal in-memory server using the Google provider, encryption-at-rest
// from environment, and the standard `OAUTH_*` env loader. See the
// `examples/` directory for full end-to-end programs.
//
//	package main
//
//	import (
//		"log"
//		"log/slog"
//		"net/http"
//		"os"
//
//		"github.com/giantswarm/mcp-oauth/handler"
//		"github.com/giantswarm/mcp-oauth/oauthconfig"
//		"github.com/giantswarm/mcp-oauth/providers/google"
//		"github.com/giantswarm/mcp-oauth/server"
//		"github.com/giantswarm/mcp-oauth/storage/memory"
//	)
//
//	func main() {
//		cfg, err := oauthconfig.FromEnv()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		enc, err := oauthconfig.NewEncryptorFromEnv()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		provider, err := google.NewProvider(&google.Config{
//			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//			RedirectURL:  cfg.Issuer + "/oauth/callback",
//		})
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		store := memory.New(memory.WithEncryptor(enc))
//		srv, err := server.New(provider, store, store, store, cfg, slog.Default())
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		h := handler.New(srv, slog.Default())
//
//		mux := http.NewServeMux()
//		h.RegisterOAuthRoutes(mux, handler.OAuthRoutesOptions{IncludeMetadata: true})
//		mux.Handle("/mcp", h.ValidateToken(mcpHandler))
//		log.Fatal(http.ListenAndServe(":8080", mux))
//	}
//
// The library does not provide MCP itself — `mcpHandler` is whatever your
// MCP transport exposes. The OAuth layer protects it via
// [handler.Handler.ValidateToken], which extracts the bearer token, validates
// it against the configured provider (or self-issued JWT in JWT-AT mode), and
// stashes the resolved [providers.UserInfo] in the request context for
// [handler.UserInfoFromContext].
package oauth
