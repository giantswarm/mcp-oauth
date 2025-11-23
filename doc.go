// Package oauth provides OAuth 2.1 authentication for the MCP server.
//
// This package implements OAuth 2.1 authentication according to the Model Context Protocol
// (MCP) specification dated 2025-06-18. The MCP server acts as an OAuth 2.1 Resource Server,
// using Google as the Authorization Server for secure authentication.
//
// Architecture:
//   - MCP Server: OAuth 2.1 Resource Server (validates Google tokens)
//   - Google: OAuth 2.1 Authorization Server (issues tokens, handles user auth)
//   - MCP Client: OAuth 2.1 Client (handles OAuth flow, includes tokens in requests)
//
// Key Features:
//   - Protected Resource Metadata (RFC 9728) - advertises Google as authorization server
//   - Bearer token validation via Google's userinfo endpoint
//   - Automatic token refresh with rotation (OAuth 2.1 security best practice)
//   - Rate limiting per IP address and per user with token bucket algorithm
//   - Secure token storage with optional AES-256-GCM encryption at rest
//   - Token expiration handling with automatic cleanup
//   - Token revocation endpoint (RFC 7009)
//   - Comprehensive audit logging for security events
//   - Client type enforcement (public vs confidential)
//   - PKCE S256 enforcement (plain method disabled for security)
//   - Integration with Google APIs (Gmail, Drive, Calendar, etc.)
//
// Security Features (Production-Ready):
//
// 1. Token Encryption at Rest (AES-256-GCM):
//   - Tokens can be encrypted in memory using AES-256-GCM
//   - Authenticated encryption prevents tampering
//   - Configure via Security.EncryptionKey (32 bytes)
//   - Use GenerateEncryptionKey() or load from secure storage (KMS, Vault)
//
// 2. Refresh Token Rotation (OAuth 2.1):
//   - New refresh token issued on each use
//   - Old refresh token invalidated immediately
//   - Detects stolen tokens via reuse detection
//   - Enabled by default (disable via Security.DisableRefreshTokenRotation)
//
// 3. Comprehensive Audit Logging:
//   - All authentication events logged with structured logging
//   - Security events: failed auth, rate limits, invalid tokens, token reuse
//   - All sensitive data (tokens, emails) hashed before logging (SHA-256)
//   - Enabled by default (disable via Security.EnableAuditLogging=false)
//
// 4. Client Type Validation:
//   - Public clients (mobile, SPA) must use "none" auth method
//   - Confidential clients must use client_secret_basic or client_secret_post
//   - Prevents security violations (confidential client without secret)
//
// 5. PKCE Security:
//   - Only S256 method supported (plain method disabled per OAuth 2.1)
//   - 43-128 character code_verifier enforced
//   - Prevents authorization code interception attacks
//
// 6. Token Revocation (RFC 7009):
//   - Clients can revoke access and refresh tokens
//   - Client authentication required
//   - All revocations logged for audit trail
//
// 7. Cryptographically Secure Token Generation:
//   - All tokens generated using crypto/rand (not math/rand)
//   - 48-byte access and refresh tokens (384 bits of entropy)
//   - 32-byte client IDs and secrets
//
// Security Considerations:
//   - Token Storage: Tokens can be encrypted at rest with AES-256-GCM. Enable via
//     Security.EncryptionKey for production deployments.
//   - Logging: All sensitive data (tokens, emails, PII) is hashed before logging using
//     SHA256 to prevent exposure in log files. Only use structured logging.
//   - Clock Skew: A 5-second grace period is applied to token expiration checks to handle
//     time synchronization issues between systems.
//   - Refresh Token Protection: Tokens with valid refresh tokens are preserved even if
//     the access token expires, allowing automatic renewal.
//   - Rate Limiting: Per-IP and per-user rate limiting prevents brute force attacks and
//     DoS attempts. Configure based on your threat model.
//
// Compliance:
//   - OAuth 2.1 Draft: Implements key security improvements
//   - RFC 6749: OAuth 2.0 Authorization Framework
//   - RFC 6750: Bearer Token Usage
//   - RFC 7009: Token Revocation
//   - RFC 7591: Dynamic Client Registration
//   - RFC 7636: PKCE (S256 only)
//   - RFC 8414: Authorization Server Metadata
//   - RFC 9728: Protected Resource Metadata
//
// The package is designed to be used by the MCP server's HTTP and SSE transports
// to add OAuth protection to their endpoints.
//
// Example usage:
//
//	// Generate encryption key for production (do this once, store securely)
//	encKey, _ := oauth.GenerateEncryptionKey()
//	// Or load from environment: oauth.EncryptionKeyFromBase64(os.Getenv("OAUTH_ENCRYPTION_KEY"))
//
//	// Create OAuth handler with full security features
//	handler, err := oauth.NewHandler(&oauth.Config{
//		Resource: "https://mcp.example.com",
//		SupportedScopes: []string{
//			"https://www.googleapis.com/auth/gmail.readonly",
//			// ... other Google scopes
//		},
//		GoogleAuth: oauth.GoogleAuthConfig{
//			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//		},
//		RateLimit: oauth.RateLimitConfig{
//			Rate:     10,
//			Burst:    20,
//			UserRate: 100,
//			UserBurst: 200,
//		},
//		Security: oauth.SecurityConfig{
//			EncryptionKey: encKey,                      // Enable encryption
//			EnableAuditLogging: true,                   // Enable audit logs
//			DisableRefreshTokenRotation: false,         // Enable rotation
//			AllowPublicClientRegistration: false,       // Require auth
//			RegistrationAccessToken: "secure-token",    // Registration token
//			RefreshTokenTTL: 90 * 24 * time.Hour,      // 90 days
//		},
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Protect MCP endpoints
//	http.Handle("/mcp", handler.ValidateGoogleToken(mcpHandler))
//
//	// Serve metadata endpoints
//	http.HandleFunc("/.well-known/oauth-protected-resource",
//		handler.ServeProtectedResourceMetadata)
//	http.HandleFunc("/.well-known/oauth-authorization-server",
//		handler.ServeAuthorizationServerMetadata)
//
//	// Token revocation endpoint (RFC 7009)
//	http.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
package oauth
