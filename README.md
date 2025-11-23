# mcp-oauth

[![Go Reference](https://pkg.go.dev/badge/github.com/giantswarm/mcp-oauth.svg)](https://pkg.go.dev/github.com/giantswarm/mcp-oauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/giantswarm/mcp-oauth)](https://goreportcard.com/report/github.com/giantswarm/mcp-oauth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A production-ready OAuth 2.1 library for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers, implementing secure authentication with Google as the Authorization Server.

## Features

### Core OAuth 2.1 Implementation

- ✅ **OAuth 2.1 Compliant**: Implements OAuth 2.1 security best practices
- ✅ **Google Integration**: Uses Google as Authorization Server (Gmail, Drive, Calendar, etc.)
- ✅ **Dynamic Client Registration**: RFC 7591 compliant client registration
- ✅ **Token Revocation**: RFC 7009 token revocation endpoint
- ✅ **Protected Resource Metadata**: RFC 9728 metadata endpoints
- ✅ **PKCE Required**: S256 code challenge method enforced (plain disabled)

### Security Features (Production-Ready)

- 🔒 **Token Encryption at Rest**: AES-256-GCM authenticated encryption
- 🔄 **Refresh Token Rotation**: Automatic rotation with reuse detection (OAuth 2.1)
- 📝 **Comprehensive Audit Logging**: All security events logged with hashed sensitive data
- 🚦 **Rate Limiting**: Per-IP and per-user token bucket rate limiting
- 🔐 **Client Type Validation**: Enforces public vs confidential client authentication
- 🛡️ **Cryptographically Secure Tokens**: All tokens use crypto/rand (384 bits entropy)

### Developer Experience

- 📚 **Well Documented**: Comprehensive godoc and examples
- 🧪 **Thoroughly Tested**: High test coverage with table-driven tests
- 🔧 **Easy to Use**: Simple API with sensible defaults
- ⚡ **Production Ready**: Battle-tested in real MCP servers

## Installation

```bash
go get github.com/giantswarm/mcp-oauth
```

## Quick Start

### Basic Setup

```go
package main

import (
    "log"
    "net/http"
    "os"
    "time"
    
    oauth "github.com/giantswarm/mcp-oauth"
)

func main() {
    // Create OAuth handler with Google authentication
    handler, err := oauth.NewHandler(&oauth.Config{
        Resource: "https://mcp.example.com",
        SupportedScopes: []string{
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
        },
        GoogleAuth: oauth.GoogleAuthConfig{
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            RedirectURL:  "https://mcp.example.com/oauth/google/callback",
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Protect your MCP endpoints
    http.Handle("/mcp", handler.ValidateGoogleToken(mcpHandler))
    
    // Serve OAuth metadata endpoints
    http.HandleFunc("/.well-known/oauth-protected-resource", 
        handler.ServeProtectedResourceMetadata)
    http.HandleFunc("/.well-known/oauth-authorization-server", 
        handler.ServeAuthorizationServerMetadata)
    
    // OAuth endpoints
    http.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
    http.HandleFunc("/oauth/token", handler.ServeToken)
    http.HandleFunc("/oauth/google/callback", handler.ServeGoogleCallback)
    http.HandleFunc("/oauth/register", handler.ServeClientRegistration)
    http.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Production Setup with Full Security

```go
// Generate encryption key (do this once, store securely in KMS/Vault)
encKey, err := oauth.GenerateEncryptionKey()
if err != nil {
    log.Fatal(err)
}
// Or load from environment:
// encKey, err := oauth.EncryptionKeyFromBase64(os.Getenv("OAUTH_ENCRYPTION_KEY"))

handler, err := oauth.NewHandler(&oauth.Config{
    Resource: "https://mcp.example.com",
    SupportedScopes: []string{
        "https://www.googleapis.com/auth/gmail.readonly",
    },
    GoogleAuth: oauth.GoogleAuthConfig{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    },
    
    // Rate limiting configuration
    RateLimit: oauth.RateLimitConfig{
        Rate:      10,   // 10 requests/second per IP
        Burst:     20,   // Allow bursts up to 20
        UserRate:  100,  // 100 requests/second per user
        UserBurst: 200,
        TrustProxy: true, // If behind reverse proxy
    },
    
    // Security configuration (all enabled by default)
    Security: oauth.SecurityConfig{
        EncryptionKey: encKey,                          // Enable token encryption
        EnableAuditLogging: true,                       // Enable audit logs
        DisableRefreshTokenRotation: false,             // Enable rotation
        AllowPublicClientRegistration: false,           // Require auth
        RegistrationAccessToken: "secure-random-token", // Registration token
        RefreshTokenTTL: 90 * 24 * time.Hour,          // 90 days
        MaxClientsPerIP: 10,                           // Limit registrations
    },
})
```

## Architecture

This library implements a two-tier OAuth architecture:

```
┌─────────────┐         ┌──────────────┐         ┌────────────┐
│  MCP Client │◄────────┤  MCP Server  │◄────────┤   Google   │
│             │  Tokens │ (This Library)│  Tokens │   OAuth    │
│ OAuth Client│────────►│Resource Server│────────►│Authorization│
└─────────────┘         └──────────────┘         │   Server   │
                        Authorization             └────────────┘
                           Server
                           (Proxy)
```

- **MCP Server**: Acts as both OAuth Resource Server (validates tokens) and Authorization Server (proxies to Google)
- **Google**: Authorization Server that handles user authentication and issues tokens
- **MCP Client**: OAuth Client that obtains tokens and includes them in MCP requests

## Configuration

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable required Google APIs (Gmail, Drive, etc.)
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URIs: `https://yourdomain.com/oauth/google/callback`
6. Copy Client ID and Client Secret

### Environment Variables

```bash
# Required
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Optional (for production)
OAUTH_ENCRYPTION_KEY=base64-encoded-32-byte-key
OAUTH_REGISTRATION_TOKEN=secure-random-token-for-client-registration
```

### Configuration Options

#### GoogleAuthConfig

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `ClientID` | `string` | Google OAuth Client ID | ✅ |
| `ClientSecret` | `string` | Google OAuth Client Secret | ✅ |
| `RedirectURL` | `string` | OAuth callback URL | Optional (defaults to `{Resource}/oauth/google/callback`) |

#### RateLimitConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `Rate` | `int` | Requests/second per IP | 10 |
| `Burst` | `int` | Burst size per IP | 20 |
| `UserRate` | `int` | Requests/second per user | 100 |
| `UserBurst` | `int` | Burst size per user | 200 |
| `TrustProxy` | `bool` | Trust X-Forwarded-For header | false |
| `CleanupInterval` | `time.Duration` | Cleanup interval | 5 minutes |

#### SecurityConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `EncryptionKey` | `[]byte` | AES-256 key (32 bytes) for token encryption | nil (disabled) |
| `EnableAuditLogging` | `bool` | Enable security audit logging | true |
| `DisableRefreshTokenRotation` | `bool` | Disable refresh token rotation | false (rotation enabled) |
| `AllowPublicClientRegistration` | `bool` | Allow unauthenticated client registration | false |
| `RegistrationAccessToken` | `string` | Token required for client registration | "" |
| `RefreshTokenTTL` | `time.Duration` | Refresh token lifetime | 90 days |
| `MaxClientsPerIP` | `int` | Max clients per IP address | 10 |
| `AllowCustomRedirectSchemes` | `bool` | Allow custom URI schemes (e.g., `myapp://`) | true |

## Security

### Token Encryption

Tokens can be encrypted at rest using AES-256-GCM:

```go
// Generate a new encryption key
key, err := oauth.GenerateEncryptionKey()

// Or convert from base64 (for loading from env vars)
key, err := oauth.EncryptionKeyFromBase64(os.Getenv("ENCRYPTION_KEY"))

// Convert to base64 for storage
keyStr := oauth.EncryptionKeyToBase64(key)
```

### Refresh Token Rotation

OAuth 2.1 requires refresh token rotation to detect token theft:

```go
Security: oauth.SecurityConfig{
    DisableRefreshTokenRotation: false, // Keep enabled (default)
}
```

When enabled:
- Each token refresh issues a new refresh token
- Old refresh token is immediately invalidated
- Reuse of old tokens is detected and logged as a security event

### Audit Logging

All security events are logged with structured logging:

```go
Security: oauth.SecurityConfig{
    EnableAuditLogging: true, // Enabled by default
}
```

Logged events:
- Authentication attempts (success/failure)
- Token operations (issue, refresh, revoke)
- Rate limit violations
- Security violations (token reuse, invalid tokens)
- All sensitive data (tokens, emails) is hashed with SHA-256

### Rate Limiting

Prevent DoS and brute force attacks:

```go
RateLimit: oauth.RateLimitConfig{
    Rate:      10,  // 10 req/s per IP
    Burst:     20,  // Allow bursts
    UserRate:  100, // Higher limit for authenticated users
    UserBurst: 200,
}
```

## Client Registration

### Dynamic Registration (RFC 7591)

```bash
# Register a confidential client (server-side app)
curl -X POST https://mcp.example.com/oauth/register \
  -H "Authorization: Bearer YOUR_REGISTRATION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "client_type": "confidential",
    "redirect_uris": ["https://client.example.com/callback"],
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "https://www.googleapis.com/auth/gmail.readonly"
  }'

# Response includes client_id and client_secret
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_name": "My MCP Client",
  "redirect_uris": ["https://client.example.com/callback"],
  ...
}
```

### Public Clients (Mobile/SPA)

```json
{
  "client_type": "public",
  "token_endpoint_auth_method": "none",
  "redirect_uris": ["myapp://oauth/callback"]
}
```

## OAuth Flow

### 1. Client Registration

Register your client application with the MCP server (one-time setup).

### 2. Authorization Request

```
GET https://mcp.example.com/oauth/authorize?
  client_id=CLIENT_ID
  &redirect_uri=https://client.example.com/callback
  &scope=https://www.googleapis.com/auth/gmail.readonly
  &state=random-state
  &code_challenge=BASE64URL(SHA256(code_verifier))
  &code_challenge_method=S256
  &response_type=code
```

### 3. User Authentication

User is redirected to Google for authentication and consent.

### 4. Authorization Code

After consent, user is redirected back with authorization code:

```
https://client.example.com/callback?code=AUTH_CODE&state=random-state
```

### 5. Token Exchange

```bash
curl -X POST https://mcp.example.com/oauth/token \
  -u CLIENT_ID:CLIENT_SECRET \
  -d grant_type=authorization_code \
  -d code=AUTH_CODE \
  -d redirect_uri=https://client.example.com/callback \
  -d code_verifier=CODE_VERIFIER
```

Response:
```json
{
  "access_token": "ya29...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "1//...",
  "scope": "https://www.googleapis.com/auth/gmail.readonly"
}
```

### 6. Access Protected Resources

```bash
curl https://mcp.example.com/mcp \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 7. Token Refresh

```bash
curl -X POST https://mcp.example.com/oauth/token \
  -u CLIENT_ID:CLIENT_SECRET \
  -d grant_type=refresh_token \
  -d refresh_token=REFRESH_TOKEN
```

### 8. Token Revocation

```bash
curl -X POST https://mcp.example.com/oauth/revoke \
  -u CLIENT_ID:CLIENT_SECRET \
  -d token=ACCESS_OR_REFRESH_TOKEN
```

## API Reference

### Handler Methods

#### `NewHandler(config *Config) (*Handler, error)`

Creates a new OAuth handler with the provided configuration.

#### `ValidateGoogleToken(next http.Handler) http.Handler`

Middleware that validates Google OAuth tokens and injects user info into request context.

#### `ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request)`

Serves RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource`.

#### `ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request)`

Serves RFC 8414 Authorization Server Metadata at `/.well-known/oauth-authorization-server`.

#### `ServeAuthorization(w http.ResponseWriter, r *http.Request)`

Handles OAuth authorization requests (`/oauth/authorize`).

#### `ServeToken(w http.ResponseWriter, r *http.Request)`

Handles token endpoint requests (`/oauth/token`) for authorization_code and refresh_token grants.

#### `ServeGoogleCallback(w http.ResponseWriter, r *http.Request)`

Handles the Google OAuth callback (`/oauth/google/callback`).

#### `ServeClientRegistration(w http.ResponseWriter, r *http.Request)`

Handles dynamic client registration (`/oauth/register`).

#### `ServeTokenRevocation(w http.ResponseWriter, r *http.Request)`

Handles token revocation requests (`/oauth/revoke`).

### Utility Functions

#### `GenerateEncryptionKey() ([]byte, error)`

Generates a new 32-byte AES-256 encryption key.

#### `EncryptionKeyFromBase64(s string) ([]byte, error)`

Decodes a base64-encoded encryption key.

#### `EncryptionKeyToBase64(key []byte) string`

Encodes an encryption key to base64.

## Examples

See the [examples](./examples) directory for complete working examples:

- **[basic](./examples/basic)**: Simple MCP server with OAuth
- **[production](./examples/production)**: Production-ready setup with all security features
- **[custom-scopes](./examples/custom-scopes)**: Using multiple Google API scopes

## Testing

Run all tests:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

Run with race detector:

```bash
go test -race ./...
```

## Compliance

This library implements the following RFCs and specifications:

- **OAuth 2.1** (Draft): Modern OAuth security best practices
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 6750**: Bearer Token Usage
- **RFC 7009**: Token Revocation
- **RFC 7591**: Dynamic Client Registration
- **RFC 7636**: PKCE (S256 only, plain disabled)
- **RFC 8414**: Authorization Server Metadata
- **RFC 9728**: Protected Resource Metadata
- **MCP Specification**: Model Context Protocol (2025-06-18)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Policy

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io) ecosystem
- Implements [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2) integration

## Support

- 📖 [Documentation](https://pkg.go.dev/github.com/giantswarm/mcp-oauth)
- 🐛 [Issue Tracker](https://github.com/giantswarm/mcp-oauth/issues)
- 💬 [Discussions](https://github.com/giantswarm/mcp-oauth/discussions)

