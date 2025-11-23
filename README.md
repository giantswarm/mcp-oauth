# mcp-oauth - OAuth 2.1 Authorization Server

A **provider-agnostic** library for implementing OAuth 2.1 Authorization Servers for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers, with support for multiple identity providers.

## ✨ Key Features

### 🔌 Provider Abstraction
- ✅ **Google OAuth** (built-in)
- ✅ Easy to add custom providers

### 🗄️ Storage Abstraction
- ✅ **In-memory** (built-in, production-ready)
- ✅ Simple interface to implement custom storage

### 🔒 Security Features
- Token encryption at rest (AES-256-GCM)
- Security audit logging
- Rate limiting (token bucket algorithm)
- PKCE enforcement (S256 only)
- Refresh token rotation (OAuth 2.1)

## 🏗️ Architecture

```
┌─────────────────┐
│   Your MCP App  │
└────────┬────────┘
         │
    ┌────▼─────┐
    │ Handler  │  (HTTP layer)
    └────┬─────┘
         │
    ┌────▼─────┐
    │  Server  │  (Business logic)
    └──┬───┬───┘
       │   │
   ┌───▼┐ ┌▼────────┐
   │Pro-│ │ Storage │
   │vider│ │         │
   └────┘ └─────────┘
```

**Clean Separation:**
- **Handler**: HTTP request/response handling
- **Server**: OAuth business logic (provider-agnostic)
- **Provider**: Identity provider integration (Google, or custom)
- **Storage**: Token/client/flow storage (in-memory, or custom)

## 🚀 Quick Start

Build an OAuth 2.1 Authorization Server for your MCP server:

```go
package main

import (
    "log"
    "net/http"
    "os"

    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/providers/google"
    "github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
    // 1. Choose a provider (Google in this example)
    provider, _ := google.NewProvider(&google.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/oauth/callback",
        Scopes:       []string{"openid", "email", "profile"},
    })

    // 2. Choose storage (in-memory is fine for most use cases)
    store := memory.New()
    defer store.Stop()

    // 3. Create OAuth server
    server, _ := oauth.NewServer(
        provider,
        store, // TokenStore
        store, // ClientStore
        store, // FlowStore
        &oauth.ServerConfig{
            Issuer: "http://localhost:8080",
        },
        nil, // logger (optional)
    )

    // 4. Create HTTP handler
    handler := oauth.NewHandler(server, nil)

    // 5. Setup routes
    http.HandleFunc("/.well-known/oauth-protected-resource",
        handler.ServeProtectedResourceMetadata)
    http.Handle("/mcp", handler.ValidateToken(yourMCPHandler))

    http.ListenAndServe(":8080", nil)
}
```

## 📦 Installation

```bash
go get github.com/giantswarm/mcp-oauth
```

## 🔌 Providers

### Google

```go
import "github.com/giantswarm/mcp-oauth/providers/google"

provider, err := google.NewProvider(&google.Config{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    RedirectURL:  "https://yourdomain.com/oauth/callback",
    Scopes: []string{
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.readonly",
    },
})
```

### Custom Provider

Implement the `providers.Provider` interface:

```go
type Provider interface {
    Name() string
    AuthorizationURL(state string, opts *AuthOptions) string
    ExchangeCode(ctx context.Context, code string, opts *ExchangeOptions) (*TokenResponse, error)
    ValidateToken(ctx context.Context, accessToken string) (*UserInfo, error)
    RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
    RevokeToken(ctx context.Context, token string) error
}
```

## 🗄️ Storage

### In-Memory (Built-in)

Perfect for most use cases:

```go
import "github.com/giantswarm/mcp-oauth/storage/memory"

store := memory.New()
defer store.Stop() // Cleanup background goroutines

server, _ := oauth.NewServer(
    provider,
    store, // TokenStore
    store, // ClientStore
    store, // FlowStore
    config,
    logger,
)
```

### Custom Storage

Implement the storage interfaces:

```go
import "golang.org/x/oauth2"

type TokenStore interface {
    SaveToken(userID string, token *oauth2.Token) error
    GetToken(userID string) (*oauth2.Token, error)
    DeleteToken(userID string) error
    // ... more methods
}
```

## 🔒 Security

### 🛡️ Secure by Default

This library follows the **secure-by-default** principle. All security features are enabled out of the box:

✅ **PKCE Required** - Mandatory PKCE (S256 only) for all authorization flows (OAuth 2.1)  
✅ **Refresh Token Rotation** - Automatic token rotation with reuse detection (OAuth 2.1)  
✅ **S256 Only** - Rejects insecure 'plain' PKCE method  
✅ **No Proxy Trust** - Doesn't trust X-Forwarded-For headers by default  
✅ **Rate Limiting** - Built-in protection against abuse

**No configuration needed for secure defaults!** Just create your server:

```go
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        // All security features enabled by default!
    },
    logger,
)
```

### 🔧 Supporting Legacy Clients

If you need to support older clients that don't support PKCE or S256:

```go
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        
        // ⚠️  WARNING: Only enable for backward compatibility
        RequirePKCE: false,        // Allow clients without PKCE
        AllowPKCEPlain: true,      // Allow 'plain' method (not recommended)
    },
    logger,
)
// The server will log security warnings when you use less secure options
```

**Important**: The server logs clear warnings when security features are weakened.

### Token Encryption

```go
import "github.com/giantswarm/mcp-oauth/security"

// Generate encryption key (do once, store securely)
key, _ := security.GenerateKey()

encryptor, _ := security.NewEncryptor(key)
server.SetEncryptor(encryptor)
```

### Audit Logging

```go
auditor := security.NewAuditor(logger, true)
server.SetAuditor(auditor)

// Now all security events are logged:
// - Token issued/refreshed/revoked
// - Authentication failures
// - Rate limit violations
// - Security configuration warnings
```

### Rate Limiting

#### IP-Based Rate Limiting

Protects against brute force attacks and DoS from specific IPs:

```go
ipRateLimiter := security.NewRateLimiter(
    10,    // 10 requests/second per IP
    20,    // burst of 20
    logger,
)
server.SetRateLimiter(ipRateLimiter)
```

#### User-Based Rate Limiting

Additional rate limiting for authenticated users (applies after authentication):

```go
userRateLimiter := security.NewRateLimiter(
    100,   // 100 requests/second per user (higher than IP limit)
    200,   // burst of 200
    logger,
)
server.SetUserRateLimiter(userRateLimiter)
```

**Security Benefits:**
- IP-based limiting prevents unauthenticated abuse
- User-based limiting prevents authenticated abuse
- Layered defense: both limits are enforced independently

### Client Registration Protection

Protect against DoS via mass client registration:

```go
&oauth.ServerConfig{
    // Require authentication for client registration (secure by default)
    AllowPublicClientRegistration: false,
    
    // Registration access token (share only with trusted developers)
    RegistrationAccessToken: "your-secure-token-here", // Use crypto/rand
    
    // Limit registrations per IP
    MaxClientsPerIP: 10,
}
```

Clients must include the registration token when registering:

```bash
curl -X POST https://your-server.com/oauth/register \
  -H "Authorization: Bearer your-registration-token" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My App", "redirect_uris": ["https://myapp.com/callback"]}'
```

### Custom Redirect URI Schemes

Support for native/mobile apps with custom URI schemes:

```go
&oauth.ServerConfig{
    // Allow custom schemes for native apps
    AllowedCustomSchemes: []string{
        "^myapp$",                  // Exact: myapp://
        "^com\\.example\\.",        // Prefix: com.example.*://
        "^[a-z][a-z0-9+.-]*$",      // RFC 3986 (default)
    },
}
```

**Security**: Dangerous schemes (javascript, data, file) are always blocked.

### Proxy Configuration

When running behind a reverse proxy (nginx, HAProxy, etc.):

```go
&oauth.ServerConfig{
    TrustProxy: true,         // Enable proxy header trust
    TrustedProxyCount: 2,     // Number of proxies (e.g., CloudFlare + nginx)
    // Extracts client IP from: ips[len(ips) - TrustedProxyCount - 1]
}
```

**Security Note**: Only enable `TrustProxy` when behind a properly configured trusted reverse proxy.

## 📚 Examples

See the [examples](./examples) directory:

- **[basic](./examples/basic)**: Simple setup with Google
- **[production](./examples/production)**: Full security features

## 🧪 Testing

The architecture makes testing easy:

```go
// Create a mock provider
type MockProvider struct{}

func (m *MockProvider) ValidateToken(ctx context.Context, token string) (*providers.UserInfo, error) {
    return &providers.UserInfo{
        ID:    "test-user",
        Email: "test@example.com",
    }, nil
}

// Use in tests
server, _ := oauth.NewServer(&MockProvider{}, mockStore, ...)
```

## 📜 License

Apache License 2.0

## 🛡️ Security Best Practices

### Production Deployment Checklist

Before deploying to production, ensure:

- ✅ **HTTPS Required**: Set `Issuer` to HTTPS URL
- ✅ **Token Encryption**: Set `EncryptionKey` (32 bytes from secure source)
- ✅ **Audit Logging**: Enable security audit logging
- ✅ **Rate Limiting**: Configure both IP and user rate limits
- ✅ **PKCE Enforced**: Keep `RequirePKCE=true` (default)
- ✅ **S256 Only**: Keep `AllowPKCEPlain=false` (default)
- ✅ **Token Rotation**: Keep `AllowRefreshTokenRotation=true` (default)
- ✅ **Registration Protected**: Set `RegistrationAccessToken` or disable registration
- ✅ **Proxy Configured**: Set `TrustProxy` and `TrustedProxyCount` if behind proxy

### Security Warnings

The library logs clear warnings when security is weakened:

```
⚠️  SECURITY WARNING: PKCE is DISABLED
⚠️  SECURITY WARNING: Plain PKCE method is ALLOWED
⚠️  SECURITY WARNING: Public client registration is ENABLED
```

**Always investigate and address security warnings before production deployment.**

### OAuth 2.1 Compliance

This library implements OAuth 2.1 security best practices:

- **PKCE Required**: Mandatory for all flows (prevents code interception)
- **Refresh Token Rotation**: Automatic token rotation with reuse detection
- **S256 Only**: Rejects insecure 'plain' PKCE method
- **State Required**: CSRF protection via state parameter
- **HTTPS Required**: Production deployments must use HTTPS

### Vulnerability Reporting

Report security vulnerabilities privately via GitHub Security Advisories or email:
- See [SECURITY.md](./SECURITY.md) for details
- **Do not** file public issues for security vulnerabilities

## 🤝 Contributing

Contributions welcome! Especially:
- New provider implementations
- Storage implementations
- Bug fixes and improvements
- Security enhancements

