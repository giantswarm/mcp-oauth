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
type TokenStore interface {
    SaveToken(userID string, token *providers.TokenResponse) error
    GetToken(userID string) (*providers.TokenResponse, error)
    DeleteToken(userID string) error
    // ... more methods
}
```

## 🔒 Security

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
```

### Rate Limiting

```go
rateLimiter := security.NewRateLimiter(
    10,    // 10 requests/second
    20,    // burst of 20
    logger,
)
server.SetRateLimiter(rateLimiter)
```

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

## 🤝 Contributing

Contributions welcome! Especially:
- New provider implementations
- Storage implementations
- Bug fixes and improvements

