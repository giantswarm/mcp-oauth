# Getting Started

This guide walks you through setting up an OAuth 2.1 Authorization Server for your MCP application.

## Contents

1. [Installation](#installation)
2. [Providers](#providers)
3. [Storage](#storage)
4. [Your First OAuth Server](#your-first-oauth-server)
5. [Testing Your Setup](#testing-your-setup)

## Installation

```bash
go get github.com/giantswarm/mcp-oauth
```

## Providers

Providers handle authentication with identity services (Google, GitHub, etc.). The library includes Google OAuth built-in and provides an interface for custom providers.

### Google Provider

```go
import "github.com/giantswarm/mcp-oauth/providers/google"

provider, err := google.NewProvider(&google.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "https://your-domain.com/oauth/callback",
    Scopes: []string{
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.readonly",
    },
})
if err != nil {
    log.Fatal(err)
}
```

**Getting Google Credentials:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Navigate to APIs & Services > Credentials
4. Create OAuth 2.0 Client ID
5. Add your redirect URI
6. Copy Client ID and Client Secret

### Custom Provider

Implement the `providers.Provider` interface:

```go
import "github.com/giantswarm/mcp-oauth/providers"

type MyProvider struct {
    // your fields
}

func (p *MyProvider) Name() string {
    return "my-provider"
}

func (p *MyProvider) AuthorizationURL(state string, opts *providers.AuthOptions) string {
    // Build authorization URL for your identity provider
    return fmt.Sprintf("https://auth.example.com/authorize?state=%s", state)
}

func (p *MyProvider) ExchangeCode(ctx context.Context, code string, opts *providers.ExchangeOptions) (*providers.TokenResponse, error) {
    // Exchange authorization code for tokens
    return &providers.TokenResponse{
        AccessToken:  "...",
        RefreshToken: "...",
        ExpiresIn:    3600,
    }, nil
}

func (p *MyProvider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
    // Validate token and return user info
    return &providers.UserInfo{
        ID:    "user-123",
        Email: "user@example.com",
    }, nil
}

func (p *MyProvider) RefreshToken(ctx context.Context, refreshToken string) (*providers.TokenResponse, error) {
    // Refresh an expired token
    return &providers.TokenResponse{...}, nil
}

func (p *MyProvider) RevokeToken(ctx context.Context, token string) error {
    // Revoke a token
    return nil
}
```

## Storage

Storage handles persistence for tokens, clients, and OAuth flows. The library provides in-memory storage and interfaces for custom backends.

### In-Memory Storage

Suitable for single-instance deployments and development:

```go
import "github.com/giantswarm/mcp-oauth/storage/memory"

store := memory.New()
defer store.Stop() // Clean up background goroutines
```

The in-memory storage implements all three storage interfaces:

- `TokenStore` - Access and refresh tokens
- `ClientStore` - OAuth client registrations  
- `FlowStore` - Authorization flow state

### Custom Storage

For production deployments requiring persistence or multi-instance setups, implement the storage interfaces. All methods accept `context.Context` for tracing and cancellation:

```go
import (
    "context"
    "time"

    "golang.org/x/oauth2"
    "github.com/giantswarm/mcp-oauth/providers"
    "github.com/giantswarm/mcp-oauth/storage"
)

// TokenStore handles token persistence
type TokenStore interface {
    SaveToken(ctx context.Context, userID string, token *oauth2.Token) error
    GetToken(ctx context.Context, userID string) (*oauth2.Token, error)
    DeleteToken(ctx context.Context, userID string) error
    SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error
    GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error)
    SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error
    GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error)
    DeleteRefreshToken(ctx context.Context, refreshToken string) error
}

// ClientStore handles OAuth client persistence
type ClientStore interface {
    SaveClient(ctx context.Context, client *storage.Client) error
    GetClient(ctx context.Context, clientID string) (*storage.Client, error)
    ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error
    ListClients(ctx context.Context) ([]*storage.Client, error)
    CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) error
}

// FlowStore handles authorization flow state
type FlowStore interface {
    SaveAuthorizationState(ctx context.Context, state *storage.AuthorizationState) error
    GetAuthorizationState(ctx context.Context, stateID string) (*storage.AuthorizationState, error)
    DeleteAuthorizationState(ctx context.Context, stateID string) error
    SaveAuthorizationCode(ctx context.Context, code *storage.AuthorizationCode) error
    GetAuthorizationCode(ctx context.Context, code string) (*storage.AuthorizationCode, error)
    DeleteAuthorizationCode(ctx context.Context, code string) error
}
```

**Example: Redis Storage**

```go
type RedisStore struct {
    client *redis.Client
}

func (r *RedisStore) SaveToken(userID string, token *oauth2.Token) error {
    data, _ := json.Marshal(token)
    return r.client.Set(ctx, "token:"+userID, data, 0).Err()
}

func (r *RedisStore) GetToken(userID string) (*oauth2.Token, error) {
    data, err := r.client.Get(ctx, "token:"+userID).Bytes()
    if err != nil {
        return nil, err
    }
    var token oauth2.Token
    json.Unmarshal(data, &token)
    return &token, nil
}
// ... implement remaining methods
```

## Your First OAuth Server

Here's a complete example that puts everything together:

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
    // 1. Configure provider
    provider, err := google.NewProvider(&google.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/oauth/callback",
        Scopes:       []string{"openid", "email", "profile"},
    })
    if err != nil {
        log.Fatalf("Failed to create provider: %v", err)
    }

    // 2. Configure storage
    store := memory.New()
    defer store.Stop()

    // 3. Create OAuth server
    server, err := oauth.NewServer(
        provider,
        store, // TokenStore
        store, // ClientStore
        store, // FlowStore
        &oauth.ServerConfig{
            Issuer:          "http://localhost:8080",
            SupportedScopes: []string{"openid", "email", "profile"},
        },
        nil, // logger (optional)
    )
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }

    // 4. Create handler
    handler := oauth.NewHandler(server, nil)

    // 5. Setup routes
    mux := http.NewServeMux()

    // OAuth endpoints (registered automatically)
    // GET  /.well-known/oauth-authorization-server
    // GET  /.well-known/oauth-protected-resource
    // GET  /oauth/authorize
    // POST /oauth/token
    // POST /oauth/register
    // POST /oauth/revoke
    
    handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")

    // Your protected MCP endpoint
    mux.Handle("/mcp", handler.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello from protected MCP endpoint!"))
    })))

    log.Println("OAuth server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Testing Your Setup

### 1. Start the Server

```bash
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
go run main.go
```

### 2. Check Discovery Endpoints

```bash
# Authorization Server Metadata
curl http://localhost:8080/.well-known/oauth-authorization-server

# Protected Resource Metadata
curl http://localhost:8080/.well-known/oauth-protected-resource
```

### 3. Register a Client

```bash
curl -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Test App",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

### 4. Test Protected Endpoint

```bash
# Without token - should return 401
curl -i http://localhost:8080/mcp

# Check WWW-Authenticate header for discovery info
```

## Next Steps

- [Configuration Guide](./configuration.md) - Customize your server
- [Security Guide](./security.md) - Production security settings
- [Discovery Mechanisms](./discovery.md) - OAuth discovery features
- [Examples](../examples/) - More complete examples

