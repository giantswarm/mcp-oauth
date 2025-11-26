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
- CORS support for browser-based clients

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
    mux := http.NewServeMux()
    
    // Register Protected Resource Metadata endpoints (root + sub-path)
    handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
    
    // Protected MCP endpoint
    mux.Handle("/mcp", handler.ValidateToken(yourMCPHandler))

    http.ListenAndServe(":8080", mux)
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

> **📖 For comprehensive security documentation, see [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)**  
> This document explains the two-layer PKCE architecture, attack mitigation strategies, and production deployment best practices.

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

### WWW-Authenticate Header & Protected Resource Discovery

The library implements MCP 2025-11-25 specification for Protected Resource Metadata discovery via WWW-Authenticate headers. When enabled, all 401 Unauthorized responses include enhanced headers that help clients discover the authorization server and required scopes.

**Configuration:**

```go
config := &server.Config{
    Issuer: "https://your-domain.com",
    
    // MCP 2025-11-25 compliant WWW-Authenticate headers are enabled by default
    // Only set to true if you need backward compatibility with legacy clients
    // DisableWWWAuthenticateMetadata: false,  // (default: false = enabled, secure)
    
    // Optional: Configure default scopes to advertise in 401 challenges
    DefaultChallengeScopes: []string{"mcp:access", "files:read"},
}
```

**Example Response:**

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource",
                         scope="mcp:access files:read",
                         error="invalid_token",
                         error_description="Token has expired"
```

**Security Considerations:**

- **Information Disclosure**: The `resource_metadata` URL and configured scopes are intentionally public information per OAuth 2.0/MCP specifications. This is similar to the existing metadata endpoint exposure and is required for proper OAuth discovery.
- **Scope Configuration**: Review your `DefaultChallengeScopes` carefully. Don't include overly specific scopes that could aid attackers in reconnaissance. Use broad, general scopes like `"mcp:access"` rather than `"internal:admin:full_access"`.
- **Backward Compatibility**: Set `DisableWWWAuthenticateMetadata: true` only if you need compatibility with legacy OAuth clients that may not understand enhanced WWW-Authenticate parameters. Modern OAuth clients ignore parameters they don't understand, so the default (enabled) is safe for most deployments.
- **Header Size Limits**: If configuring many scopes, be aware that some proxies/servers have HTTP header size limits (typically 8KB). The library will log warnings if you exceed 50 scopes.

**Specification Compliance:**
- RFC 6750 Section 3: Bearer token challenge format
- RFC 9728: Protected Resource Metadata discovery
- MCP 2025-11-25: MUST include resource_metadata in WWW-Authenticate

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

### Token Validation & Proactive Refresh

The server can proactively refresh provider tokens when they're near expiry, preventing validation failures and improving user experience:

```go
&oauth.ServerConfig{
    // Proactive token refresh threshold (default: 300 seconds = 5 minutes)
    // When a token will expire within this window and has a refresh token,
    // ValidateToken will attempt to refresh it before validation
    TokenRefreshThreshold: 300,
    
    // Clock skew grace period (default: 5 seconds)
    // Prevents false expiration errors due to clock synchronization issues
    ClockSkewGracePeriod: 5,
}
```

**How Proactive Refresh Works:**

1. During token validation, if the token will expire within `TokenRefreshThreshold`
2. AND the token has a refresh token available
3. The server attempts to refresh it with the provider (Google, GitHub, etc.)
4. On success: Updated token is saved, validation continues seamlessly
5. On failure: Gracefully falls back to normal validation (no error to user)

**Benefits:**

- **Better UX**: Users don't see "token expired" errors when refresh is possible
- **Fewer API calls**: Reduces failed validation attempts
- **Configurable**: Adjust threshold based on your token lifetimes and usage patterns
- **Graceful fallback**: Refresh failures don't break the validation flow

**Example scenarios:**

```go
// Default 5 minute threshold - good for most use cases
TokenRefreshThreshold: 300

// Longer threshold for high-security apps (more frequent refresh)
TokenRefreshThreshold: 600  // 10 minutes

// Shorter threshold for low-latency requirements
TokenRefreshThreshold: 60   // 1 minute
```

### CORS Support for Browser-Based Clients

Enable CORS (Cross-Origin Resource Sharing) to allow browser-based MCP clients to use your OAuth server:

```go
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        
        // Configure CORS for browser clients
        CORS: server.CORSConfig{
            // List of allowed origins
            AllowedOrigins: []string{
                "https://app.example.com",
                "https://dashboard.example.com",
            },
            // Enable credentials (cookies, Bearer tokens)
            AllowCredentials: true,
            // Preflight cache duration (seconds)
            MaxAge: 3600,
        },
    },
    logger,
)

// Don't forget to handle OPTIONS preflight requests:
http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodOptions {
        handler.ServePreflightRequest(w, r)
        return
    }
    handler.ServeToken(w, r)
})
```

**CORS Configuration Options:**

- `AllowedOrigins`: List of allowed origin URLs. Empty list disables CORS (default, secure).
- `AllowCredentials`: Set to `true` to allow cookies and authorization headers (needed for OAuth).
- `MaxAge`: How long (in seconds) browsers can cache preflight responses (default: 3600).

**⚠️  Security Warning: Wildcard Origins**

```go
CORS: server.CORSConfig{
    AllowedOrigins: []string{"*"},  // ⚠️  NOT RECOMMENDED for production!
}
```

Using wildcard `*` allows **any** website to make requests to your OAuth server, enabling potential CSRF attacks. **Only use specific origins in production.**

**How It Works:**

1. Browser sends OPTIONS preflight request before actual request
2. Server checks if origin is in `AllowedOrigins`
3. If allowed, sets CORS headers (`Access-Control-Allow-Origin`, etc.)
4. Browser proceeds with actual request
5. Server sets CORS headers on actual response too

**CORS is opt-in and disabled by default for security.** Only enable it if you have browser-based clients.

### Rate Limiting

#### IP-Based Rate Limiting

Protects against brute force attacks and DoS from specific IPs:

```go
ipRateLimiter := security.NewRateLimiter(
    10,    // 10 requests/second per IP
    20,    // burst of 20
    logger,
)
defer ipRateLimiter.Stop() // Important: cleanup background goroutines
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
defer userRateLimiter.Stop() // Important: cleanup background goroutines
server.SetUserRateLimiter(userRateLimiter)
```

#### Client Registration Rate Limiting

Prevents resource exhaustion through repeated client registration/deletion cycles:

```go
clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger)
defer clientRegRateLimiter.Stop() // Important: cleanup background goroutines
server.SetClientRegistrationRateLimiter(clientRegRateLimiter)

// Or with custom configuration:
clientRegRateLimiter := security.NewClientRegistrationRateLimiterWithConfig(
    10,              // max registrations per window
    time.Hour,       // time window
    10000,           // max IPs to track (memory bound)
    logger,
)
defer clientRegRateLimiter.Stop()
server.SetClientRegistrationRateLimiter(clientRegRateLimiter)
```

**Rate Limiter Configuration via Server Config:**

```go
&oauth.ServerConfig{
    // Time-windowed client registration limits
    MaxRegistrationsPerHour: 10,        // default: 10 per IP per hour
    RegistrationRateLimitWindow: 3600,  // default: 3600 seconds (1 hour)
    
    // Static limit (complementary to rate limiting)
    MaxClientsPerIP: 10,                // max total active clients per IP
}
```

**Security Benefits:**
- IP-based limiting prevents unauthenticated abuse
- User-based limiting prevents authenticated abuse
- Client registration limiting prevents registration/deletion cycle DoS
- Layered defense: all limits are enforced independently
- Time-windowed tracking prevents circumvention via deletion

**Important Lifecycle Management:**
All rate limiters run background cleanup goroutines. Always call `Stop()` when shutting down:

```go
// Proper cleanup prevents goroutine leaks
defer ipRateLimiter.Stop()
defer userRateLimiter.Stop()
defer clientRegRateLimiter.Stop()
```

### Client Registration Protection

The `AllowPublicClientRegistration` configuration controls **two security aspects**:

1. **DCR Endpoint Authentication**: Whether the `/oauth/register` endpoint requires a Bearer token
2. **Public Client Creation**: Whether public clients (native apps with `token_endpoint_auth_method: "none"`) can be registered

**Secure Production Configuration (Recommended):**

```go
&oauth.ServerConfig{
    // SECURE: Require authentication AND deny public client creation
    AllowPublicClientRegistration: false,
    
    // Registration access token (share only with trusted developers)
    RegistrationAccessToken: "your-secure-token-here", // Use: openssl rand -base64 32
    
    // Limit registrations per IP
    MaxClientsPerIP: 10,
}
```

With this configuration:
- Only authenticated requests (with valid token) can access `/oauth/register`
- Only **confidential clients** (with secrets) can be created
- Public clients are denied even with valid authentication

**Development/Native App Configuration:**

```go
&oauth.ServerConfig{
    // PERMISSIVE: Allow unauthenticated registration AND public clients
    AllowPublicClientRegistration: true,
    
    // Still recommended: limit per-IP to prevent abuse
    MaxClientsPerIP: 10,
}
```

With this configuration:
- Anyone can register clients (⚠️  DoS risk - use only in trusted environments)
- Both confidential AND public clients can be created

**Registering Clients:**

Confidential client (server-side app with secret):
```bash
curl -X POST https://your-server.com/oauth/register \
  -H "Authorization: Bearer your-registration-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Web App",
    "redirect_uris": ["https://myapp.com/callback"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

Public client (native/CLI app, requires `AllowPublicClientRegistration: true`):
```bash
curl -X POST https://your-server.com/oauth/register \
  -H "Authorization: Bearer your-registration-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Native App",
    "redirect_uris": ["myapp://callback"],
    "token_endpoint_auth_method": "none"
  }'
```

**Metadata Discovery & Security:**

The registration endpoint is advertised in RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`) when client registration is enabled:
- **Included**: When `RegistrationAccessToken` is set OR `AllowPublicClientRegistration=true`
- **Excluded**: When neither is configured (endpoint effectively disabled)

This conditional advertising provides defense-in-depth:
- RFC 8414-compliant clients can automatically discover the registration endpoint
- The endpoint remains hidden in metadata when registration is disabled
- Even if advertised, the endpoint enforces authentication via Bearer token
- Multiple layers of protection: authentication, rate limiting, per-IP limits, and audit logging

**Security Note:** Advertising the registration endpoint in metadata does NOT weaken security. The endpoint itself enforces strict authentication (when `AllowPublicClientRegistration=false`), rate limiting, and audit logging. This is analogous to advertising the token endpoint - it's public information about available functionality, but access is strictly controlled.

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

**Security Notes:**
- Only enable `TrustProxy` when behind a properly configured trusted reverse proxy
- **Critical for Rate Limiting**: IP-based rate limiting (including client registration limits) depends on accurate client IP extraction
- Without proper proxy configuration, attackers can spoof X-Forwarded-For headers to bypass rate limits
- Ensure your reverse proxy (nginx, HAProxy, CloudFlare, etc.) is configured to set X-Forwarded-For correctly

**Example nginx configuration:**
```nginx
location / {
    proxy_pass http://oauth-server:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
}
```

**Rate Limiting Effectiveness:**
Rate limiting is only as secure as your IP extraction. If `TrustProxy=false` (default), the library uses the direct connection IP, which is most secure but may not work behind proxies. If `TrustProxy=true`, ensure your proxy infrastructure is properly configured and trusted.

## 📊 Observability & Instrumentation

The library provides comprehensive OpenTelemetry (OTEL) instrumentation for metrics, distributed tracing, and structured logging.

### Quick Start

Enable instrumentation in your server configuration:

```go
import "github.com/giantswarm/mcp-oauth/instrumentation"

// Enable instrumentation with Prometheus metrics
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        Instrumentation: oauth.InstrumentationConfig{
            Enabled:         true,
            ServiceName:     "my-oauth-server",
            ServiceVersion:  "1.0.0",
            MetricsExporter: "prometheus", // Export metrics for Prometheus
            TracesExporter:  "otlp",       // Export traces via OTLP
            OTLPEndpoint:    "localhost:4318", // OTLP collector endpoint
        },
    },
    logger,
)

// Expose Prometheus metrics endpoint
import "github.com/prometheus/client_golang/prometheus/promhttp"
http.Handle("/metrics", promhttp.Handler())
```

### Exporter Configuration

The library supports multiple exporters for metrics and traces:

**Metrics Exporters:**
- `"prometheus"` - Export metrics in Prometheus format (production recommended)
- `"stdout"` - Print metrics to stdout (development/debugging)
- `"none"` or `""` - No metrics export (default, zero overhead)

**Trace Exporters:**
- `"otlp"` - Export traces via OTLP HTTP (production recommended, requires `OTLPEndpoint`)
- `"stdout"` - Print traces to stdout (development/debugging)
- `"none"` or `""` - No trace export (default, zero overhead)

**Examples:**

```go
// Production: Prometheus + OTLP traces
Instrumentation: oauth.InstrumentationConfig{
    Enabled:         true,
    MetricsExporter: "prometheus",
    TracesExporter:  "otlp",
    OTLPEndpoint:    "jaeger:4318", // Or your OTLP collector
}

// Development: stdout exporters for local debugging
Instrumentation: oauth.InstrumentationConfig{
    Enabled:         true,
    MetricsExporter: "stdout",
    TracesExporter:  "stdout",
}

// Minimal: Only metrics, no tracing
Instrumentation: oauth.InstrumentationConfig{
    Enabled:         true,
    MetricsExporter: "prometheus",
    TracesExporter:  "none",
}
```

### Available Metrics

**HTTP Layer:**
- `oauth.http.requests.total{method, endpoint, status}` - Total HTTP requests
- `oauth.http.request.duration{endpoint}` - Request duration (ms)

**OAuth Flows:**
- `oauth.authorization.started{client_id}` - Authorization flows started
- `oauth.code.exchanged{client_id, pkce_method}` - Authorization codes exchanged
- `oauth.token.refreshed{client_id, rotated}` - Tokens refreshed
- `oauth.token.revoked{client_id}` - Tokens revoked
- `oauth.client.registered{client_type}` - Clients registered

**Security:**
- `oauth.rate_limit.exceeded{limiter_type}` - Rate limit violations
- `oauth.pkce.validation_failed{method}` - PKCE validation failures
- `oauth.code.reuse_detected` - Authorization code reuse attempts
- `oauth.token.reuse_detected` - Token reuse attempts

**Storage:**
- `storage.operation.total{operation, result}` - Storage operations
- `storage.operation.duration{operation}` - Operation duration (ms)

**Provider:**
- `provider.api.calls.total{provider, operation, status}` - Provider API calls
- `provider.api.duration{provider, operation}` - API call duration (ms)
- `provider.api.errors.total{provider, operation, error_type}` - Provider API errors

### Distributed Tracing

Spans are automatically created for all major operations:

```
http.request (from otelhttp)
├── oauth.http.authorization
│   └── oauth.server.start_authorization_flow
│       ├── storage.save_authorization_state
│       └── provider.google.authorization_url
└── oauth.http.callback
    └── oauth.server.handle_provider_callback
        ├── storage.get_authorization_state
        ├── provider.google.exchange_code
        └── storage.save_token
```

### Performance

- **When disabled**: Zero overhead (uses no-op providers)
- **When enabled**: < 1% latency increase, ~1-2 MB memory for metric registry
- Thread-safe concurrent access
- Lock-free atomic operations for metrics

### Privacy & Compliance

**Data Collection:**

When instrumentation is enabled, the following data may be collected in distributed traces and metrics:
- **Client IPs** - For security monitoring and rate limit enforcement
- **Client IDs and User IDs** - Non-sensitive identifiers for tracking OAuth flows
- **OAuth Flow Metadata** - Scopes, PKCE methods, grant types, token types
- **Timing Information** - Request durations, operation latencies
- **Error Information** - Error codes and non-sensitive error descriptions

**Security Guarantees:**

✅ **Actual credentials are NEVER logged:**
- Access tokens, refresh tokens, authorization codes are never included in traces
- Client secrets are never logged
- Only metadata about tokens (type, expiry, family ID) is recorded

⚠️ **GDPR and Privacy Considerations:**
- **Client IP addresses** may be considered Personally Identifiable Information (PII) in some jurisdictions
- **User IDs** may be subject to privacy regulations depending on your implementation
- Configure trace sampling and retention policies appropriately for your compliance requirements
- Consider data minimization: disable instrumentation in regions with strict privacy laws if not needed

**Recommendations:**
1. Review your jurisdiction's privacy laws before enabling instrumentation in production
2. Configure appropriate trace sampling rates (e.g., 1% for high-volume systems)
3. Set reasonable retention periods for traces (7-30 days recommended)
4. Implement access controls on your observability infrastructure
5. Document data collection in your privacy policy
6. Consider using trace scrubbing/redaction for sensitive attributes

**Example - Minimal Data Collection:**

```go
// For privacy-sensitive environments, keep instrumentation disabled
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        Instrumentation: oauth.InstrumentationConfig{
            Enabled: false, // No data collection
        },
    },
    logger,
)
```

### Integration with Observability Backends

**Prometheus:**
The Prometheus exporter is pull-based and works with the standard `prometheus/client_golang` library. Simply expose the `/metrics` endpoint and configure Prometheus to scrape it.

**Jaeger/OpenTelemetry Collector:**
Use the OTLP trace exporter to send traces to Jaeger, Grafana Tempo, or any OTLP-compatible backend:

```bash
# Example: Run Jaeger with OTLP support
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4318:4318 \
  jaegertracing/all-in-one:latest

# Configure your OAuth server
OTLPEndpoint: "localhost:4318"
TracesExporter: "otlp"
```

See the [instrumentation package documentation](https://pkg.go.dev/github.com/giantswarm/mcp-oauth/instrumentation) for full details.

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
- ✅ **Rate Limiting**: Configure IP, user, and client registration rate limits
- ✅ **Rate Limiter Cleanup**: Call `Stop()` on all rate limiters during shutdown
- ✅ **PKCE Enforced**: Keep `RequirePKCE=true` (default)
- ✅ **S256 Only**: Keep `AllowPKCEPlain=false` (default)
- ✅ **Token Rotation**: Keep `AllowRefreshTokenRotation=true` (default)
- ✅ **Registration Protected**: Set `RegistrationAccessToken` or disable registration
- ✅ **Proxy Configured**: Set `TrustProxy` and `TrustedProxyCount` if behind proxy
- ✅ **Proxy Headers**: Verify reverse proxy correctly sets X-Forwarded-For (critical for rate limiting)

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

