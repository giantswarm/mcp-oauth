# Configuration Guide

This guide covers all configuration options for the mcp-oauth library.

## Contents

1. [Server Configuration](#server-configuration)
2. [CORS Configuration](#cors-configuration)
3. [Proxy Configuration](#proxy-configuration)
4. [Interstitial Page Customization](#interstitial-page-customization)
5. [Token Behavior](#token-behavior)
6. [Client Registration](#client-registration)
7. [Scope Configuration](#scope-configuration)

## Server Configuration

The `ServerConfig` struct controls the OAuth server behavior:

```go
import "github.com/giantswarm/mcp-oauth/server"

config := &server.Config{
    // Required: Your server's canonical URL
    Issuer: "https://auth.example.com",
    
    // Optional: All other fields have sensible defaults
}
```

### Core Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Issuer` | `string` | *required* | Canonical URL of your OAuth server |
| `ResourceIdentifier` | `string` | `""` | Resource identifier for token audience binding (RFC 8707) |
| `SupportedScopes` | `[]string` | `nil` | Scopes this server supports |

### Security Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `RequirePKCE` | `bool` | `true` | Require PKCE for all authorization requests |
| `AllowPKCEPlain` | `bool` | `false` | Allow insecure 'plain' PKCE method |
| `AllowRefreshTokenRotation` | `bool` | `true` | Enable refresh token rotation |
| `MinStateLength` | `int` | `16` | Minimum length for state parameter |

### Discovery Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `DisableWWWAuthenticateMetadata` | `bool` | `false` | Disable enhanced WWW-Authenticate headers |
| `DefaultChallengeScopes` | `[]string` | `nil` | Scopes to include in 401 challenges |
| `EnableClientIDMetadataDocuments` | `bool` | `false` | Enable URL-based client IDs (MCP 2025-11-25) |

### Example: Production Configuration

```go
config := &server.Config{
    Issuer:          "https://auth.example.com",
    SupportedScopes: []string{"openid", "email", "profile", "mcp:access"},
    
    // Security (all defaults are secure)
    RequirePKCE:               true,
    AllowPKCEPlain:            false,
    AllowRefreshTokenRotation: true,
    
    // Discovery
    DefaultChallengeScopes: []string{"mcp:access"},
    
    // Resource binding
    ResourceIdentifier: "https://api.example.com",
}
```

## CORS Configuration

Enable CORS (Cross-Origin Resource Sharing) for browser-based MCP clients:

```go
config := &server.Config{
    Issuer: "https://auth.example.com",
    
    CORS: server.CORSConfig{
        AllowedOrigins: []string{
            "https://app.example.com",
            "https://dashboard.example.com",
        },
        AllowCredentials: true,
        MaxAge:           3600, // Preflight cache duration in seconds
    },
}
```

### Handling Preflight Requests

```go
http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodOptions {
        handler.ServePreflightRequest(w, r)
        return
    }
    handler.ServeToken(w, r)
})
```

### CORS Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `AllowedOrigins` | `[]string` | `nil` | Allowed origin URLs (empty = CORS disabled) |
| `AllowCredentials` | `bool` | `false` | Allow cookies and authorization headers |
| `MaxAge` | `int` | `3600` | Preflight response cache duration |

**Security Warning**: Avoid wildcard origins (`*`) in production. This allows any website to make requests to your OAuth server.

## Proxy Configuration

When running behind a reverse proxy (nginx, HAProxy, CloudFlare):

```go
config := &server.Config{
    Issuer: "https://auth.example.com",
    
    TrustProxy:        true,  // Enable proxy header trust
    TrustedProxyCount: 2,     // Number of proxies in chain
}
```

### How It Works

Client IP extraction from `X-Forwarded-For`:
- `TrustedProxyCount: 1` - Uses the last IP in the chain
- `TrustedProxyCount: 2` - Skips last 2 IPs, uses the one before

**Example nginx configuration:**

```nginx
location / {
    proxy_pass http://oauth-server:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
}
```

**Important**: Only enable `TrustProxy` when behind a trusted reverse proxy. Without proper configuration, attackers can spoof IPs to bypass rate limiting.

## Interstitial Page Customization

When OAuth redirects to custom URL schemes (like `cursor://`, `vscode://`), browsers may fail silently. The library serves an HTML interstitial page as a fallback. You can customize this page.

### Simple Branding

```go
config := &server.Config{
    Issuer: "https://auth.example.com",
    
    Interstitial: &server.InterstitialConfig{
        Branding: &server.InterstitialBranding{
            LogoURL:            "https://cdn.example.com/logo.svg",
            LogoAlt:            "Example Corp",
            Title:              "Connected to Example Corp",
            Message:            "You have been authenticated successfully.",
            ButtonText:         "Return to App",
            PrimaryColor:       "#4F46E5",
            BackgroundGradient: "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)",
            CustomCSS:          ".container { max-width: 600px; }",
        },
    },
}
```

### Branding Options

| Field | Description |
|-------|-------------|
| `LogoURL` | Custom logo image (HTTPS required) |
| `LogoAlt` | Alt text for accessibility |
| `Title` | Page heading |
| `Message` | Success message (supports `{{.AppName}}` placeholder) |
| `ButtonText` | Button label (supports `{{.AppName}}` placeholder) |
| `PrimaryColor` | CSS color for buttons/highlights |
| `BackgroundGradient` | CSS background value |
| `CustomCSS` | Additional CSS (validated for security) |

### Custom Template

For more control, provide a custom HTML template:

```go
config := &server.Config{
    Interstitial: &server.InterstitialConfig{
        CustomTemplate: `<!DOCTYPE html>
<html>
<head><title>{{if .Title}}{{.Title}}{{else}}Success{{end}}</title></head>
<body>
    <h1>Welcome, authenticated with {{.AppName}}!</h1>
    <a href="{{.RedirectURL}}">Continue</a>
</body>
</html>`,
    },
}
```

**Template Variables:**
- `{{.RedirectURL}}` - OAuth redirect URL
- `{{.AppName}}` - Human-readable app name
- All branding fields are also available

### Custom Handler

For complete control:

```go
import "github.com/giantswarm/mcp-oauth/security"

config := &server.Config{
    Interstitial: &server.InterstitialConfig{
        CustomHandler: func(w http.ResponseWriter, r *http.Request) {
            redirectURL := oauth.InterstitialRedirectURL(r.Context())
            appName := oauth.InterstitialAppName(r.Context())
            
            // Set security headers (recommended)
            security.SetInterstitialSecurityHeaders(w, "https://auth.example.com")
            
            w.Header().Set("Content-Type", "text/html")
            fmt.Fprintf(w, "<html><body><a href='%s'>Open %s</a></body></html>", 
                redirectURL, appName)
        },
    },
}
```

## Token Behavior

### Proactive Token Refresh

The server can refresh tokens before they expire, improving user experience:

```go
config := &server.Config{
    // Refresh tokens when they expire within this window (seconds)
    TokenRefreshThreshold: 300, // 5 minutes (default)
    
    // Grace period for clock synchronization issues (seconds)
    ClockSkewGracePeriod: 5,
}
```

**How it works:**
1. During validation, if token expires within `TokenRefreshThreshold`
2. AND the token has a refresh token
3. Server attempts to refresh it with the provider
4. On success: Updated token saved, validation continues
5. On failure: Graceful fallback to normal validation

### Token Lifetimes

Token lifetimes are typically controlled by the identity provider. For server-issued tokens:

```go
config := &server.Config{
    // Authorization code lifetime (default: 10 minutes)
    AuthorizationCodeLifetime: 600,
}
```

## Client Registration

Control dynamic client registration:

```go
config := &server.Config{
    // Require authentication for /oauth/register
    AllowPublicClientRegistration: false,
    
    // Registration access token (share only with trusted developers)
    RegistrationAccessToken: os.Getenv("REGISTRATION_TOKEN"),
    
    // Limit registrations per IP
    MaxClientsPerIP: 10,
    
    // Rate limiting
    MaxRegistrationsPerHour:     10,
    RegistrationRateLimitWindow: 3600, // seconds
}
```

### Client Types

**Confidential clients** (server-side apps with secrets):
```bash
curl -X POST https://auth.example.com/oauth/register \
  -H "Authorization: Bearer $REGISTRATION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Web App",
    "redirect_uris": ["https://myapp.com/callback"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

**Public clients** (native/CLI apps, requires `AllowPublicClientRegistration: true`):
```bash
curl -X POST https://auth.example.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Native App",
    "redirect_uris": ["myapp://callback"],
    "token_endpoint_auth_method": "none"
  }'
```

### Custom Redirect URI Schemes

Support native/mobile apps with custom URI schemes:

```go
config := &server.Config{
    AllowedCustomSchemes: []string{
        "^myapp$",                  // Exact: myapp://
        "^com\\.example\\.",        // Prefix: com.example.*://
        "^[a-z][a-z0-9+.-]*$",      // RFC 3986 (default)
    },
}
```

Dangerous schemes (`javascript`, `data`, `file`) are always blocked.

## Scope Configuration

### Server-Wide Scopes

```go
config := &server.Config{
    // All scopes this server supports
    SupportedScopes: []string{
        "openid",
        "email",
        "profile",
        "mcp:access",
        "files:read",
        "files:write",
        "admin:access",
    },
    
    // Scopes to advertise in 401 challenges
    DefaultChallengeScopes: []string{"mcp:access"},
}
```

### Endpoint-Specific Scopes

Require specific scopes for different endpoints:

```go
config := &server.Config{
    // Path-based requirements (wildcards supported)
    EndpointScopeRequirements: map[string][]string{
        "/api/files/*":  {"files:read", "files:write"},
        "/api/admin/*":  {"admin:access"},
    },
    
    // Method + path requirements
    EndpointMethodScopeRequirements: map[string]map[string][]string{
        "/api/files/*": {
            "GET":    {"files:read"},
            "POST":   {"files:write"},
            "DELETE": {"files:delete", "admin:access"},
        },
    },
}
```

### Per-Path Metadata

Different API paths can advertise different requirements:

```go
config := &server.Config{
    ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
        "/mcp/files": {
            ScopesSupported: []string{"files:read", "files:write"},
        },
        "/mcp/admin": {
            ScopesSupported:      []string{"admin:access"},
            AuthorizationServers: []string{"https://admin-auth.example.com"},
        },
    },
}
```

See [Discovery Mechanisms](./discovery.md) for more on per-path metadata.

## Next Steps

- [Security Guide](./security.md) - Security features and production checklist
- [Observability](./observability.md) - Metrics and tracing
- [Discovery Mechanisms](./discovery.md) - OAuth discovery configuration

