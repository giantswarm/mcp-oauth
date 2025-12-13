# Security Guide

This guide covers security configuration for production deployments. For deep technical details on the security implementation, see [Security Architecture](../SECURITY_ARCHITECTURE.md).

## Contents

1. [Secure Defaults](#secure-defaults)
2. [Production Checklist](#production-checklist)
3. [Token Encryption](#token-encryption)
4. [Rate Limiting](#rate-limiting)
5. [Audit Logging](#audit-logging)
6. [Client Registration Protection](#client-registration-protection)
7. [Redirect URI Security](#redirect-uri-security)
8. [Legacy Client Support](#legacy-client-support)

## Secure Defaults

The library follows **secure-by-default** principles. All security features are enabled out of the box:

| Feature | Default | Description |
|---------|---------|-------------|
| PKCE Required | Enabled | Mandatory PKCE for all authorization flows |
| S256 Only | Enabled | Rejects insecure 'plain' PKCE method |
| Refresh Token Rotation | Enabled | Automatic rotation with reuse detection |
| WWW-Authenticate Metadata | Enabled | Enhanced 401 headers for discovery |
| No Proxy Trust | Enabled | Doesn't trust X-Forwarded-For by default |

**No configuration needed for secure defaults:**

```go
server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
        // All security features enabled by default
    },
    logger,
)
```

## Production Checklist

Before deploying to production, verify these settings:

### Required

- [ ] **HTTPS Only**: `Issuer` uses `https://` URL
- [ ] **PKCE Enforced**: `RequirePKCE` is `true` (default)
- [ ] **S256 Only**: `AllowPKCEPlain` is `false` (default)

### Recommended

- [ ] **Token Encryption**: Enable via `SetEncryptor()` for at-rest encryption
- [ ] **Audit Logging**: Set up `Auditor` for security event logging
- [ ] **Rate Limiting**: Configure IP, user, and client registration limits
- [ ] **Registration Protected**: Set `RegistrationAccessToken` or disable registration
- [ ] **Proxy Configured**: Set `TrustProxy` and `TrustedProxyCount` if behind proxy
- [ ] **Production Mode**: Set `ProductionMode=true` for strict redirect URI validation

### High-Security (Recommended for Sensitive Environments)

- [ ] **DNS Validation**: Enable `DNSValidation=true` to check hostname IPs
- [ ] **Strict DNS**: Enable `DNSValidationStrict=true` for fail-closed DNS validation
- [ ] **Auth-Time Validation**: Enable `ValidateRedirectURIAtAuthorization=true` for TOCTOU protection

### Rate Limiter Cleanup

All rate limiters run background goroutines. Always call `Stop()` during shutdown:

```go
defer ipRateLimiter.Stop()
defer userRateLimiter.Stop()
defer clientRegRateLimiter.Stop()
```

## Token Encryption

Encrypt tokens at rest using AES-256-GCM:

```go
import "github.com/giantswarm/mcp-oauth/security"

// Generate key once, store securely (e.g., secrets manager)
key, err := security.GenerateKey()
if err != nil {
    log.Fatal(err)
}

// Create encryptor
encryptor, err := security.NewEncryptor(key)
if err != nil {
    log.Fatal(err)
}

// Attach to server
server.SetEncryptor(encryptor)
```

**Key Management:**
- Generate keys using `security.GenerateKey()` (32 bytes, cryptographically random)
- Store keys in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
- Never commit keys to version control
- Rotate keys periodically

## Rate Limiting

### IP-Based Rate Limiting

Protect against brute force attacks and DoS:

```go
import "github.com/giantswarm/mcp-oauth/security"

ipRateLimiter := security.NewRateLimiter(
    10,    // 10 requests/second per IP
    20,    // burst of 20
    logger,
)
defer ipRateLimiter.Stop()

server.SetRateLimiter(ipRateLimiter)
```

### User-Based Rate Limiting

Additional limits for authenticated users:

```go
userRateLimiter := security.NewRateLimiter(
    100,   // 100 requests/second per user
    200,   // burst of 200
    logger,
)
defer userRateLimiter.Stop()

server.SetUserRateLimiter(userRateLimiter)
```

### Client Registration Rate Limiting

Prevent resource exhaustion through registration/deletion cycles:

```go
// Default configuration
clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger)
defer clientRegRateLimiter.Stop()

server.SetClientRegistrationRateLimiter(clientRegRateLimiter)

// Or with custom configuration
clientRegRateLimiter := security.NewClientRegistrationRateLimiterWithConfig(
    10,              // max registrations per window
    time.Hour,       // time window
    10000,           // max IPs to track
    logger,
)
```

### Configuration via Server Config

```go
config := &server.Config{
    // Time-windowed limits
    MaxRegistrationsPerHour:     10,
    RegistrationRateLimitWindow: 3600, // seconds
    
    // Static limit
    MaxClientsPerIP: 10,
}
```

## Audit Logging

Log all security-relevant events:

```go
import "github.com/giantswarm/mcp-oauth/security"

auditor := security.NewAuditor(logger, true) // true = verbose mode
server.SetAuditor(auditor)
```

### Logged Events

| Event | Description |
|-------|-------------|
| `token_issued` | Access token issued |
| `token_refreshed` | Token refreshed |
| `token_revoked` | Token revoked |
| `auth_failure` | Authentication failure |
| `rate_limit_exceeded` | Rate limit violation |
| `authorization_code_reuse` | Code reuse attempt (attack indicator) |
| `token_reuse_detected` | Refresh token reuse (theft indicator) |
| `invalid_pkce` | PKCE validation failure |
| `client_registered` | New client registered |

### Monitoring Recommendations

Set up alerts for:
- `authorization_code_reuse` - Possible attack
- `token_reuse_detected` - Possible token theft
- `rate_limit_exceeded` - Possible abuse
- Spikes in `auth_failure` - Brute force attempt

## Client Registration Protection

The `AllowPublicClientRegistration` setting controls two aspects:

1. **DCR Endpoint Authentication**: Whether `/oauth/register` requires a Bearer token
2. **Public Client Creation**: Whether clients with `token_endpoint_auth_method: "none"` can be created

### Secure Production Configuration

```go
config := &server.Config{
    // Require authentication and deny public clients
    AllowPublicClientRegistration: false,
    
    // Registration token (generate: openssl rand -base64 32)
    RegistrationAccessToken: os.Getenv("REGISTRATION_TOKEN"),
    
    // Limit per IP
    MaxClientsPerIP: 10,
}
```

With this configuration:
- Only authenticated requests can access `/oauth/register`
- Only confidential clients (with secrets) can be created
- Public clients are denied even with valid authentication

### Trusted Custom URI Schemes (Cursor/IDE Compatibility)

For MCP clients like Cursor that don't support registration tokens, you can allow unauthenticated registration **only** for clients using trusted custom URI schemes:

```go
config := &server.Config{
    // Require token for most clients
    AllowPublicClientRegistration: false,
    RegistrationAccessToken: os.Getenv("REGISTRATION_TOKEN"),
    
    // Allow unauthenticated registration for IDE clients
    TrustedPublicRegistrationSchemes: []string{
        "cursor",
        "vscode",
        "vscode-insiders",
        "windsurf",
    },
    
    // Strict scheme matching is enabled by default when TrustedPublicRegistrationSchemes is set
    // To allow mixed schemes (not recommended), set DisableStrictSchemeMatching: true
}
```

**Security Model:**

This feature relies on **two layers of protection**:

1. **PKCE (Primary Defense):** Even if an attacker intercepts the authorization code via scheme hijacking, they cannot exchange it without the `code_verifier`. PKCE is enforced by default and is the primary security control.

2. **Custom URI Scheme Registration:** Custom URI schemes (e.g., `cursor://`, `vscode://`) are typically registered at the OS level, making them harder to hijack than web URLs.

**Platform Considerations:**

Custom URI scheme protection varies by platform:

| Platform | Protection Level | Notes |
|----------|-----------------|-------|
| macOS/iOS | Moderate | Schemes registered per-app, but no verification of who registered first |
| Windows | Moderate | Any app can register a scheme; first-installer-wins |
| Android | Strong (App Links) | App Links provide verified ownership; traditional schemes are weaker |
| Linux | Weak | Depends on desktop environment configuration |

**Because platform protection varies, PKCE enforcement is critical.** The library requires PKCE by default (`RequirePKCE=true`, `AllowPKCEPlain=false`), which mitigates scheme hijacking attacks on all platforms.

**Automatic Security Filtering:**

The following schemes are automatically **blocked** from `TrustedPublicRegistrationSchemes`:
- `http://` and `https://` - Can be hijacked by any attacker with a web server
- Dangerous schemes: `javascript:`, `data:`, `file:`, `vbscript:`, `about:`, `ftp:`, `blob:`, `ms-appx:`

**Security Controls:**

| Setting | Default | Description |
|---------|---------|-------------|
| `TrustedPublicRegistrationSchemes` | `[]` | List of allowed schemes for token-free registration |
| `DisableStrictSchemeMatching` | `false` | Set to `true` to allow mixed schemes (not recommended) |

Strict scheme matching is automatically enabled when `TrustedPublicRegistrationSchemes` is configured. This ensures ALL redirect URIs must use trusted schemes for unauthenticated registration.

**Audit Logging:**

Registrations via trusted schemes are logged with event type `client_registered_via_trusted_scheme` for security monitoring.

### Development Configuration

```go
config := &server.Config{
    // Allow unauthenticated registration and public clients
    AllowPublicClientRegistration: true,
    
    // Still limit per IP
    MaxClientsPerIP: 10,
}
```

Use only in trusted development environments.

## Redirect URI Security

The library provides comprehensive redirect URI validation to prevent SSRF and open redirect attacks. **All security features are enabled by default** following the library's principle of "secure by default, explicit opt-out for less security."

### Secure by Default

The following security controls are **automatically enabled**:

| Setting | Default | Description |
|---------|---------|-------------|
| `ProductionMode` | `true` | HTTPS required for non-loopback URIs |
| `DNSValidation` | `true` | Resolve hostnames to check IPs |
| `DNSValidationStrict` | `true` | Fail-closed on DNS failures |
| `ValidateRedirectURIAtAuthorization` | `true` | Re-validate at authorization time (TOCTOU protection) |
| `AllowLocalhostRedirectURIs` | `false` | Loopback blocked by default (set to `true` for native apps) |
| `AllowPrivateIPRedirectURIs` | `false` | RFC 1918 private IPs blocked |
| `AllowLinkLocalRedirectURIs` | `false` | 169.254.x.x/fe80:: blocked (cloud SSRF) |

**Note for Native/CLI App Support:** If your OAuth server needs to support native applications (desktop apps, CLI tools), you must set `AllowLocalhostRedirectURIs: true` per [RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3). This allows HTTP on loopback addresses (`localhost`, `127.x.x.x`, `::1`) which is required for native app OAuth flows.

### Escape Hatches for Less Strict Validation

If you need to reduce security for specific use cases, use the `Allow*` flags:

```go
config := &server.Config{
    // Native app support (RFC 8252) - allows HTTP on localhost/loopback
    AllowLocalhostRedirectURIs: true,
    
    // Internal/VPN deployments - allows RFC 1918 private IPs
    // WARNING: Enables SSRF to internal networks
    AllowPrivateIPRedirectURIs: true,
    
    // Rarely needed - allows link-local addresses
    // WARNING: Enables SSRF to cloud metadata services (169.254.169.254)
    AllowLinkLocalRedirectURIs: true,
}
```

### Disabling Security Features (Development Only)

To completely disable security features (e.g., for local development), use the explicit `Disable*` fields:

```go
config := &server.Config{
    // Disable HTTPS requirement for non-loopback (development only!)
    DisableProductionMode: true,
    
    // Disable DNS validation (if latency is unacceptable)
    DisableDNSValidation: true,
    
    // Use fail-open DNS validation (if DNS is unreliable)
    DisableDNSValidationStrict: true,
    
    // Skip authorization-time re-validation (if latency is critical)
    DisableAuthorizationTimeValidation: true,
}
```

**WARNING:** These `Disable*` fields significantly weaken security. Only use them in trusted development environments, never in production.

### Native App Support (RFC 8252)

For native/CLI apps that need localhost redirects:

```go
config := server.HighSecurityRedirectURIConfig()
config.Issuer = "https://auth.example.com"
// AllowLocalhostRedirectURIs is already true in HighSecurityRedirectURIConfig
```

Or manually:

```go
config := &server.Config{
    AllowLocalhostRedirectURIs: true,  // Allows http://localhost, http://127.0.0.1, http://[::1]
}
```

### DNS Validation Details

DNS validation is enabled by default and operates in **strict (fail-closed) mode**:

- Hostnames in redirect URIs are resolved via DNS
- If the resolved IP is private/link-local, registration is rejected
- If DNS resolution fails, registration is rejected (strict mode)
- At authorization time, redirect URIs are re-validated to catch DNS rebinding attacks

**TOCTOU (Time-of-Check to Time-of-Use) Protection:**

DNS rebinding attacks are mitigated by re-validating redirect URIs at authorization time (`ValidateRedirectURIAtAuthorization=true`), not just at registration.

**DNS Timeout Configuration:**

The DNS validation timeout controls how long to wait for DNS resolution:

```go
config := &server.Config{
    DNSValidationTimeout: 5 * time.Second,  // Default: 2s, Maximum: 30s
}
```

- **Default:** 2 seconds - fast enough for good UX, slow enough for most DNS servers
- **Maximum:** 30 seconds - values above this are automatically capped to prevent DoS via slow registrations
- **Negative values:** Automatically corrected to the default

**High-Volume Deployments:**

For environments with high-volume client registration, consider these infrastructure-level optimizations:

- **DNS Caching:** Deploy a local DNS cache (e.g., CoreDNS, dnsmasq) to reduce latency and external DNS load
- **Rate Limiting:** Apply rate limiting at the infrastructure level (reverse proxy, API gateway) to protect against registration abuse
- **Connection Pooling:** The library uses Go's default DNS resolver which pools connections; for extreme scale, consider a custom `DNSResolver` implementation with additional caching

### Blocked URI Schemes

The following schemes are always blocked (XSS/security risk):

- `javascript:` - XSS attacks via script execution
- `data:` - XSS attacks via inline content
- `file:` - Local filesystem access
- `vbscript:` - Legacy XSS (Internet Explorer)
- `about:` - Browser internals access
- `ftp:` - Insecure protocol
- `blob:` - XSS via Blob URLs (browser exploit vector)
- `ms-appx:` - Windows app package access
- `ms-appx-web:` - Windows app web content access

Customize via `BlockedRedirectSchemes` (not recommended).

### Known Limitations

**IPv6 Zone IDs:**

IPv6 addresses with zone IDs (e.g., `fe80::1%eth0`) cannot be parsed by Go's `net.ParseIP()`. When such addresses appear in redirect URIs:

- They are treated as hostnames rather than IP addresses
- If DNS validation is disabled, they may pass validation
- If DNS validation is enabled, they will fail DNS lookup (blocking registration in strict mode)

For maximum security, keep DNS validation enabled (`DNSValidation=true`, `DNSValidationStrict=true`) to ensure these edge cases are properly handled.

## Legacy Client Support

If you need to support older clients that don't support PKCE or S256:

```go
config := &server.Config{
    Issuer: "https://your-domain.com",
    
    // WARNING: Only enable for backward compatibility
    RequirePKCE:    false, // Allow clients without PKCE
    AllowPKCEPlain: true,  // Allow 'plain' method (insecure)
}
```

The server logs security warnings when these are enabled:

```
SECURITY WARNING: PKCE is DISABLED
SECURITY WARNING: Plain PKCE method is ALLOWED
```

**Always investigate and address security warnings before production deployment.**

## OAuth 2.1 Compliance

This library implements OAuth 2.1 security best practices:

| Requirement | Implementation |
|-------------|----------------|
| PKCE Required | Mandatory for all flows |
| Refresh Token Rotation | Automatic with reuse detection |
| S256 Only | 'plain' method rejected by default |
| State Required | CSRF protection enforced |
| HTTPS Required | Production deployments must use HTTPS |

## Next Steps

- [Configuration Guide](./configuration.md) - All configuration options
- [Security Architecture](../SECURITY_ARCHITECTURE.md) - Deep technical details
- [Discovery Mechanisms](./discovery.md) - OAuth discovery security

