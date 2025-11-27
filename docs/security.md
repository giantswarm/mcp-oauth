# Security Guide

This guide covers security configuration for production deployments. For deep technical details on the security implementation, see [Security Architecture](../SECURITY_ARCHITECTURE.md).

## Contents

1. [Secure Defaults](#secure-defaults)
2. [Production Checklist](#production-checklist)
3. [Token Encryption](#token-encryption)
4. [Rate Limiting](#rate-limiting)
5. [Audit Logging](#audit-logging)
6. [Client Registration Protection](#client-registration-protection)
7. [Legacy Client Support](#legacy-client-support)

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

- [ ] **Token Encryption**: Configure `EncryptionKey` for at-rest encryption
- [ ] **Audit Logging**: Set up `Auditor` for security event logging
- [ ] **Rate Limiting**: Configure IP, user, and client registration limits
- [ ] **Registration Protected**: Set `RegistrationAccessToken` or disable registration
- [ ] **Proxy Configured**: Set `TrustProxy` and `TrustedProxyCount` if behind proxy

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

