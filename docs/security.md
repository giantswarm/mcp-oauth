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
8. [SSO Token Forwarding](#sso-token-forwarding)
9. [Legacy Client Support](#legacy-client-support)

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

- [ ] **Token Encryption**: Pass `oauth.WithEncryptor(...)` to `oauth.NewServer` for at-rest encryption
- [ ] **Audit Logging**: Pass `oauth.WithAuditor(...)` to `oauth.NewServer` for security event logging
- [ ] **Rate Limiting**: Configure IP, user, and client registration limits via `oauth.WithRateLimiter`, `oauth.WithUserRateLimiter`, `oauth.WithClientRegistrationRateLimiter`
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

// Attach to server at construction time
server, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://your-domain.com"},
    logger,
    oauth.WithEncryptor(encryptor),
)
```

`WithEncryptor` propagates the encryptor to the token store when the store implements `SetEncryptor(*security.Encryptor)` (memory and Valkey both do).

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

server, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://your-domain.com"},
    logger,
    oauth.WithRateLimiter(ipRateLimiter),
)
```

When configured, the limiter is enforced at the entry of every unauthenticated OAuth surface: `/authorize`, `/token`, `/revoke`, `/introspect`, `/register`, the discovery documents (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/openid-configuration`), `/.well-known/jwks.json`, and the `ValidateToken` middleware. Exceeded requests return `429` with `Retry-After` and emit a `rate_limit_exceeded` audit event.

`/authorize` is hit by end-user browsers, whereas `/token`, `/revoke`, and `/introspect` are typically server-to-server. Size the IP limit so a single shared egress (corporate NAT, mobile carrier) does not throttle real users; if that risk is real, run a separate limiter in front of `/authorize` via your reverse proxy.

IPv6 clients are bucketed to the `/64` prefix (the conventional end-site allocation) so an attacker holding a `/64` cannot rotate 2^64 addresses to bypass the per-IP limit. IPv4 is keyed by the full address. The bucket helper is exported as `security.RateLimitBucket(ip)`.

The `Retry-After` value on a 429 is computed from the limiter's configured rate (`ceil(1/rps)` for the token-bucket limiters, the configured window for the client-registration limiter). Operators tuning rate / burst do not need to update Retry-After separately.

`/token` and `/revoke` additionally enforce the user rate limiter (`server.WithUserRateLimiter(...)`) after client authentication completes, keyed on `client_id`. This bounds a compromised confidential client that already holds valid credentials. Public clients (no Basic Auth) remain bounded by the IP limit only.

### User-Based Rate Limiting

Additional limits for authenticated users:

```go
userRateLimiter := security.NewRateLimiter(
    100,   // 100 requests/second per user
    200,   // burst of 200
    logger,
)
defer userRateLimiter.Stop()

server, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://your-domain.com"},
    logger,
    oauth.WithUserRateLimiter(userRateLimiter),
)
```

To layer both IP and user limits, pass both options on the same `oauth.NewServer` call.

### Client Registration Rate Limiting

Prevent resource exhaustion through registration/deletion cycles:

```go
// Default configuration
clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger)
defer clientRegRateLimiter.Stop()

server, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://your-domain.com"},
    logger,
    oauth.WithClientRegistrationRateLimiter(clientRegRateLimiter),
)

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

server, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://your-domain.com"},
    logger,
    oauth.WithAuditor(auditor),
)
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

### Trusted HTTPS Redirect URIs (SaaS MCP Clients)

For well-known SaaS MCP clients (e.g. Claude.ai) whose redirect URI is fixed, operator-known, and HTTPS, you can allowlist specific URIs without enabling `AllowPublicClientRegistration` globally or pre-registering the client out-of-band:

```go
config := &server.Config{
    AllowPublicClientRegistration: false,
    RegistrationAccessToken:       os.Getenv("REGISTRATION_TOKEN"),

    TrustedPublicRegistrationRedirectURIs: []string{
        "https://claude.ai/api/mcp/auth_callback",
    },
}
```

**Matching:**

| Aspect | Behavior |
|---|---|
| Strictness | Every `redirect_uris` entry in the request must be in the allowlist; otherwise the token gate applies. |
| Normalization | Scheme and host are lowercased; HTTPS default port (`:443`) is stripped; trailing slashes are stripped from the path. |
| Path & query | Compared case-sensitively after normalization. |
| Public clients | `token_endpoint_auth_method: "none"` succeeds when the request matches the allowlist. |

**Configuration validation:**

Entries are validated at startup; the following are dropped with an error log and the feature is disabled if no valid entries remain:

- non-HTTPS schemes
- URIs with a fragment or userinfo
- IP literals that are loopback (`127.0.0.0/8`, `::1`), private (RFC 1918), link-local (`169.254.0.0/16`, `fe80::/10`), or unspecified (`0.0.0.0`, `::`)
- the hostname `localhost`
- duplicate entries after normalization

**Threat model vs. trusted schemes:**

| | Trusted scheme | Trusted HTTPS redirect URI |
|---|---|---|
| Allowlisted unit | URI scheme (`cursor`) | Full URI (`https://claude.ai/api/mcp/auth_callback`) |
| Attack on the callback | Possible if attacker registers the same scheme on the user's OS | Not possible — attacker cannot host the operator-attested URL |
| OS / platform dependency | Yes (varies per OS, see table above) | No |
| Primary defense | PKCE + OS-level scheme registration | PKCE + operator attestation of the URL |

This control is **narrower** than `TrustedPublicRegistrationSchemes`: only the specific URLs the operator vouches for can register, and they cannot be impersonated by an attacker who controls a different web server.

**Operator responsibility:**

Each entry vouches for a specific URL. Avoid allowlisting URLs on multi-tenant hosting (e.g. `https://*.github.io/...`, public pastebin / preview domains, or shared SaaS subdomains the operator does not control end-to-end) — any tenant on that host can host an attacker-controlled callback at the same URL. Allowlist only URLs whose host you trust the platform vendor for.

**Combining with `TrustedPublicRegistrationSchemes`:**

The two allowlists are independent — each is evaluated in strict mode. A registration request whose `redirect_uris` mixes a trusted scheme and a trusted HTTPS URI satisfies neither gate and is rejected. To onboard a custom-scheme client (e.g. Cursor) and a SaaS HTTPS client (e.g. Claude.ai) on the same server, register them as separate clients.

**Audit Logging:**

Registrations via the trusted HTTPS allowlist are logged with event type `client_registered_via_trusted_redirect_uri`. The matched URI is included in the event details.

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

## SSO Token Forwarding

The `TrustedAudiences` feature enables Single Sign-On (SSO) scenarios where tokens issued to a trusted upstream service can be accepted by downstream MCP servers.

### Use Case: MCP Aggregator Architecture

In architectures with an MCP aggregator (like muster) that proxies requests to downstream MCP servers:

1. Users authenticate to the aggregator once
2. The aggregator receives tokens with its own `client_id` as the audience
3. Downstream servers accept these forwarded tokens via `TrustedAudiences`

Without this feature, each downstream MCP server would require its own separate OAuth flow.

### Token Validation Flow

When `TrustedAudiences` is configured, the token validation follows a prioritized approach:

1. **JWT Detection**: Check if the Bearer token is a JWT (three dot-separated parts)
2. **JWKS Validation**: If the provider supports JWKS, validate the JWT signature using the provider's JWKS endpoint
3. **Audience Check**: Verify the JWT's `aud` claim matches one of the `TrustedAudiences`
4. **Claims Extraction**: Extract user info directly from JWT claims (sub, email, name, groups, etc.)
5. **Fallback**: If JWT validation fails, fall back to the provider's userinfo endpoint

This approach is critical for ID token forwarding scenarios. Many Identity Providers (IdPs) reject ID tokens when passed to their userinfo endpoint, as userinfo expects access tokens. By validating JWTs via JWKS first, the library can correctly handle forwarded ID tokens.

### Configuration

```go
config := &server.Config{
    Issuer:             "https://auth.example.com",
    ResourceIdentifier: "https://mcp-kubernetes.example.com",
    
    // Accept tokens issued to the muster aggregator
    TrustedAudiences: []string{
        "muster-client",
        "my-other-aggregator-client",
    },
}
```

JWKS documents are cached for 1 hour by default to balance performance with key rotation freshness.

### Provider Requirements

For JWT validation to work, the provider must implement the `JWKSProvider` interface:

| Provider | JWKS Support | Notes |
|----------|--------------|-------|
| Google   | Yes          | Uses `https://www.googleapis.com/oauth2/v3/certs` |
| Dex      | Yes          | Discovers JWKS URI via OIDC discovery |
| GitHub   | No           | GitHub OAuth Apps don't use OIDC/JWT |

Providers without JWKS support will always use userinfo endpoint validation.

### Security Model

| Aspect | Behavior |
|--------|----------|
| **JWKS Validation** | JWTs are validated via cryptographic signature verification |
| **Explicit Trust** | Each trusted audience must be explicitly configured |
| **Same Issuer** | Tokens are only accepted if from the configured IdP |
| **Own Identifier** | Server's own `ResourceIdentifier` is always implicitly trusted |
| **Audit Logging** | `EventForwardedIDTokenAccepted` and `EventCrossClientTokenAccepted` logged |
| **SSRF Protection** | JWKS URIs are validated to block private IPs, loopback, and link-local addresses |
| **DNS Rebinding Protection** | Resolved IPs are validated at connection time to prevent DNS rebinding attacks |
| **Memory Limits** | Response body limited to 1MB, max 100 keys per JWKS |
| **Algorithm Restriction** | Only RSA and ECDSA signing methods accepted (prevents algorithm confusion attacks like CVE-2015-9235) |
| **URL Normalization** | Case-insensitive host comparison, default port removal (443/80) |
| **Constant-Time** | Audience comparison uses constant-time comparison |

### Security Recommendations

1. **Minimize Trust**: Only add audiences you explicitly trust
2. **Same IdP**: All trusted audiences should use the same Identity Provider
3. **Monitor Logs**: Watch for `forwarded_id_token_accepted` and `cross_client_token_accepted` audit events
4. **Validate Scopes**: Use `EndpointScopeRequirements` for fine-grained access control
5. **JWKS Caching**: The default 1-hour cache TTL balances performance with key rotation freshness

### Direct Acceptance: `Server.AcceptForwardedIDToken`

`Server.ValidateToken` runs the JWKS/TrustedAudiences path opportunistically — if the token isn't a JWT or the audience doesn't match, it falls back to the userinfo endpoint. `Server.AcceptForwardedIDToken` is the direct, non-fallback entry point for callers that want the library to accept a forwarded token or fail hard.

Use it when an upstream intermediary (aggregator, bridge, sidecar) already holds a valid ID token from the trusted IdP and presents it as the Bearer credential. See [silent-authentication.md](./silent-authentication.md) for the full usage guide; this section covers the security properties and operator-facing configuration.

#### Session-ID correlation property

`AcceptForwardedIDToken` returns a deterministic identifier of the form `"ext-" + hex(sha256(bearerToken))[:16]`. Two MCP servers receiving the same bearer token compute the same identifier, which gives cross-hop audit-log correlation when an aggregator fans a single token out to multiple downstream servers. This is intentional for single-tenant deployments — it lets one correlation ID line up the hops of a distributed request without any coordination.

**Threat model implication:** anyone with audit-log access across two servers in the same correlation set can link a user's sessions across them via the token hash. The hash is one-way (the token cannot be recovered from the identifier), but session linkage is observable. For single-tenant deployments where all servers belong to the same operator and the same audit pipeline, this is a feature. For multi-tenant deployments where different operators run different servers and must not correlate sessions, it is a property to disable.

#### `Config.SessionIDHMACKey`: multi-tenant isolation

Setting `Config.SessionIDHMACKey` replaces the SHA-256 derivation with HMAC-SHA-256 keyed by the configured value. The identifier becomes `"ext-" + hex(hmac-sha256(key, bearerToken))[:16]` — still deterministic, but correlation holds only among servers that share the key.

```go
config := &server.Config{
    Issuer:           "https://auth.example.com",
    TrustedAudiences: []string{"muster-client"},

    // Per-deployment secret. Treat as sensitive; rotate via the same process
    // you use for EncryptionKey. Must be the same across all MCP servers that
    // should share session-ID correlation, and different from other tenants'.
    SessionIDHMACKey: mustReadKey("/etc/mcp/session-id-hmac.key"),
}
```

**Operator caveat (critical — the library cannot detect the mistake):** every MCP server in a correlation set must either *all* configure the same `SessionIDHMACKey` **or** *all* leave it empty. A single mismatched key silently breaks correlation with no runtime error — the tokens still validate, the sessions just no longer line up across hops. Treat the key as a deployment-wide constant and version it (e.g. `session-id-hmac-key-v1`) so rotations are explicit and detectable.

Recommended key properties: 32 random bytes from `crypto/rand`, base64-encoded for transport, loaded from a secret manager or mounted file (not from an environment variable).

#### Expiry behavior

`AcceptForwardedIDToken` does not refresh forwarded tokens — the library holds no refresh credential for them. When the JWT `exp` has passed, validation fails and the caller must propagate 401 so the MCP client re-authenticates against the upstream IdP. Callers should use `acceptance.ExpiresAt` to set any session-cache TTLs rather than re-parsing the JWT.

### Private IdP Deployments

If your Identity Provider (e.g., Dex) runs on a private network, JWKS fetching will fail due to SSRF protection. Use the `AllowPrivateIPJWKS` configuration option to allow JWKS endpoints to resolve to private IP addresses:

```go
config := &server.Config{
    Issuer:             "https://dex.internal.example.com",
    TrustedAudiences:   []string{"muster-client"},
    
    // Allow JWKS fetching from private IdP
    // WARNING: Reduces SSRF protection for JWKS endpoints only
    AllowPrivateIPJWKS: true,
}
```

| Setting | Default | Behavior |
|---------|---------|----------|
| `AllowPrivateIPJWKS` | `false` | Private IPs blocked for JWKS fetching |

**When enabled, allows:**
- Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
- Loopback addresses: 127.0.0.0/8, ::1
- Link-local addresses: 169.254.0.0/16, fe80::/10

**Security notes:**
- HTTPS is still required even when `AllowPrivateIPJWKS` is enabled
- This only affects JWKS fetching for SSO token validation (TrustedAudiences)
- A warning is logged at startup when this option is enabled
- For Google OAuth, this setting has no effect as Google's JWKS endpoint is always publicly accessible

### Example YAML Configuration

```yaml
# Downstream MCP server (mcp-kubernetes) configuration
oauth:
  issuer: "https://auth.example.com"
  resourceIdentifier: "https://mcp-kubernetes.example.com"
  # Trust tokens forwarded from muster aggregator
  trustedAudiences:
    - "muster-client"
```

### Audit Events

When a forwarded ID token is validated via JWKS, `EventForwardedIDTokenAccepted` is logged:

```json
{
  "event_type": "forwarded_id_token_accepted",
  "user_id": "user@example.com",
  "details": {
    "matched_audience": "muster-client",
    "email": "user@example.com",
    "validation_method": "jwks",
    "sso_token_forwarded": true
  }
}
```

When a token is accepted via `TrustedAudiences`, the `EventCrossClientTokenAccepted` event is logged:

```json
{
  "event_type": "cross_client_token_accepted",
  "user_id_hash": "a1b2c3d4...",
  "client_id": "original-client",
  "details": {
    "original_audience": "muster-client",
    "server_identifier": "https://mcp-kubernetes.example.com",
    "trusted_via": "TrustedAudiences",
    "sso_token_forwarded": true
  }
}
```

## JWKS Security Hardening

The JWKS (JSON Web Key Set) fetching mechanism includes multiple layers of security protection to prevent attacks during JWT validation.

### DNS Rebinding Protection

DNS rebinding attacks occur when an attacker controls a DNS server that initially resolves to a public IP (passing URL validation) but later resolves to a private IP during the actual HTTP connection. The library mitigates this by validating resolved IPs at connection time:

```go
// DNS rebinding protection is enabled by default when using NewJWKSClient
// The SSRF-safe HTTP client validates IPs after DNS resolution
client := oidc.NewJWKSClient(nil, 0, logger)
```

**How it works:**
1. URL validation checks the hostname against known private ranges
2. At connection time, DNS is resolved to actual IPs
3. Each resolved IP is validated against restricted ranges before connection
4. If any resolved IP is private/loopback/link-local, the connection is rejected

This prevents attackers from using DNS rebinding to access:
- Internal Kubernetes services
- Cloud metadata endpoints (169.254.169.254)
- Local development servers

### Algorithm Confusion Attack Prevention

The library explicitly restricts JWT signing algorithms to prevent algorithm confusion attacks (CVE-2015-9235):

| Algorithm Type | Supported | Why |
|---------------|-----------|-----|
| RSA (RS256, RS384, RS512) | Yes | Asymmetric, public key verification |
| RSA-PSS (PS256, PS384, PS512) | Yes | Asymmetric with improved padding |
| ECDSA (ES256, ES384, ES512) | Yes | Asymmetric, elliptic curve |
| HMAC (HS256, HS384, HS512) | **No** | Symmetric - enables key confusion attacks |

The algorithm check validates the **method type** (not just the header string), preventing attackers from changing the `alg` header to force HMAC verification with the public key.

### URL Normalization

Audience comparison uses strict URL normalization to prevent bypasses:

```go
// These are all considered equivalent:
"https://example.com"
"HTTPS://EXAMPLE.COM"
"https://example.com:443"
"https://example.com/"
```

Normalization includes:
- **Case normalization**: Scheme and host are lowercased
- **Default port removal**: `:443` for HTTPS, `:80` for HTTP
- **Trailing slash removal**: Consistent path handling
- **Path case preserved**: Only scheme/host are case-insensitive

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

