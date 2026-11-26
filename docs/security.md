# Security Guide

This guide covers security configuration for production deployments. For deep technical details on the security implementation, see [Security Architecture](../SECURITY_ARCHITECTURE.md).

## Contents

1. [Secure Defaults](#secure-defaults)
2. [Production Checklist](#production-checklist)
3. [Token Encryption](#token-encryption)
4. [Rate Limiting](#rate-limiting)
5. [Audit Logging](#audit-logging)
6. [Token Introspection (RFC 7662)](#token-introspection-rfc-7662)
7. [Client Registration Protection](#client-registration-protection)
8. [Redirect URI Security](#redirect-uri-security)
9. [SSO Token Forwarding](#sso-token-forwarding)
10. [Legacy Client Support](#legacy-client-support)

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

- [ ] **Token Encryption**: Pass `memory.WithEncryptor(enc)` / `valkey.WithEncryptor(enc)` to the store constructor for at-rest encryption
- [ ] **Audit Logging**: Set up `Auditor` for security event logging
- [ ] **Rate Limiting**: Configure IP, user, and client registration limits
- [ ] **Registration Protected**: Set `InitialAccessToken` or disable registration
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

// Wire into the store at construction.
store := memory.New(memory.WithEncryptor(encryptor))
srv, err := server.New(provider, store, store, store, cfg, logger)
```

The ciphertext envelope is versioned (`0x01 || kid || nonce || ct`); legacy
`nonce || ct` payloads produced by previous releases remain readable on
decrypt. `security.NewKeyRing` builds a [`security.KeyRing`](../security/encryption.go)
over fixed keys, an active one and previous ones for a rotation; operators
wanting an external KMS supply their own.

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

srv, err := server.New(provider, tokenStore, clientStore, flowStore, config, logger,
    server.WithRateLimiter(ipRateLimiter),
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

srv, err := server.New(provider, tokenStore, clientStore, flowStore, config, logger,
    server.WithUserRateLimiter(userRateLimiter),
)
```

### Client Registration Rate Limiting

Prevent resource exhaustion through registration/deletion cycles:

```go
// Default configuration
clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger)
defer clientRegRateLimiter.Stop()

srv, err := server.New(provider, tokenStore, clientStore, flowStore, config, logger,
    server.WithClientRegistrationRateLimiter(clientRegRateLimiter),
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

auditor := security.NewAuditor(logger, true) // true = enabled
// Set security.WithPIIRedaction(true) to hash client_id / IP / user_agent
// (user_id is always hashed) for regulated audit sinks.

srv, err := server.New(provider, store, store, store, cfg, logger, server.WithAuditor(auditor))
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
| `introspection_requester_denied` | Cross-client introspection probe (see [Token Introspection](#token-introspection-rfc-7662)) |

### Monitoring Recommendations

Set up alerts for:
- `authorization_code_reuse` - Possible attack
- `token_reuse_detected` - Possible token theft
- `rate_limit_exceeded` - Possible abuse
- Spikes in `auth_failure` - Brute force attempt
- Spikes in `introspection_requester_denied` with `reason=cross_client_probe` - DCR client enumerating tokens it does not own

## Token Introspection (RFC 7662)

`/oauth/introspect` is opt-in via `Config.EnableIntrospectionEndpoint`. When enabled, the endpoint enforces a **cross-client gate**: a client receives the RFC 7662 §2.2 response only for tokens it owns, or for tokens whose `client_id` it is enrolled for via `Config.IntrospectionResourceServers`. Every other probe returns `{"active": false}` with no other claims — byte-identical to an unknown-token response.

### Why the gate

Without it, any DCR-registered client could introspect any token in the store and learn (a) whether it is active and (b) the bound user's `sub` / `email` / `email_verified` / `name`. That is a passive token / user enumeration channel. The gate closes the channel while preserving introspection's legitimate use case (resource servers validating tokens issued to their own clients).

### Configuration

```go
srvCfg.EnableIntrospectionEndpoint = true
srvCfg.IntrospectionResourceServers = []string{
    "rs-billing-api",   // resource server allowed to introspect tokens
    "rs-files-api",     // …issued to any DCR client targeting this RS
}
```

Empty entries are rejected at `Config.Validate`. Unregistered client IDs are rejected at `Server.New`. Same-client probes are always allowed and do not require enrolment.

### Response shape

`client_id` reflects the **token-bound** client, not the requester. `exp`, `iat`, `aud`, `iss`, `scope`, `sub`, `token_type` are projected from token metadata (opaque mode) or the verified JWT claims (JWT mode). `nbf` is projected when the JWT carries it. User attributes (`email`, `email_verified`, `name`) are projected on the authorized path only.

### Auditing

Cross-client denials emit `introspection_requester_denied` (severity `medium`) with `reason ∈ {empty_requester, empty_token_bound_client, cross_client_probe}`. The wire response hides the denial from the caller; the audit record preserves it for SIEM ingestion.

## Client Registration Protection

The `AllowPublicClientRegistration` setting controls two aspects:

1. **DCR Endpoint Authentication**: Whether `/oauth/register` requires a Bearer token
2. **Public Client Creation**: Whether clients with `token_endpoint_auth_method: "none"` can be created

### Secure Production Configuration

```go
config := &server.Config{
    // Require authentication and deny public clients
    AllowPublicClientRegistration: false,

    // Initial access token (generate: openssl rand -base64 32)
    InitialAccessToken: os.Getenv("INITIAL_ACCESS_TOKEN"),

    // Limit per IP
    MaxClientsPerIP: 10,
}
```

With this configuration:
- Only authenticated requests can access `/oauth/register`
- Only confidential clients (with secrets) can be created
- Public clients are denied even with valid authentication

### Trusted Custom URI Schemes (Cursor/IDE Compatibility)

For MCP clients like Cursor that don't support initial access tokens, you can allow unauthenticated registration **only** for clients using trusted custom URI schemes:

```go
config := &server.Config{
    // Require token for most clients
    AllowPublicClientRegistration: false,
    InitialAccessToken:            os.Getenv("INITIAL_ACCESS_TOKEN"),

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

2. **Redirect Validation:** Strict matching limits this registration exemption to the configured schemes. It does not authenticate an application: anyone can submit a matching redirect URI, and another application may claim the same OS scheme. OS routing is not proof that the requester is Cursor.

**Platform Considerations:**

Custom URI scheme protection varies by platform:

| Platform | Protection Level | Notes |
|----------|-----------------|-------|
| macOS/iOS | Moderate | Schemes registered per-app, but no verification of who registered first |
| Windows | Moderate | Any app can register a scheme; first-installer-wins |
| Android | Unverified for private-use schemes | App Links verify claimed HTTPS links, not private-use schemes such as `cursor://` |
| Linux | Weak | Depends on desktop environment configuration |

**Because platform protection varies, PKCE enforcement is critical.** The library always requires PKCE; plain challenges are disabled by default (`AllowPKCEPlain=false`). This protects code redemption, not the identity displayed to the user.

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

#### Why Cursor compatibility still needs the exemption

Retain the `cursor` exemption where existing Desktop clients depend on custom-scheme registration. [Cursor documents localhost and HTTPS callbacks](https://cursor.com/docs/mcp#static-redirect-url), but [Cursor staff also describe a Desktop fallback to `cursor://`](https://forum.cursor.com/t/oauth-redirect-uri-changed-from-cursor-to-http-localhost-for-streamable-http-mcp/165019/6). Inspection of the official Linux x64 Desktop 3.30.14 MCP bundle confirms a custom-scheme path when loopback is disabled by remote configuration or a server denylist, and a registration retry with the selected callback alone. Desktop sign-in was not executed during this check.

This setting exempts matching requests from registration authentication. It does not enable loopback redirects or control the separate custom-scheme redirect policy. With public registration disabled and no other applicable registration allowance, removing `cursor` rejects fresh registrations that use that path. Keeping it does not enable HTTPS or localhost registration under strict matching; do not disable strict matching or enable unrestricted public registration as a workaround.

An explicit CIMD client ID provides an alternative for compatible clients. On 2026-11-20, Linux x64 Cursor CLI `2026.11.19-f005e9d` completed browser authorization and listed 10 MCP tools against an HTTPS mcp-kubernetes 1.15.1 server using this configuration:

```json
{
  "mcpServers": {
    "example": {
      "url": "https://mcp.example.com/mcp",
      "auth": {
        "CLIENT_ID": "https://cursor.com/oauth/mcp-client.json"
      }
    }
  }
}
```

The server must enable `EnableClientIDMetadataDocuments` and permit this exact client ID under its metadata policy, either through a validated fetch of [Cursor's document](https://cursor.com/oauth/mcp-client.json) or pinned `PreRegisteredClientMetadata`. Restricting metadata to other platform clients does not admit Cursor automatically. No client secret is needed for this public client.

URL-only automatic registration failed in the CLI test, even though the server advertised CIMD support. The explicit configuration proves that client can use CIMD; it does not prove automatic CIMD selection or Desktop compatibility. The deployed scheme exemption remained enabled during the successful test, so this was not an end-to-end test with the setting removed. Migrate client configurations and verify fresh Desktop and CLI sign-in before removing an installation's exemption. Retention has no scheduled expiry; the compatibility decision is recorded in [giantswarm/giantswarm#39131](https://github.com/giantswarm/giantswarm/issues/39131).

**Audit Logging:**

Registrations via trusted schemes are logged with event type `client_registered_via_trusted_scheme` for security monitoring.

### Trusted HTTPS Redirect URIs (SaaS MCP Clients)

For well-known SaaS MCP clients (e.g. Claude.ai) whose redirect URI is fixed, operator-known, and HTTPS, you can allowlist specific URIs without enabling `AllowPublicClientRegistration` globally or pre-registering the client out-of-band:

```go
config := &server.Config{
    AllowPublicClientRegistration: false,
    InitialAccessToken:            os.Getenv("INITIAL_ACCESS_TOKEN"),

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

The library provides comprehensive redirect URI validation against open redirects and authorization codes sent to unintended addresses. The server never connects to a redirect URI, so these checks are browser-redirect policy, not SSRF protection. **All security features are enabled by default** following the library's principle of "secure by default, explicit opt-out for less security."

### Secure by Default

The following security controls are **automatically enabled**:

| Setting | Default | Description |
|---------|---------|-------------|
| `ProductionMode` | `true` | HTTPS required for non-loopback URIs; `DisableProductionMode` is deprecated and logs a warning unless `Issuer` is a loopback URL |
| `DNSValidation` | `true` | Resolve hostnames to check IPs |
| `DNSValidationStrict` | `true` | Fail-closed on DNS failures |
| `ValidateRedirectURIAtAuthorization` | `true` | Re-validate at authorization time (TOCTOU protection) |
| `AllowPrivateIPRedirectURIHosts` | empty | Hostnames whose redirect URIs may resolve to RFC 1918 private IPv4 or RFC 4193 IPv6 unique-local IPs; every other host keeps the private-IP check |
| `AllowPrivateIPRedirectURIs` | `false` | Deprecated: lifts the private-IP check for every host |
| `AllowLinkLocalRedirectURIs` | `false` | 169.254.x.x/fe80:: blocked (cloud metadata addresses) |

**Note for Native/CLI App Support:** Loopback redirect URIs (`localhost`, `127.x.x.x`, `::1`) are always accepted over HTTP, as [RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) requires for native applications. A registered loopback redirect URI matches a request on any port; every other component, query included, must match exactly. `AllowLocalhostRedirectURIs` is deprecated and has no effect; `OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS=false` logs a deprecation warning.

### Escape Hatches for Less Strict Validation

If you need to reduce security for specific use cases, configure only the exception you need. The following examples are alternatives.

For known callbacks on private hostnames, list those hostnames. This allows RFC 1918 private IPv4 and RFC 4193 IPv6 unique-local addresses for listed hosts only. Literal private IP redirect URIs and link-local addresses remain blocked.

```go
config := &server.Config{
    AllowPrivateIPRedirectURIHosts: []string{"gateway.internal.example.com"},
}
```

The deprecated `AllowPrivateIPRedirectURIs: true` lifts the check for every host and overrides the hostname list. Setting it logs a deprecation warning.

For deployments that require link-local callbacks, enable that exception separately:

```go
config := &server.Config{
    // WARNING: codes may be redirected to cloud metadata addresses (169.254.169.254)
    AllowLinkLocalRedirectURIs: true,
}
```

### Disabling Security Features (Development Only)

To completely disable security features (e.g., for local development), use the explicit `Disable*` fields:

```go
config := &server.Config{
    // Accept http:// redirect URIs on any host at registration (authorization
    // still refuses them with an https:// Issuer); deprecated, warns unless
    // Issuer is a loopback URL such as http://localhost:8080
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

### Development-only overrides

The following flags exist for non-production scenarios. Each emits a startup `WARN` log entry when set.

| Field | Risk | Dev use case |
|---|---|---|
| `AllowInsecureHTTP` | Bearer tokens transmitted in clear — full credential exposure | Non-loopback HTTP test environments. RFC 8252 §7.3 loopback HTTP (`http://localhost`) is always permitted without this flag. |
| `AllowPrivateIPClientMetadataHosts` | Deprecated, deviates from CIMD draft-03 §10.7: the listed hostnames' CIMD metadata URLs may resolve to RFC 1918 / RFC 4193 IPs; every other host keeps the guard | Replace with pre-registration in `PreRegisteredClientMetadata` (§9.2), which fetches nothing |
| `AllowPrivateIPJWKSHosts` | SSRF limited to the listed hostnames: their JWKS endpoints may resolve to RFC 1918 / RFC 4193 IPs; every other host keeps the guard | A private IdP whose `jwks_uri` is on another host than its issuer (the issuer host needs no entry) |
| `AllowPrivateIPClientMetadata` | Deprecated: SSRF into cluster for every CIMD host (CWE-918) | Replace with pre-registration in `PreRegisteredClientMetadata` |
| `AllowPrivateIPJWKS` | Deprecated: SSRF into cluster for every JWKS host (CWE-918) | Replace with `AllowPrivateIPJWKSHosts` |

Every private-IP allowance follows one pattern, `AllowPrivateIP<Operation>Hosts`: a hostname list (no port, no wildcard; a redirect URI with a literal IP never reads the list), with the connection-time guard kept for every host that is not listed. Entries match case-insensitively and ignore one trailing dot; redirect URIs and client IDs are still compared byte for byte against what was registered ([RFC 9700 §4.1.3](https://datatracker.ietf.org/doc/html/rfc9700#section-4.1.3)).

Every list lifts RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and RFC 4193 (`fc00::/7`) on top of the guard the operation applies to an unlisted host, and nothing else: a listed host is never refused an address an unlisted host may reach. Loopback, link-local (cloud metadata) and unspecified addresses stay refused for a listed host on the CIMD and JWKS fetches; the CIMD guard also refuses the other IANA special-purpose ranges, listed or not. The redirect list is browser-redirect policy, not a fetch: link-local keeps its own switch (`AllowLinkLocalRedirectURIs`), and a redirect hostname that resolves to loopback is accepted for every host, listed or not, like a loopback redirect URI. The deprecated blanket switches still work, keep their wider behaviour, and log a deprecation warning naming their host list.

```go
// Development / private-network only, never set in internet-facing production
config := &server.Config{
    AllowInsecureHTTP:                 true,                         // http:// issuer/redirect outside loopback
    AllowPrivateIPClientMetadataHosts: []string{"gateway.internal"}, // CIMD on a private hostname
    AllowPrivateIPJWKSHosts:           []string{"dex.internal"},     // forwarded-token JWKS on a private IdP
}
```

**WARNING:** These flags bypass production security invariants and must not appear in internet-facing deployments.

### Native App Support (RFC 8252)

Native/CLI apps need no setting: loopback redirects (`http://localhost`, `http://127.0.0.1`, `http://[::1]`) are always allowed, and only the port may differ from the registered URI.

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

`TrustedAudiences` lists the client IDs whose upstream ID tokens this server accepts as forwarded identities: through `Server.AcceptForwardedIDToken`, and as a bearer in `Server.ValidateToken` unless `Config.RequireResourceAccessTokens` is set.

ID-token bearer acceptance is deprecated and remains available during the migration to resource access tokens. At startup, `DEPRECATED:` warnings name `TrustedAudiences` when `RequireResourceAccessTokens` is false, `TrustedIssuer.OpenIDProvider` when enabled, and `TrustedIssuer.AcceptedTypHeaders` when it includes the empty string (a missing `typ`). Configuration supplied through functional options is included. The warnings do not change token acceptance. Before adopting mcp-oauth 2.0.0, migrate callers to access tokens issued for each resource, set `RequireResourceAccessTokens`, remove `TrustedAudiences` and `OpenIDProvider`, and restrict accepted bearer types to `at+jwt`. Do not enable enforcement while callers still forward ID tokens.

### Use Case: MCP Aggregator Architecture

In architectures with an MCP aggregator (like muster) that proxies requests to downstream MCP servers:

1. Users authenticate to the aggregator once
2. The aggregator forwards the user's ID token, whose audience is the aggregator's client ID
3. Each downstream server lists that client ID in `TrustedAudiences`

A forwarded ID token is accepted by every downstream that trusts the aggregator's audience, so one leaked token reaches all of them. The standard alternative is RFC 8693 token exchange (see [token exchange](./token-exchange.md)): the aggregator obtains an access token per downstream resource, and each downstream sets `Config.RequireResourceAccessTokens` to refuse forwarded ID tokens. `oauth.forwarded_id_token.accepted_total` and `forwarded_id_token_accepted` audit events show which servers still receive forwarded tokens.

### Token Validation Flow

`Server.ValidateToken` accepts resource access tokens through these paths:

1. **Self-issued JWT**: Verify signature, access-token type, issuer, expiry, resource audience, revocation, and token family.
2. **Forwarded ID token** (skipped under `RequireResourceAccessTokens`): the audience must match `TrustedAudiences`; signature, issuer and expiry are verified against the provider's JWKS, and any failure is a rejection (audit `forwarded_id_token_invalid`; a WARN log line carries the cause). A JWKS outage is a retryable 503. A token carrying `act` (delegation) or `cnf` (sender-constrained) is not taken here: it continues to step 3, where the trusted issuer's actor policy applies and the handler middleware enforces the DPoP binding. This step runs first so that an ID token issued to a trusted client is the caller's identity (`TokenSourceSSO`) even when its issuer is also a trusted issuer.
3. **Trusted-issuer JWT**: Verify the configured issuer's signature, claims, and `AcceptedTypHeaders`. The audience must match the entry's `AllowedAudiences` (this server's resource identifier when empty). Under `RequireResourceAccessTokens` it must also include this server's resource identifier.
4. **Stored access token**: Require a local provider-token mapping and metadata with `TokenType: "access"`. Check local expiry and the resource audience before refreshing or validating the mapped provider credential through userinfo.

Unknown opaque bearers are refused (audit `unknown_bearer`). Unknown compact JWTs, including unsecured JWTs with empty signatures, return `server.ErrUnknownJWTBearer` (audit `unknown_jwt_bearer`; a WARN log line names the token's unverified `iss` and `aud`, truncated, next to `TrustedAudiences` unless `RequireResourceAccessTokens` is set, so an ID token issued to a client missing from `TrustedAudiences` can be identified). The 401 response stays generic. Refresh tokens cannot serve as resource bearers, and an upstream ID token only through step 2. Stored ID-token metadata cannot authorize a request or bind it to a token pair's DPoP key.

When a client omits the `resource` parameter, access and refresh metadata default to `Config.GetResourceIdentifier()`. Custom stores must implement both `storage.TokenMetadataStore` and `storage.TokenMetadataGetter` for stored bearer validation. Missing metadata or audience, a token type other than `access`, and an empty mapped provider access token are rejections. A transient store failure remains a retryable 503. Use the `access_token` returned by the local OAuth token endpoint; provider userinfo success alone does not establish that an upstream token was issued for this resource.

The constructor requires both metadata interfaces. Legacy stores without `UserProviderTokenStore` also need `ProviderRefreshLockStore` so concurrent servers coordinate provider refresh before consuming the grant. Authorization-code and refresh grants persist required token mappings, metadata, and refresh-family records before consuming their grants. A failed required write returns a storage error, discards staged credentials, and leaves the grant available for retry. ID-token metadata is optional bookkeeping and does not gate grant success.

### Configuration

```go
config := &server.Config{
    Issuer:             "https://auth.example.com",
    ResourceIdentifier: "https://mcp-kubernetes.example.com",

    // Clients whose forwarded ID tokens are accepted.
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

Providers without JWKS support validate local access tokens through their stored provider credentials and userinfo. They refuse unknown bearers in every format.

### Security Model

| Aspect | Behavior |
|--------|----------|
| **JWKS Validation** | JWTs are validated via cryptographic signature verification |
| **Explicit Trust** | Each trusted audience must be explicitly configured |
| **Same Issuer** | Tokens are only accepted if from the configured IdP |
| **Resource Requests** | Forwarded ID tokens are accepted for `TrustedAudiences` unless `RequireResourceAccessTokens` is set, which requires access tokens naming this server's `ResourceIdentifier` |
| **No Delegation or Binding** | A token carrying `act` or `cnf` is never accepted as a forwarded ID token |
| **Audit Logging** | `EventForwardedIDTokenAccepted` records each accepted forwarded ID token |
| **SSRF Protection** | JWKS URIs are validated to block private IPs, loopback, and link-local addresses |
| **DNS Rebinding Protection** | Resolved IPs are validated at connection time to prevent DNS rebinding attacks |
| **Memory Limits** | Response body limited to 1MB, max 100 keys per JWKS |
| **Algorithm Restriction** | Only RSA and ECDSA signing methods accepted (prevents algorithm confusion attacks like CVE-2015-9235) |
| **URL Normalization** | Case-insensitive host comparison, default port removal (443/80) |
| **Constant-Time** | Audience comparison uses constant-time comparison |

### Security Recommendations

1. **Minimize Trust**: Only add audiences you explicitly trust
2. **Same IdP**: All trusted audiences should use the same Identity Provider
3. **Monitor Logs**: Watch for `forwarded_id_token_accepted` events and resource authentication failures
4. **Move to Token Exchange**: Once callers obtain per-resource access tokens, set `RequireResourceAccessTokens`
5. **Validate Scopes**: Use `EndpointScopeRequirements` for fine-grained access control
6. **JWKS Caching**: The default 1-hour cache TTL balances performance with key rotation freshness

### Direct Acceptance: `Server.AcceptForwardedIDToken`

`Server.AcceptForwardedIDToken` verifies a forwarded ID token directly, without the other `ValidateToken` paths, whatever `RequireResourceAccessTokens` says. An upstream ID token can be shared across sessions and does not inherit their audience, scopes, or DPoP binding from stored metadata.

Use it when an intermediary needs verified claims from a trusted IdP and wants a hard failure rather than another validation path. See [silent-authentication.md](./silent-authentication.md) for the usage guide.

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

#### `Config.ForwardedSessionIdentity`: bearer or principal

The session identifier above applies to every validated bearer without a refresh-token family: forwarded ID tokens, trusted-issuer tokens and self-issued exchange JWTs, whether they arrive through `AcceptForwardedIDToken`, `AcceptTrustedIssuerToken` or the resource-server middleware (`Server.SessionIDForBearer`). `Config.ForwardedSessionIdentity` selects its input:

| Value | Input | A refreshed token | Choose it when |
|---|---|---|---|
| `bearer` (default, also `""`) | the token bytes | is a new session | sessions should end with the token, or servers correlate one token across hops |
| `principal` | `iss`, `sub`, `azp` (or the sorted `aud` set when `azp` is absent) and the `act` chain | keeps its session | a resource server keeps per-session state (backend connections, capability caches) for an agent acting on behalf of a person, whose token its gateway refreshes |

Both derivations are domain-separated with their own label and keyed with `SessionIDHMACKey` when it is set, so a principal-derived identifier never equals a bearer-derived one. A bearer that names no principal (not a JWT, or no `iss`/`sub`) keeps the bearer derivation. Refresh-token-family sessions (interactive login and refresh) are unaffected.

The trade-off of `principal`:

- **The session id is not a credential.** It correlates state across bearers; every request's bearer is validated as before, and a bearer that fails validation (expired, revoked upstream, wrong audience) gets no session, whatever the derivation.
- **State outlives a single bearer.** Connections a resource server made with a previous bearer's exchanged tokens keep working until those tokens expire and are re-exchanged from the current bearer. That is the same trust as within one bearer's lifetime under `bearer`.
- **A person's sessions become linkable over time.** Under `bearer`, two tokens of the same principal are two identifiers; under `principal` they are one, for as long as the principal is unchanged. A different person, client or actor chain is always a different session.
- **Token exchange keys stay bearer-derived.** `SelfIssuedExchange` and `BrokeredExchange` compute their rate-limit and audit session id from the subject token before validating it, so its claims are not yet trusted there.

#### Expiry behavior

`AcceptForwardedIDToken` does not refresh forwarded tokens — the library holds no refresh credential for them. When the JWT `exp` has passed, validation fails and the caller must propagate 401 so the MCP client re-authenticates against the upstream IdP. Callers should use `acceptance.ExpiresAt` to set any session-cache TTLs rather than re-parsing the JWT.

### Private IdP Deployments

If your Identity Provider (e.g., Dex) runs on a private network, nothing needs to be set when its `jwks_uri` is on the issuer's host: the server already reaches that host for discovery and token calls, so the JWKS fetch for forwarded SSO ID tokens may resolve there privately too. A `jwks_uri` on any other host keeps the guard; list that host in `AllowPrivateIPJWKSHosts`. The host the discovery document names is never trusted on its own.

```go
config := &server.Config{
    TrustedAudiences:        []string{"muster-client"},
    AllowPrivateIPJWKSHosts: []string{"keys.internal.example.com"}, // only when jwks_uri is not on the issuer host
}
```

| Setting | Default | Behavior |
|---------|---------|----------|
| (provider issuer host) | always | May resolve to RFC 1918 / RFC 4193 IPs for the JWKS fetch |
| `AllowPrivateIPJWKSHosts` | empty | Listed hosts may resolve to RFC 1918 / RFC 4193 IPs; every other host is guarded |
| `AllowPrivateIPJWKS` | `false` | Deprecated: lifts the guard for every JWKS host |

Trusted issuers have the same field, `TrustedIssuer.AllowPrivateIPJWKSHosts`. They get no issuer-host allowance: list the host.

**For the issuer host and a listed host, allows:**
- Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
- IPv6 unique-local addresses: fc00::/7 (RFC 4193)

Loopback, link-local and unspecified addresses stay refused.

**Security notes:**
- HTTPS is still required for a listed host
- This only affects JWKS fetching for SSO token validation (TrustedAudiences)
- A warning naming the hosts is logged at startup
- For Google OAuth, this setting has no effect as Google's JWKS endpoint is always publicly accessible

#### Internal CA trust

`AllowPrivateIPJWKSHosts` controls which IP addresses a fetch may reach. It does not
control which CA signs the certificate. Those are independent settings: an IdP on
a public address can still present a certificate from an internal CA.

Pass the CA pool through the `RootCAs` field that fits the fetch. Each one
applies whether or not the private-IP flags are set:

| Field | Verifies |
|---|---|
| `server.Config.JWKSRootCAs` | forwarded SSO ID tokens (`TrustedAudiences`) |
| `server.TrustedIssuer.RootCAs` | that issuer's JWKS endpoint |
| `dex.Config.RootCAs` | Dex OIDC discovery and token endpoint |
| `oidc.JWKSClientOptions.RootCAs` | a JWKS client you build yourself |
| `oidc.TokenExchangeClientOptions.RootCAs` | an RFC 8693 token endpoint |

```go
pool, err := x509.SystemCertPool()
if err != nil {
    return err
}
if !pool.AppendCertsFromPEM(caPEM) {
    return errors.New("no certificate found in the CA bundle")
}

config := &server.Config{
    Issuer:           "https://dex.example.com",
    TrustedAudiences: []string{"muster-client"},
    JWKSRootCAs:      pool, // no AllowPrivateIPJWKSHosts needed
}
```

A pool replaces the system roots rather than extending them. Start from
`x509.SystemCertPool()` and append, as above, unless you intend to trust the
internal CA alone.

#### Egress proxies

Calls to an endpoint the operator configures (Dex discovery and token
endpoint, a JWKS or token exchange client with `AllowPrivateIP`) honor
`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`. These clients have no dial guard,
so a proxy bypasses nothing. When a proxy is set, list an internal IdP that
the proxy cannot reach in `NO_PROXY`; a host in `NO_PROXY` is dialed directly.

The SSRF-safe clients (CIMD metadata, the default JWKS and token exchange
clients, and the host-scoped private-IP clients) check the resolved addresses
first. When `HTTPS_PROXY` and `NO_PROXY` name a proxy for the host, they open a
`CONNECT` tunnel to each checked IP in turn, never to the hostname; otherwise
they dial those IPs directly. A proxy that only admits domain names refuses a
`CONNECT` to an IP, so list such hosts in `NO_PROXY` when direct egress exists.
See the Egress Proxies section of `SECURITY_ARCHITECTURE.md`.

`dex.Config.AllowPrivateIP` is deprecated and has no effect; the Dex
client reaches private addresses without it.

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

When a forwarded ID token is validated via JWKS, `EventForwardedIDTokenAccepted` is logged. `session_id` is the `ext-<hex>` value `AcceptForwardedIDToken` returns; `request_id` is the one `security.RequestIDMiddleware` put on the request context (empty without it):

```json
{
  "event_type": "forwarded_id_token_accepted",
  "user_id_hash": "a1b2c3d4...",
  "request_id": "Qm9vdHN0cmFwUmVxdWVzdA",
  "details": {
    "matched_audience": "muster-client",
    "email": "user@example.com",
    "validation_method": "jwks",
    "sso_token_forwarded": true,
    "session_id": "ext-0123456789abcdef"
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

### Basic credentials that are not form-encoded

RFC 6749 §2.3.1 has a client form-encode its client ID and secret before Basic encoding them, so `/token`, `/revoke` and `/introspect` form-decode both. A client that sends its secret unencoded still authenticates: when the decoded secret is refused, the secret as sent is checked, and a match logs `Client authenticated with Basic credentials that are not form-encoded` with the `client_id` (never the secret). That log names the clients to fix.

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
