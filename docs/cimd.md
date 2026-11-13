# Client ID Metadata Documents (CIMD)

Client ID Metadata Documents (CIMD) let clients use HTTPS URLs as client identifiers with dynamic metadata discovery. MCP 2026-07-28 recommends CIMD and retains Dynamic Client Registration for compatibility. See the [authorization audit](./mcp-2026-07-28.md) for outstanding conformance gaps.

## Contents

1. [What are Client ID Metadata Documents?](#what-are-client-id-metadata-documents)
2. [When to Use CIMD](#when-to-use-cimd)
3. [Configuration](#configuration)
4. [Client Metadata Document Format](#client-metadata-document-format)
5. [How It Works](#how-it-works)
6. [Security](#security)
7. [Caching](#caching)
8. [Troubleshooting](#troubleshooting)

## What are Client ID Metadata Documents?

Client ID Metadata Documents allow OAuth clients to use HTTPS URLs as their client identifiers. Instead of pre-registering clients with the authorization server, the server can dynamically discover client metadata by fetching a JSON document from the URL.

This addresses a common MCP scenario: **servers and clients often have no pre-existing relationship**. With CIMD, clients can self-describe their metadata, and authorization servers can verify client identity by fetching and validating the metadata document.

### Traditional vs. CIMD Flow

**Traditional OAuth (pre-registration required):**
1. Client developer registers with authorization server
2. Server issues a `client_id` (opaque string like `abc123`)
3. Client uses this `client_id` in authorization requests

**CIMD Flow (no pre-registration):**
1. Client hosts a metadata document at an HTTPS URL
2. Client uses the URL as its `client_id` (e.g., `https://example.com/oauth/client.json`)
3. Authorization server fetches and validates the metadata dynamically

## When to Use CIMD

CIMD is ideal for:

- **Distributed MCP ecosystems** where clients and servers don't have prior relationships
- **Third-party client applications** that need to connect to multiple MCP servers
- **CLI tools and native applications** that can host metadata documents
- **Reducing operational overhead** of manual client registration

CIMD may not be appropriate for:

- **High-security environments** requiring vetted client registration
- **Clients that cannot host HTTPS content** (embedded systems, offline apps)
- **Scenarios requiring client secrets** (this library supports public CIMD clients with `token_endpoint_auth_method: "none"`)

## Configuration

### Enabling CIMD

```go
import (
    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/storage/memory"
)

server, err := oauth.NewServer(
    provider,
    store, store, store, // TokenStore, ClientStore, FlowStore
    &oauth.ServerConfig{
        Issuer: "https://your-server.com",

        // Enable Client ID Metadata Documents
        EnableClientIDMetadataDocuments: true,

        // Optional: Configure metadata fetch timeout (default: 10s)
        ClientMetadataFetchTimeout: 10 * time.Second,

        // Optional: Configure cache TTL (default: 5 minutes)
        ClientMetadataCacheTTL: 5 * time.Minute,
    },
    logger,
)
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `EnableClientIDMetadataDocuments` | `bool` | `false` | Enable URL-based client_id support |
| `ClientMetadataFetchTimeout` | `time.Duration` | `10s` | Timeout for fetching metadata from URLs |
| `ClientMetadataCacheTTL` | `time.Duration` | `5m` | How long to cache fetched metadata |

### Authorization Server Metadata

When CIMD is enabled, the authorization server metadata (`/.well-known/oauth-authorization-server`) will include:

```json
{
  "issuer": "https://your-server.com",
  "authorization_endpoint": "https://your-server.com/oauth/authorize",
  "token_endpoint": "https://your-server.com/oauth/token",
  "client_id_metadata_document_supported": true,
  ...
}
```

Clients can use this field to determine if the server supports URL-based client IDs.

## Client Metadata Document Format

The metadata document is a JSON file hosted at the client's URL. The `client_id` field **MUST** exactly match the URL from which the document is fetched.

### Required Fields

```json
{
  "client_id": "https://example.com/oauth/client.json",
  "redirect_uris": [
    "http://localhost:8080/callback",
    "http://127.0.0.1:8080/callback"
  ]
}
```

### Full Example

```json
{
  "client_id": "https://example.com/oauth/client.json",
  "client_name": "Example MCP Client",
  "client_uri": "https://example.com",
  "logo_uri": "https://example.com/logo.png",
  "redirect_uris": [
    "http://localhost:8080/callback",
    "http://127.0.0.1:8080/callback",
    "https://example.com/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile email",
  "contacts": ["support@example.com"]
}
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | Yes | MUST exactly match the HTTPS document URL, including escaped path components; a path is required and dot segments are prohibited |
| `redirect_uris` | Yes | Array of allowed redirect URIs |
| `client_name` | Yes | Non-empty human-readable client name (displayed on consent screen) |
| `client_uri` | No | URL of the client's homepage |
| `logo_uri` | No | URL to the client's logo |
| `grant_types` | No | Defaults to `["authorization_code"]` |
| `response_types` | No | Defaults to `["code"]` |
| `token_endpoint_auth_method` | No | Defaults to `"none"` (public client); other methods are not supported |
| `scope` | No | Space-delimited scopes the client may request |
| `contacts` | No | Contact email addresses |

Documents containing `client_secret` or `client_secret_expires_at` are rejected, including when their values are `null`. A public metadata document cannot establish a shared secret. Asymmetric client authentication is optional in the CIMD specification and is not implemented by this library.

### Redirect URI Rules

Redirect URIs follow OAuth 2.1 security requirements:

- **HTTPS required** for non-localhost URIs
- **HTTP allowed only for localhost** (`localhost`, `127.0.0.1`, `::1`)
- **Custom schemes are rejected for CIMD callbacks**; HTTPS and HTTP loopback callbacks are supported. The separate DCR/native OAuth custom-scheme support does not change these CIMD rules.

## How It Works

### Authorization Flow with CIMD

```
┌──────────┐                         ┌────────────────────┐
│  Client  │                         │ Authorization      │
│ (with    │                         │ Server             │
│ metadata)│                         │                    │
└────┬─────┘                         └─────────┬──────────┘
     │                                         │
     │ 1. Authorization Request                │
     │    client_id=https://example.com/client.json
     │─────────────────────────────────────────>
     │                                         │
     │                    2. Fetch metadata    │
     │         <───────────────────────────────│
     │                                         │
     │  3. Return client.json                  │
     │─────────────────────────────────────────>
     │                                         │
     │                    4. Validate:         │
     │                    - client_id matches URL
     │                    - redirect_uri in list
     │                    - PKCE required      │
     │                                         │
     │ 5. Continue OAuth flow                  │
     │<────────────────────────────────────────│
     │                                         │
```

### Step-by-Step Flow

1. **Client initiates authorization** with `client_id` set to their metadata document URL:
   ```
   GET /oauth/authorize?
     client_id=https://example.com/oauth/client.json&
     redirect_uri=http://localhost:8080/callback&
     response_type=code&
     code_challenge=abc...&
     code_challenge_method=S256&
     state=xyz
   ```

2. **Server checks if client_id is a URL** (HTTPS scheme, valid hostname)

3. **Server fetches metadata** from the URL with SSRF protection

4. **Server validates metadata:**
   - `client_id` in document matches the fetch URL exactly
   - `redirect_uri` parameter matches one in `redirect_uris` array
   - Required fields are present

5. **Server caches metadata** for future requests (respecting TTL and Cache-Control)

6. **Server asks the person for consent** unless the client is in `TrustedClients` for this redirect URI (see [Consent](#consent))

7. **OAuth flow continues** with the upstream identity provider

## Security

CIMD includes comprehensive security measures to prevent abuse.

### SSRF Protection

The server implements multiple layers of SSRF (Server-Side Request Forgery) protection:

1. **HTTPS Only**: Only HTTPS URLs are accepted as client IDs
2. **DNS Validation at Connection Time**: IP addresses are validated when connecting, preventing DNS rebinding attacks
3. **Only globally reachable addresses** ([`code.dny.dev/ssrf`](https://pkg.go.dev/code.dny.dev/ssrf)):
   - Every IANA special-purpose IPv4 range: loopback, private, link-local (cloud metadata), shared address space (`100.64.0.0/10`), benchmarking, documentation, multicast and reserved
   - IPv6 only inside `2000::/3`, without the special-purpose ranges in it (6to4, Teredo, documentation)
   - An IPv4 address in IPv6 form is checked as IPv4
   - `AllowPrivateIPClientMetadata` (every host) and `AllowPrivateIPClientMetadataHosts` (listed hostnames) lift the guard

4. **No Redirects**: HTTP redirects are not followed

### Consent

A Client ID Metadata Document only proves that its URL serves it: anyone can publish one that lists their own redirect URI. Before the upstream identity provider, `/oauth/authorize` therefore shows a consent page for every client that is not trusted, the same page dynamically registered clients get. It shows:

- the host of the `client_id` URL, and the `client_name` the document declares, labelled as the client's own claim;
- where the sign-in will be sent: the redirect URI, its host in large type;
- the effective upstream permissions, the MCP scopes and the resource;
- a warning when every redirect URI is a loopback address, since any program on the computer can then claim to be the client.

The person answers with a same-origin POST. A short-lived pending request is encrypted in the flow store and consumed atomically; no upstream authorization state exists before approval. Each browser can have eight pending requests. The form posts to the public authorization endpoint, including an issuer path prefix when present.

The upstream redirect sets a transaction-specific browser cookie. The callback must match that cookie before the provider code is exchanged, and the stored authorization state is consumed once across replicas. A callback from another browser cannot use the approval. Provider error callbacks also require the matching browser and consume the state. Completed callbacks release their browser slot even when the provider refuses the sign-in, code exchange, nonce or userinfo validation.

An approval is remembered for 30 days only after the upstream identity is verified, and only for HTTPS callbacks on non-loopback hosts. It is bound to the upstream issuer and subject, client, exact registered redirect URI, MCP and upstream scope sets, and resource. Loopback and custom-scheme callbacks require fresh consent on every sign-in, even when the port is unchanged or the browser carries a prior approval; `prompt=none` returns `consent_required`. A public client identifier and PKCE do not prove which local application owns the callback. If the upstream account changes, that account must approve before a client code is issued. Changes to upstream permissions require fresh consent; the provider receives the exact permission set displayed on the page.

Consent is enabled by default, with no feature flag. The memory and Valkey stores select a shared, issuer-specific key automatically. If storage encryption is configured, HKDF derives the consent key from that existing key. Otherwise the store keeps a generated key; Valkey replicas use the same persisted value. The existing flow-store configuration is sufficient, so consumers using these stores need only a normal dependency and application upgrade. `ConsentCookieKey` and `OAUTH_CONSENT_COOKIE_KEY` are optional overrides, not rollout prerequisites.

Custom flow stores must implement `storage.ConsentStore` and `storage.AuthorizationStateConsumer` before mounting the browser authorization handler. Unsupported stores fail closed. `Server.CompleteBrowserAuthorization` verifies the browser and upstream identity without issuing a code; a non-nil result means the callback state has been consumed, including on provider failure, and the caller must retire its browser binding. Only a nil error permits `Server.IssueAuthorizationCode` to finish a consented result. `Server.CancelBrowserAuthorization` validates and consumes a provider error callback without exchanging a code. `StartAuthorizationFlow` and `HandleProviderCallback` remain available to integrations that implement their own consent and browser binding.

A denial returns `error=access_denied` to the validated client callback with the original `state` and the issuer. `prompt=none` without approval returns `consent_required` through the same OAuth error response. Invalid clients and unregistered redirect URIs receive a local error without a redirect.

Operators list the clients they know with their exact redirect URIs:

```go
config := &server.Config{
    EnableClientIDMetadataDocuments: true,
    TrustedClients: []server.TrustedClient{{
        ClientID:     "https://claude.ai/oauth/mcp-oauth-client-metadata",
        RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
    }},
}
```

A trusted entry covers only the redirect URIs it lists, so a change to the client's document cannot extend it. Loopback redirect URIs cannot be listed: native apps see the page for every sign-in.

HTTP clients implementing a browser flow must keep one cookie jar through the consent GET, approval POST and provider callback. A test or automation that expects the first GET to redirect immediately must submit the form. Existing bearer-token, refresh-token and token-exchange traffic does not enter this handler and needs no new flag or trust entry.

Custom providers that transform requested scopes implement `providers.AuthorizationScopeResolver`. `AuthorizationURLOptions.ResolvedScopes` carries the approved snapshot into the upstream URL; providers must not widen it after consent.

### Client Identity Validation

**Critical Security Check**: The `client_id` field in the metadata document **MUST** exactly match the URL from which it was fetched.

```
URL: https://example.com/oauth/client.json
       ↓
Document MUST contain: "client_id": "https://example.com/oauth/client.json"
```

This prevents impersonation attacks where an attacker tries to use their own metadata document with a victim's client_id.

### PKCE Requirement

All CIMD clients are treated as public clients and **MUST use PKCE** with the S256 method. This protects against authorization code interception attacks.

### Rate Limiting

The server implements per-domain rate limiting for metadata fetches to prevent abuse:

- Prevents DoS attacks via rapid metadata requests
- Configurable limits per domain

### Negative Caching

Failed metadata fetches are cached to prevent:

- Rapid retry attacks
- Resource exhaustion from invalid client IDs
- DoS via repeated failures

Failed entries use progressive backoff for cache TTL.

### Audit Logging

All CIMD operations are logged for security monitoring:

- `client_metadata_fetched`: Successful metadata fetch
- `client_metadata_fetch_failed`: Failed fetch attempt
- `client_metadata_fetch_blocked`: SSRF protection triggered
- `client_metadata_cache_hit`: Served from cache
- `client_metadata_negative_cache_hit`: Blocked due to previous failure
- `client_metadata_rate_limited`: Rate limit exceeded
- `client_metadata_id_mismatch`: Security violation (client_id mismatch)

## Caching

The server caches fetched metadata to reduce latency and external requests.

### Cache Behavior

| Scenario | Cache TTL |
|----------|-----------|
| Successful fetch (no Cache-Control) | `ClientMetadataCacheTTL` (default: 5 min) |
| Successful fetch (with Cache-Control) | `min(max-age, 1 hour)` |
| Failed fetch | 5 minutes (with progressive backoff) |

### Cache-Control Header

Clients can suggest cache duration using HTTP Cache-Control headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=300

{"client_id": "...", ...}
```

The server caps `max-age` at 1 hour to prevent cache poisoning attacks.

### Cache Eviction

- **LRU eviction** when cache reaches capacity (default: 1000 entries)
- **Expired entries** are cleaned up periodically
- **Negative cache** has separate capacity (default: 500 entries)

## Troubleshooting

### Common Errors

#### "client_id metadata URL must use HTTPS"

The client_id must be an HTTPS URL. HTTP URLs are not allowed for security.

**Solution**: Host your client metadata at an HTTPS URL.

#### "client_id mismatch: document contains X but was fetched from Y"

The `client_id` field in your metadata document doesn't match the URL.

**Solution**: Ensure the `client_id` field exactly matches the URL where the document is hosted:

```json
{
  "client_id": "https://example.com/oauth/client.json",
  ...
}
```

#### "client_id metadata URL resolves to private/internal IP address"

SSRF protection blocked the request because the hostname resolves to a private IP.

**Solution**: Host your metadata document on a publicly accessible server.

#### "metadata fetch returned HTTP 404/500"

The server couldn't fetch your metadata document.

**Solution**:
- Verify the URL is accessible
- Check the server returns `application/json` content type
- Ensure the response is valid JSON

#### "rate limit exceeded for metadata fetches from domain"

Too many requests to your domain in a short period.

**Solution**: Wait for the rate limit window to reset. Consider implementing proper caching on your metadata endpoint.

#### "client metadata previously failed validation (cached)"

A previous fetch attempt failed and is cached.

**Solution**: Wait for the negative cache entry to expire (typically 5 minutes), then fix the underlying issue and retry.

### Debugging Tips

1. **Test your metadata document**:
   ```bash
   curl -H "Accept: application/json" https://example.com/oauth/client.json
   ```

2. **Validate JSON format**:
   ```bash
   curl -s https://example.com/oauth/client.json | jq .
   ```

3. **Check Content-Type header**:
   ```bash
   curl -I https://example.com/oauth/client.json
   # Should include: Content-Type: application/json
   ```

4. **Enable debug logging** in your server to see detailed CIMD operations.

## See Also

### Library Documentation

- [Getting Started](./getting-started.md) - Setup guide
- [Configuration Guide](./configuration.md) - All configuration options
- [Security Guide](./security.md) - Security features and best practices
- [MCP 2025-11-25](./mcp-2025-11-25.md) - Specification overview

### Examples

- [CIMD Example](../examples/cimd/) - Complete working example

### Standards

- [MCP Specification 2025-11-25](https://spec.modelcontextprotocol.io/specification/2025-11-25/)
- [draft-ietf-oauth-client-id-metadata-document-00](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)

## Offline metadata

For an installation that cannot reach a client's metadata host, supply a
reviewed copy of that public client's document in `Config.StaticClientMetadata`:

```go
config := &server.Config{
    Issuer: "https://auth.example.com",
    EnableClientIDMetadataDocuments: true,
    AllowLocalhostRedirectURIs: true,
    RequirePKCE: true,
    StaticClientMetadata: []server.ClientMetadata{{
        ClientID: "https://client.example.com/cli.json",
        ClientName: "Example CLI",
        RedirectURIs: []string{"http://localhost:3000/callback"},
        GrantTypes: []string{"authorization_code", "refresh_token"},
        TokenEndpointAuthMethod: "none",
        Scope: "openid profile email offline_access",
    }},
}
```

Only an exact client ID match uses the configured document. It needs no DNS or
HTTP access, survives cache expiry, and is snapshotted at startup. Unlisted
clients keep the normal CIMD fetch and SSRF protections. Invalid documents,
duplicate IDs and configuration with CIMD disabled fail startup. Only public
clients (`token_endpoint_auth_method: none`) are supported.

This is an operator trust decision: review each document's identifier,
callbacks and scopes before adding it. Update or remove a document by changing
the configuration and restarting the server; the library never refreshes a
pinned document from the internet. Local metadata does not grant a sign-in,
skip consent, open dynamic registration, or relax redirect matching, PKCE,
resource or scope validation. A native client's loopback callback still requires
`AllowLocalhostRedirectURIs`; RFC 8252 port matching continues to apply.
