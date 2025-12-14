# Client ID Metadata Documents (CIMD)

This guide explains Client ID Metadata Documents (CIMD), a feature from the MCP 2025-11-25 specification that allows clients to use HTTPS URLs as client identifiers with dynamic metadata discovery.

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
- **Scenarios requiring client secrets** (CIMD clients are always public)

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
| `client_id` | Yes | MUST exactly match the document URL |
| `redirect_uris` | Yes | Array of allowed redirect URIs |
| `client_name` | No | Human-readable client name (displayed on consent screen) |
| `client_uri` | No | URL of the client's homepage |
| `logo_uri` | No | URL to the client's logo |
| `grant_types` | No | Defaults to `["authorization_code"]` |
| `response_types` | No | Defaults to `["code"]` |
| `token_endpoint_auth_method` | No | Defaults to `"none"` (public client) |
| `scope` | No | Space-delimited scopes the client may request |
| `contacts` | No | Contact email addresses |
| `jwks_uri` | No | URL to client's JSON Web Key Set (for confidential clients) |

### Redirect URI Rules

Redirect URIs follow OAuth 2.1 security requirements:

- **HTTPS required** for non-localhost URIs
- **HTTP allowed only for localhost** (`localhost`, `127.0.0.1`, `::1`)
- **Custom schemes allowed** (e.g., `myapp://callback`) for native applications

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

6. **OAuth flow continues** as normal (consent screen shows `client_name`)

## Security

CIMD includes comprehensive security measures to prevent abuse.

### SSRF Protection

The server implements multiple layers of SSRF (Server-Side Request Forgery) protection:

1. **HTTPS Only**: Only HTTPS URLs are accepted as client IDs
2. **DNS Validation at Connection Time**: IP addresses are validated when connecting, preventing DNS rebinding attacks
3. **Blocked IP Ranges**:
   - Loopback addresses (`127.0.0.0/8`, `::1`)
   - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
   - Cloud metadata services (e.g., `169.254.169.254`)

4. **No Redirects**: HTTP redirects are not followed

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

