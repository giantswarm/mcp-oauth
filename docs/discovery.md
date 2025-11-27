# OAuth Discovery Mechanisms

This document explains how OAuth discovery works in the `mcp-oauth` library, covering all standardized discovery mechanisms defined by OAuth 2.0, RFC 8414, RFC 9728, and MCP 2025-11-25.

## Table of Contents

1. [Overview](#overview)
2. [Protected Resource Metadata (RFC 9728)](#protected-resource-metadata-rfc-9728)
3. [Authorization Server Metadata (RFC 8414)](#authorization-server-metadata-rfc-8414)
4. [WWW-Authenticate Discovery (RFC 6750)](#www-authenticate-discovery-rfc-6750)
5. [Client ID Metadata Documents](#client-id-metadata-documents)
6. [Discovery Flow Examples](#discovery-flow-examples)
7. [Best Practices](#best-practices)

## Overview

Discovery mechanisms allow OAuth clients to automatically find and configure themselves without hardcoded URLs or manual configuration. This is especially important for:

- **MCP Clients**: Automatically discover authorization requirements
- **Multi-Resource Systems**: Clients discover different authorization servers for different resources
- **Dynamic Environments**: Clients adapt to changing server configurations
- **Standardized Integration**: Reduces manual configuration and errors

### Supported Discovery Mechanisms

| Mechanism | Standard | Purpose | Endpoint |
|-----------|----------|---------|----------|
| Protected Resource Metadata | RFC 9728 | Discover authorization server for a resource | `/.well-known/oauth-protected-resource` |
| Authorization Server Metadata | RFC 8414 | Discover OAuth endpoints and capabilities | `/.well-known/oauth-authorization-server` |
| WWW-Authenticate Header | RFC 6750 | On-demand discovery via 401 responses | N/A (HTTP header) |
| Client ID Metadata | MCP 2025-11-25 | Verify client configurations | Client-provided HTTPS URL |

## Protected Resource Metadata (RFC 9728)

### Purpose

Helps clients discover which authorization server protects a resource and what scopes are supported.

### Endpoint

**Standard Path**: `/.well-known/oauth-protected-resource`

**MCP 2025-11-25 Enhancement**: Also available at sub-paths (e.g., `/mcp/.well-known/oauth-protected-resource`)

### Configuration

The library automatically exposes this endpoint when you register routes:

```go
import (
    oauth "github.com/giantswarm/mcp-oauth"
)

func main() {
    handler := oauth.NewHandler(server, nil)
    mux := http.NewServeMux()
    
    // Register Protected Resource Metadata endpoints
    // Creates both root and sub-path discovery
    handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
    
    http.ListenAndServe(":8080", mux)
}
```

This creates two discovery endpoints:
1. `/.well-known/oauth-protected-resource` - Standard RFC 9728
2. `/mcp/.well-known/oauth-protected-resource` - MCP 2025-11-25 sub-path

### Response Format

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": [
    "https://auth.example.com"
  ],
  "scopes_supported": [
    "mcp:access",
    "files:read",
    "files:write",
    "user:profile"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```

### Fields Explained

- **`resource`**: The protected resource server identifier (usually the server's base URL)
- **`authorization_servers`**: Array of authorization server URLs that can issue tokens for this resource
- **`scopes_supported`**: List of all OAuth scopes this resource understands
- **`bearer_methods_supported`**: How bearer tokens should be sent (typically `["header"]`)

### Client Usage

```bash
# 1. Client wants to access https://mcp.example.com/api/files
# 2. Client fetches Protected Resource Metadata
curl https://mcp.example.com/.well-known/oauth-protected-resource

# 3. Response tells client the authorization server
{
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["files:read", "files:write"]
}

# 4. Client proceeds to authorization server metadata
curl https://auth.example.com/.well-known/oauth-authorization-server

# 5. Client starts OAuth flow using discovered endpoints
```

### Sub-Path Discovery (MCP 2025-11-25)

MCP 2025-11-25 requires discovery at sub-paths for better namespace isolation:

```bash
# Standard discovery (RFC 9728)
curl https://mcp.example.com/.well-known/oauth-protected-resource

# Sub-path discovery (MCP 2025-11-25)
curl https://mcp.example.com/mcp/.well-known/oauth-protected-resource

# Both return the same metadata
```

**Why sub-path discovery?**
- Allows different protected resources on same domain to advertise different authorization requirements
- Better aligns with MCP server path structure
- Enables fine-grained discovery for multi-tenant systems

## Authorization Server Metadata (RFC 8414)

### Purpose

Describes the authorization server's capabilities, endpoints, and supported features.

### Endpoint

**Standard Path**: `/.well-known/oauth-authorization-server`

### Response Format

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "registration_endpoint": "https://auth.example.com/oauth/register",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "revocation_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email"
  ]
}
```

### Key Fields

- **`issuer`**: Canonical authorization server identifier
- **`authorization_endpoint`**: Where clients start OAuth flow
- **`token_endpoint`**: Where clients exchange codes for tokens
- **`registration_endpoint`**: Dynamic client registration (if enabled)
- **`code_challenge_methods_supported`**: PKCE methods (`["S256"]` for secure-by-default)
- **`grant_types_supported`**: Supported OAuth flows

### Client Usage

```go
// Pseudocode: Client autodiscovery
func discoverAuthServer(issuer string) (*Config, error) {
    // Fetch metadata
    resp := GET(issuer + "/.well-known/oauth-authorization-server")
    metadata := parseJSON(resp)
    
    // Configure OAuth client
    return &Config{
        AuthURL:      metadata.authorization_endpoint,
        TokenURL:     metadata.token_endpoint,
        Scopes:       metadata.scopes_supported,
        PKCEMethod:   "S256", // From code_challenge_methods_supported
    }
}
```

## WWW-Authenticate Discovery (RFC 6750)

### Purpose

Provides on-demand discovery when clients attempt to access protected resources without valid credentials.

### How It Works

When a client makes an unauthorized request, the server returns a 401 response with a `WWW-Authenticate` header:

```http
GET /mcp HTTP/1.1
Host: mcp.example.com

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         scope="mcp:access files:read",
                         error="invalid_token",
                         error_description="Token has expired"
```

### Configuration

```go
&server.Config{
    Issuer: "https://auth.example.com",
    
    // Configure scopes to advertise in WWW-Authenticate challenges
    DefaultChallengeScopes: []string{"mcp:access", "files:read"},
    
    // Enhanced WWW-Authenticate headers enabled by default
    // DisableWWWAuthenticateMetadata: false,
}
```

### WWW-Authenticate Parameters

| Parameter | Purpose | Required |
|-----------|---------|----------|
| `resource_metadata` | URL to Protected Resource Metadata | Yes (MCP 2025-11-25) |
| `scope` | Scopes needed to access resource | Recommended |
| `error` | OAuth error code | Optional |
| `error_description` | Human-readable error | Optional |

### Client Discovery Flow

```
1. Client → GET /mcp
2. Server → 401 + WWW-Authenticate: resource_metadata="..."
3. Client → GET /.well-known/oauth-protected-resource
4. Server → JSON with authorization_servers
5. Client → GET /.well-known/oauth-authorization-server
6. Client → Starts OAuth flow with discovered endpoints
```

### Endpoint-Specific Scopes

The library can include endpoint-specific scopes in WWW-Authenticate headers:

```go
&server.Config{
    EndpointScopeRequirements: map[string][]string{
        "/api/files/*":  {"files:read", "files:write"},
        "/api/admin/*":  {"admin:access"},
    },
}
```

When accessing `/api/files/document.txt`:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="...",
                         scope="files:read files:write"
```

This tells the client exactly which scopes are needed for this specific endpoint.

## Client ID Metadata Documents

### Purpose

Allows clients to publish their configuration at a well-known URL, enabling distributed verification and trust establishment.

### Format

Client ID is an HTTPS URL pointing to a metadata document:

```
client_id: https://client.example.com/.well-known/client-configuration
```

### Metadata Document

```json
{
  "client_id": "https://client.example.com/.well-known/client-configuration",
  "client_name": "Example MCP Client",
  "client_uri": "https://client.example.com",
  "redirect_uris": [
    "https://client.example.com/callback"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "token_endpoint_auth_method": "none",
  "logo_uri": "https://client.example.com/logo.png",
  "policy_uri": "https://client.example.com/privacy",
  "tos_uri": "https://client.example.com/terms"
}
```

### Server Configuration

```go
&server.Config{
    // Enable Client ID Metadata Document support
    EnableClientIDMetadata: true,
    
    // Configure caching
    ClientIDMetadataCacheTTL: 3600, // 1 hour
    
    // Configure timeout for fetching metadata
    ClientIDMetadataFetchTimeout: 5, // 5 seconds
}
```

### Security

The library implements SSRF protection:
- Only HTTPS URLs allowed
- Configurable timeout
- Response size limits
- Request validation

See [Security Considerations](./mcp-2025-11-25.md#client-id-metadata-documents-security) for details.

## Discovery Flow Examples

### Example 1: Basic MCP Client Discovery

```bash
# Client wants to access MCP server at https://mcp.example.com

# Step 1: Try to access protected resource
curl -i https://mcp.example.com/mcp

# Step 2: Receive 401 with discovery hint
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"

# Step 3: Fetch Protected Resource Metadata
curl https://mcp.example.com/.well-known/oauth-protected-resource

# Response:
{
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["mcp:access"]
}

# Step 4: Fetch Authorization Server Metadata
curl https://auth.example.com/.well-known/oauth-authorization-server

# Response:
{
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  ...
}

# Step 5: Start OAuth flow with discovered endpoints
# Client redirects user to authorization_endpoint
```

### Example 2: Scope Discovery

```bash
# Client doesn't know which scopes to request

# Step 1: Access resource without token
curl -i https://mcp.example.com/api/files/doc.txt

# Step 2: Check WWW-Authenticate for scope guidance
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="...",
                         scope="files:read files:write"

# Step 3: Client requests those specific scopes
# OAuth flow with scope=files:read files:write
```

### Example 3: Insufficient Scope Recovery

```bash
# Client has basic token but needs elevated access

# Step 1: Try to access admin endpoint
curl -i -H "Authorization: Bearer <basic-token>" \
    https://mcp.example.com/api/admin/users

# Step 2: Receive 403 with required scopes
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer scope="admin:access",
                         error="insufficient_scope"

# Response body:
{
  "error": "insufficient_scope",
  "error_description": "Token lacks required scopes: admin:access",
  "scope": "admin:access"
}

# Step 3: Client initiates step-up authorization
# New OAuth flow requesting additional "admin:access" scope

# Step 4: Retry with new token
curl -i -H "Authorization: Bearer <elevated-token>" \
    https://mcp.example.com/api/admin/users

# Success!
HTTP/1.1 200 OK
```

## Best Practices

### For Server Operators

1. **Always Enable Discovery**
   ```go
   // Register discovery routes for all protected resources
   handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
   ```

2. **Configure Meaningful Scopes**
   ```go
   &server.Config{
       SupportedScopes: []string{
           "mcp:access",      // General MCP access
           "files:read",      // Specific capabilities
           "files:write",
           "admin:access",
       },
       DefaultChallengeScopes: []string{"mcp:access"}, // Start with basics
   }
   ```

3. **Use Endpoint-Specific Scopes Sparingly**
   ```go
   // Good: Broad categories
   EndpointScopeRequirements: map[string][]string{
       "/api/files/*": {"files:access"},
       "/api/admin/*": {"admin:access"},
   }
   
   // Avoid: Too granular
   EndpointScopeRequirements: map[string][]string{
       "/api/files/read":   {"files:read:doc:type:pdf"},
       "/api/files/write":  {"files:write:doc:type:pdf:metadata:title"},
   }
   ```

4. **Monitor Discovery Endpoints**
   - Track access patterns to `/.well-known/*` endpoints
   - Alert on unusual spike in 401 responses (possible reconnaissance)
   - Log first discovery per client for analytics

### For Client Developers

1. **Implement Full Discovery Chain**
   ```
   401 → WWW-Authenticate → Protected Resource Metadata → Authorization Server Metadata → OAuth Flow
   ```

2. **Cache Metadata Appropriately**
   - Cache Protected Resource Metadata (rarely changes)
   - Cache Authorization Server Metadata (relatively stable)
   - Respect cache headers from server
   - Implement fallback for cache misses

3. **Handle Scope Selection Per MCP 2025-11-25**
   - First priority: `scope` from WWW-Authenticate header
   - Second priority: `scopes_supported` from Protected Resource Metadata
   - Request only needed scopes (don't over-request)

4. **Implement Graceful Degradation**
   ```go
   // Pseudocode
   func accessResource(url string) error {
       resp := GET(url)
       
       if resp.StatusCode == 401 {
           // Try discovery
           metadata := discoverFromWWWAuthenticate(resp)
           if metadata != nil {
               token := performOAuthFlow(metadata)
               return GET(url, token)
           }
       }
       
       return handleResponse(resp)
   }
   ```

### For Multi-Resource Deployments

1. **Consistent Metadata Across Resources**
   ```go
   // Share configuration across resource servers
   sharedConfig := &server.Config{
       SupportedScopes: commonScopes,
       // ...
   }
   ```

2. **Use Resource Parameter**
   ```go
   // Bind tokens to specific resources
   &server.Config{
       AllowResourceParameter: true,
       AllowedResources: []string{
           "https://files.example.com",
           "https://api.example.com",
       },
   }
   ```

3. **Coordinate Authorization Servers**
   - Single authorization server for multiple resources (simplest)
   - Or: Use federation with consistent metadata

## See Also

- [MCP 2025-11-25 Guide](./mcp-2025-11-25.md)
- [Security Architecture](../SECURITY_ARCHITECTURE.md)
- [RFC 6750 - Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 8414 - Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9728 - Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

