# MCP 2025-11-25 Example

This example demonstrates all features introduced in the MCP 2025-11-25 specification for OAuth authorization.

## Features Demonstrated

### 1. Protected Resource Metadata Discovery (RFC 9728)
- Automatic metadata exposure at `/.well-known/oauth-protected-resource`
- Lists supported scopes and authorization servers

### 2. Enhanced WWW-Authenticate Headers (RFC 6750)
- Includes `resource_metadata` parameter for discovery
- Includes `scope` parameter with required scopes
- Includes `error` and `error_description` for debugging

### 3. Scope Selection Strategy
- `SupportedScopes` configuration for discovery
- `DefaultChallengeScopes` for 401 responses
- Endpoint-specific scope requirements
- Method-specific scope requirements

### 4. Insufficient Scope Error Handling
- Returns 403 with `insufficient_scope` error
- Includes required scopes in response
- Enables step-up authorization flows

### 5. Endpoint-Specific Scope Requirements
- Different endpoints require different scopes
- Method-aware scope validation (GET vs POST vs DELETE)
- Automatic scope validation in `ValidateToken` middleware

## Prerequisites

- Go 1.24 or later
- Google OAuth credentials

## Setup

1. Create a Google OAuth application:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing
   - Enable Google+ API
   - Create OAuth 2.0 credentials (Web application)
   - Add `http://localhost:8080/oauth/callback` to authorized redirect URIs

2. Set environment variables:
   ```bash
   export GOOGLE_CLIENT_ID="your-client-id"
   export GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

3. Build and run:
   ```bash
   go mod download
   go build
   ./mcp-2025-11-25
   ```

## Testing MCP 2025-11-25 Features

### Test 1: Discovery Endpoints

```bash
# Fetch Protected Resource Metadata
curl http://localhost:8080/.well-known/oauth-protected-resource | jq

# Fetch Authorization Server Metadata
curl http://localhost:8080/.well-known/oauth-authorization-server | jq
```

**Expected Response:**
```json
{
  "resource": "http://localhost:8080",
  "authorization_servers": ["http://localhost:8080"],
  "scopes_supported": [
    "mcp:access",
    "files:read",
    "files:write",
    "admin:access",
    "user:profile"
  ],
  "bearer_methods_supported": ["header"]
}
```

### Test 2: WWW-Authenticate Headers

```bash
# Access protected endpoint without authentication
curl -i http://localhost:8080/mcp
```

**Expected Response:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource",
                         scope="mcp:access",
                         error="invalid_token",
                         error_description="Missing Authorization header"
Content-Type: application/json

{
  "error": "invalid_token",
  "error_description": "Missing Authorization header"
}
```

### Test 3: Endpoint-Specific Scopes

```bash
# Access files endpoint
curl -i http://localhost:8080/api/files/doc.txt

# Access admin endpoint
curl -i http://localhost:8080/api/admin/users
```

**Expected WWW-Authenticate:**
- Files endpoint: `scope="files:read files:write"`
- Admin endpoint: `scope="admin:access"`

### Test 4: Insufficient Scope Error

To test this, you need a valid token with insufficient scopes:

1. Complete OAuth flow to get token with only `mcp:access` scope
2. Try to access admin endpoint:

```bash
curl -i -H "Authorization: Bearer <token>" \
    http://localhost:8080/api/admin/users
```

**Expected Response:**
```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer scope="admin:access",
                         error="insufficient_scope",
                         error_description="Token lacks required scopes: admin:access"
Content-Type: application/json

{
  "error": "insufficient_scope",
  "error_description": "Token lacks required scopes: admin:access",
  "scope": "admin:access"
}
```

This enables **step-up authorization**: Client can request new token with additional scopes.

### Test 5: Method-Specific Scopes

Different HTTP methods require different scopes:

```bash
# GET requires only files:read
curl -i -H "Authorization: Bearer <token-with-files-read>" \
    -X GET http://localhost:8080/api/files/doc.txt

# DELETE requires files:delete AND admin:access
curl -i -H "Authorization: Bearer <token-with-only-files-read>" \
    -X DELETE http://localhost:8080/api/files/doc.txt
```

The DELETE request will return `403 insufficient_scope` because it requires both `files:delete` and `admin:access`.

## Complete OAuth Flow Test

1. **Start the server:**
   ```bash
   ./mcp-2025-11-25
   ```

2. **Discover endpoints (MCP 2025-11-25 discovery flow):**
   ```bash
   # Client tries to access protected resource
   curl -i http://localhost:8080/mcp
   
   # 401 response includes resource_metadata URL
   # Client fetches metadata
   curl http://localhost:8080/.well-known/oauth-protected-resource
   
   # Client discovers authorization server
   curl http://localhost:8080/.well-known/oauth-authorization-server
   ```

3. **Register a client (Dynamic Client Registration):**
   ```bash
   curl -X POST http://localhost:8080/oauth/register \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "Test MCP Client",
       "redirect_uris": ["http://localhost:3000/callback"],
       "grant_types": ["authorization_code", "refresh_token"],
       "token_endpoint_auth_method": "none"
     }' | jq
   ```

4. **Start authorization flow:**
   
   Open in browser:
   ```
   http://localhost:8080/oauth/authorize?client_id=<client_id>&redirect_uri=http://localhost:3000/callback&response_type=code&scope=mcp:access files:read&state=random-state&code_challenge=<challenge>&code_challenge_method=S256
   ```

5. **Exchange code for token:**
   ```bash
   curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:3000/callback&client_id=<client_id>&code_verifier=<verifier>"
   ```

6. **Access protected resource:**
   ```bash
   curl -H "Authorization: Bearer <access_token>" \
     http://localhost:8080/mcp | jq
   ```

## Configuration Highlights

```go
&oauth.ServerConfig{
    // Scope configuration (MCP 2025-11-25)
    SupportedScopes: []string{
        "mcp:access", "files:read", "files:write", "admin:access", "user:profile",
    },
    DefaultChallengeScopes: []string{"mcp:access"},
    
    // Endpoint-specific scopes (MCP 2025-11-25)
    EndpointScopeRequirements: map[string][]string{
        "/api/files/*":  {"files:read", "files:write"},
        "/api/admin/*":  {"admin:access"},
    },
    
    // Method-specific scopes (MCP 2025-11-25)
    EndpointMethodScopeRequirements: map[string]map[string][]string{
        "/api/files/*": {
            "GET":    {"files:read"},
            "DELETE": {"files:delete", "admin:access"},
        },
    },
    
    // Enhanced WWW-Authenticate (enabled by default)
    DisableWWWAuthenticateMetadata: false,
}
```

## MCP 2025-11-25 Compliance Checklist

This example demonstrates:

- ✅ Protected Resource Metadata at standard path (`/.well-known/oauth-protected-resource`)
- ✅ Authorization Server Metadata (`/.well-known/oauth-authorization-server`)
- ✅ WWW-Authenticate header with `resource_metadata` parameter
- ✅ WWW-Authenticate header with `scope` parameter
- ✅ Scope selection strategy (DefaultChallengeScopes + endpoint-specific)
- ✅ `insufficient_scope` error for missing scopes
- ✅ Endpoint-specific scope requirements
- ✅ Method-specific scope requirements
- ✅ PKCE enforcement (OAuth 2.1)
- ✅ Refresh token rotation (OAuth 2.1)
- ✅ Dynamic Client Registration (RFC 7591)

## See Also

- [MCP 2025-11-25 Migration Guide](../../docs/mcp-2025-11-25.md)
- [Discovery Mechanisms](../../docs/discovery.md)
- [Security Architecture](../../SECURITY_ARCHITECTURE.md)
- [Main README](../../README.md)

