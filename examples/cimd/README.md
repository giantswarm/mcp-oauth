# Client ID Metadata Documents (CIMD) Example

This example demonstrates Client ID Metadata Documents (CIMD), a feature from the MCP 2025-11-25 specification that allows clients to use HTTPS URLs as client identifiers with dynamic metadata discovery.

## What is CIMD?

Traditionally, OAuth clients must pre-register with the authorization server to obtain a `client_id`. With CIMD, clients can use an HTTPS URL as their `client_id`, and the authorization server will fetch client metadata from that URL.

This is ideal for MCP scenarios where servers and clients have no pre-existing relationship.

## Security Warning

**This example uses environment variables for secrets for simplicity. This is NOT SECURE for production use.**

For production deployments, use a secret manager. See the [Production Example](../production/README.md).

## Prerequisites

1. **Google OAuth Credentials**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a project and enable required APIs
   - Create OAuth 2.0 credentials (Web application)
   - Add redirect URI: `http://localhost:8080/oauth/callback`
   - Copy Client ID and Client Secret

## Running the Example

1. **Set environment variables**:
   ```bash
   export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
   export GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

2. **Run the server**:
   ```bash
   go run main.go
   ```

## Using CIMD

### Step 1: Host Your Client Metadata

For CIMD to work, you need to host a client metadata document at an HTTPS URL. The document must be valid JSON with the `client_id` field matching the URL.

Example `client.json` (see `client.json` in this directory):

```json
{
  "client_id": "https://example.com/oauth/client.json",
  "client_name": "Example MCP Client",
  "redirect_uris": [
    "http://localhost:8080/callback",
    "http://127.0.0.1:8080/callback"
  ],
  "token_endpoint_auth_method": "none"
}
```

### Step 2: Start Authorization Flow

Use the HTTPS URL as your `client_id`:

```
http://localhost:8080/oauth/authorize?
  client_id=https://example.com/oauth/client.json&
  redirect_uri=http://localhost:8080/callback&
  response_type=code&
  state=random-state&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

The server will:
1. Detect that `client_id` is an HTTPS URL
2. Fetch the metadata document from that URL
3. Validate that `client_id` in the document matches the URL
4. Verify the `redirect_uri` is in the allowed list
5. Continue with the OAuth flow

### Step 3: Exchange Code for Token

After authorization, exchange the code for a token:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=https://example.com/oauth/client.json" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

## Testing Locally

For local testing without hosting an actual HTTPS server, you can use:

1. **ngrok or similar tunneling service** to expose a local server with HTTPS
2. **A static hosting service** (GitHub Pages, Cloudflare Pages, etc.) to host your `client.json`

### Using ngrok

```bash
# Start a local server to host client.json
python3 -m http.server 9000 &

# Expose it via ngrok
ngrok http 9000

# Use the ngrok URL as your client_id
# e.g., https://abc123.ngrok.io/client.json
```

## Security Features

This example demonstrates CIMD's built-in security features:

### SSRF Protection
- Only HTTPS URLs are accepted
- Private/internal IPs are blocked
- DNS rebinding protection at connection time

### PKCE Required
- All CIMD clients are public clients
- PKCE (S256) is mandatory

### Caching
- Successful fetches are cached (default: 5 minutes)
- HTTP Cache-Control headers are respected
- Failed fetches are negatively cached to prevent abuse

### Rate Limiting
- Per-domain rate limiting prevents abuse
- Audit logging tracks all CIMD operations

## Verifying CIMD is Enabled

Check the authorization server metadata:

```bash
curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq .
```

Look for `"client_id_metadata_document_supported": true` in the response.

## Metadata Document Requirements

Your client metadata document MUST:

1. **Be served over HTTPS** (except for development with ngrok)
2. **Return `Content-Type: application/json`**
3. **Have `client_id` field matching the URL exactly**
4. **Include at least one `redirect_uri`**

Optional fields:
- `client_name` - Displayed on consent screen
- `client_uri` - Link to client's homepage
- `logo_uri` - Client logo for consent screen
- `grant_types` - Defaults to `["authorization_code"]`
- `token_endpoint_auth_method` - Defaults to `"none"`
- `scope` - Space-delimited scopes the client may request

## Features Demonstrated

- CIMD configuration
- HTTPS URL as client_id
- Dynamic client metadata discovery
- SSRF protection
- Metadata caching
- PKCE enforcement

## Next Steps

- [CIMD Documentation](../../docs/cimd.md) - Complete reference
- [Security Guide](../../docs/security.md) - Security best practices
- [MCP 2025-11-25](../../docs/mcp-2025-11-25.md) - Specification details

