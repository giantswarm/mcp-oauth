# GitHub OAuth Example

This example demonstrates how to use the `mcp-oauth` library with the GitHub OAuth provider.

## Features

- GitHub OAuth authentication
- Organization-based access control (optional)
- User profile and email retrieval
- PKCE support for enhanced security
- MCP 2025-11-25 compliant discovery endpoints

## Prerequisites

### 1. Create a GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - **Application name**: Your app name (e.g., "MCP OAuth Example")
   - **Homepage URL**: `http://localhost:8080`
   - **Authorization callback URL**: `http://localhost:8080/oauth/callback`
4. Click "Register application"
5. Copy the **Client ID**
6. Generate a new **Client Secret** and copy it

### 2. Set Environment Variables

```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"

# Optional: Restrict to specific organizations (comma-separated)
export GITHUB_ALLOWED_ORGANIZATIONS="giantswarm,kubernetes"
```

## Running the Example

```bash
# From the examples/github directory
go run main.go
```

Visit `http://localhost:8080` in your browser.

## How It Works

### Authorization Flow

1. User clicks "Sign in with GitHub"
2. Browser redirects to GitHub for authentication
3. After approval, GitHub redirects back with an authorization code
4. Server exchanges the code for an access token
5. Server fetches user info from GitHub API

### Organization Restriction

When `GITHUB_ALLOWED_ORGANIZATIONS` is set:

- The `read:org` scope is automatically added to OAuth requests
- After authentication, the user's organization memberships are checked
- Only members of allowed organizations can access protected resources
- Organization matching is case-insensitive

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Home page with login link |
| `GET /oauth/authorize` | Start OAuth flow |
| `GET /oauth/callback` | OAuth callback handler |
| `POST /oauth/token` | Token exchange endpoint |
| `POST /oauth/register` | Dynamic client registration |
| `GET /api/resource` | Protected resource (requires auth) |
| `GET /health` | Health check endpoint |
| `GET /.well-known/oauth-authorization-server` | AS metadata |
| `GET /.well-known/oauth-protected-resource` | PRM metadata |

## GitHub OAuth Specifics

### Non-Expiring Tokens

GitHub OAuth Apps issue **non-expiring** access tokens. This means:
- Tokens remain valid until revoked by the user
- No refresh token is provided
- For enhanced security, implement periodic re-authentication

### Email Privacy

GitHub users can set their email to private. The provider handles this by:
1. First checking the `/user` endpoint for public email
2. If null, fetching from `/user/emails` endpoint (requires `user:email` scope)
3. Selecting the primary verified email address

### Rate Limiting

GitHub API has rate limits:
- **Authenticated requests**: 5,000/hour
- **Unauthenticated**: 60/hour

The provider's health check uses an unauthenticated endpoint to avoid consuming rate limits.

## Security Considerations

### Token Storage

Since GitHub tokens don't expire, secure storage is critical:

```go
// Use encryption for token storage in production
import "github.com/giantswarm/mcp-oauth/security"

encryptor, err := security.NewTokenEncryptor(encryptionKey)
// Use with token store
```

### PKCE

While GitHub doesn't require PKCE, this library supports it for defense-in-depth:

```go
// PKCE is automatically handled by the OAuth server
// Clients should include code_challenge and code_challenge_method parameters
```

### Organization Validation

Organization membership is validated on every token validation, ensuring:
- Users who leave an organization lose access immediately
- No caching of organization membership (fresh check each time)

## Testing

To test without a real GitHub OAuth App, you can use the mock provider:

```go
import "github.com/giantswarm/mcp-oauth/providers/mock"

provider := mock.NewProvider()
```

## Troubleshooting

### "Organization required" error

If you see this error, ensure:
1. The user is a member of one of the allowed organizations
2. The organization membership is public, OR
3. The app has been granted access to read private organization memberships

### "Email not found" 

If the email is empty:
1. Ensure the `user:email` scope is included
2. The user must have at least one verified email in GitHub

### Rate limit errors

If you see 403 errors:
1. Check GitHub API rate limit headers
2. Reduce request frequency
3. Consider caching user info locally

