# Examples

This directory contains example applications demonstrating different use cases of the mcp-oauth library.

## Available Examples

### [Basic](./basic)

Minimal OAuth setup to get started quickly.

**Features:**
- Basic configuration
- Google OAuth integration
- Client registration
- Token validation

**Best for:** Learning the basics, quick prototyping

```bash
cd basic
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
go run main.go
```

### [Production](./production)

Production-ready setup with all security features enabled.

**Features:**
- Token encryption at rest (AES-256-GCM)
- Refresh token rotation
- Comprehensive audit logging
- Rate limiting
- TLS/HTTPS support
- Structured logging
- Health checks

**Best for:** Production deployments, security-critical applications

```bash
cd production
# See production/README.md for full setup
go run main.go
```

### [Custom Scopes](./custom-scopes)

Demonstrates working with multiple Google API scopes.

**Features:**
- Multiple Google API scopes (Gmail, Drive, Calendar, Contacts)
- Scope-specific endpoints
- Best practices for scope selection

**Best for:** Multi-service integrations, understanding OAuth scopes

```bash
cd custom-scopes
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
go run main.go
```

### [MCP 2025-11-25](./mcp-2025-11-25)

Demonstrates new MCP 2025-11-25 specification features.

**Features:**
- Protected Resource Metadata (RFC 9728)
- Enhanced WWW-Authenticate headers
- Scope discovery and validation
- Resource parameter binding (RFC 8707)

**Best for:** MCP specification compliance, modern OAuth discovery

```bash
cd mcp-2025-11-25
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
go run main.go
```

### [Prometheus](./prometheus)

Demonstrates OpenTelemetry instrumentation with Prometheus metrics.

**Features:**
- Prometheus metrics endpoint
- OAuth flow metrics
- Security event metrics
- Performance monitoring

**Best for:** Observability, production monitoring

```bash
cd prometheus
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
go run main.go
# Visit http://localhost:8080/metrics
```

## Quick Start

1. **Choose an example** based on your needs
2. **Set up Google OAuth credentials** (see main README.md)
3. **Set environment variables**
4. **Run the example**

## Common Setup

All examples require Google OAuth credentials:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project
3. Enable required APIs (Gmail, Drive, etc.)
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URI: `http://localhost:8080/oauth/callback`
6. Copy Client ID and Secret

## Environment Variables

Common environment variables across examples:

```bash
# Required
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Optional
MCP_RESOURCE=http://localhost:8080  # Default
LOG_LEVEL=info                       # debug, info, warn, error
```

## Testing the Examples

### 1. Start the Server

```bash
cd basic  # or production, custom-scopes
go run main.go
```

### 2. Register a Client

```bash
curl -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "client_type": "public",
    "redirect_uris": ["http://localhost:3000/callback"],
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "https://www.googleapis.com/auth/gmail.readonly"
  }'
```

Save the `client_id` from the response.

### 3. Authorize

Generate PKCE values:

```bash
# code_verifier (43-128 random characters)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)

# code_challenge (base64url(sha256(code_verifier)))
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=+/" | tr "/+" "_-")

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"
```

Open in browser (replace CLIENT_ID and CODE_CHALLENGE):
```
http://localhost:8080/oauth/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=https://www.googleapis.com/auth/gmail.readonly&state=test-state&code_challenge=CODE_CHALLENGE&code_challenge_method=S256&response_type=code
```

### 4. Exchange Code for Token

After authorization, you'll receive a code in the redirect. Exchange it:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=CLIENT_ID" \
  -d "code_verifier=$CODE_VERIFIER"
```

### 5. Access Protected Endpoint

```bash
curl http://localhost:8080/mcp \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Building Production Applications

For production use, see the [production example](./production) and consider:

1. **Security**:
   - Enable token encryption
   - Use HTTPS/TLS
   - Enable audit logging
   - Configure rate limiting
   - Secure client registration

2. **Observability**:
   - Structured logging
   - Metrics collection
   - Health checks
   - Distributed tracing

3. **Deployment**:
   - Container images (Docker)
   - Kubernetes manifests
   - CI/CD pipelines
   - Secret management

4. **Operations**:
   - Backup and recovery
   - Monitoring and alerting
   - Incident response
   - Performance tuning

## Documentation

- [Getting Started](../docs/getting-started.md) - Setup guide
- [Configuration Guide](../docs/configuration.md) - All configuration options
- [Security Guide](../docs/security.md) - Security features and best practices
- [Observability](../docs/observability.md) - Metrics and tracing
- [API Reference](https://pkg.go.dev/github.com/giantswarm/mcp-oauth) - Godoc
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute

## Need Help?

- Check the example README files for detailed instructions
- Review the [troubleshooting sections](./production/README.md#troubleshooting)
- Open an [issue](https://github.com/giantswarm/mcp-oauth/issues) if you find bugs
- Start a [discussion](https://github.com/giantswarm/mcp-oauth/discussions) for questions

