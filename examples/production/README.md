# Production OAuth Example

This example demonstrates a production-ready OAuth 2.1 setup with all security features enabled.

## Features

- ✅ Token encryption at rest (AES-256-GCM)
- ✅ Refresh token rotation with reuse detection (OAuth 2.1)
- ✅ Comprehensive audit logging
- ✅ Triple-layered rate limiting (IP, user, security events)
- ✅ Provider-side token revocation (Google/GitHub/etc)
- ✅ Secure client registration with access token
- ✅ HTTPS/TLS support
- ✅ Structured JSON logging
- ✅ Health and readiness endpoints
- ✅ Security headers
- ✅ Request logging
- ✅ Configurable timeouts and retention periods

## Prerequisites

1. **Google OAuth Credentials** (see basic example)
2. **Encryption Key**: Generate and store securely
3. **TLS Certificates** (for HTTPS)

## Setup

### 1. Generate Encryption Key

```bash
# Generate a new encryption key
go run -C ../.. -c 'package main; import "fmt"; import oauth "github.com/giantswarm/mcp-oauth"; func main() { k, _ := oauth.GenerateEncryptionKey(); fmt.Println(oauth.EncryptionKeyToBase64(k)) }'

# Or use this one-liner with Go
go run main.go  # Will generate and display a key on first run
```

### 2. Set Environment Variables

Create a `.env` file (DO NOT commit this):

```bash
# Required
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Security
OAUTH_ENCRYPTION_KEY=your-base64-encoded-32-byte-key
OAUTH_REGISTRATION_TOKEN=secure-random-token-for-client-registration

# Server
MCP_RESOURCE=https://mcp.example.com
LISTEN_ADDR=:8443

# TLS (optional, for HTTPS)
TLS_CERT_FILE=/path/to/cert.pem
TLS_KEY_FILE=/path/to/key.pem

# Logging
LOG_LEVEL=info
LOG_JSON=true

# Optional
TRUST_PROXY=false
ENABLE_METRICS=true
```

### 3. Load Environment Variables

```bash
export $(cat .env | xargs)
```

## Running

### Development (HTTP)

```bash
# Without TLS (development only)
unset TLS_CERT_FILE TLS_KEY_FILE
go run main.go
```

### Production (HTTPS)

```bash
# Generate self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run with TLS
export TLS_CERT_FILE=cert.pem
export TLS_KEY_FILE=key.pem
go run main.go
```

## Usage

### 1. Register a Client

```bash
curl -X POST https://localhost:8443/oauth/register \
  -H "Authorization: Bearer $OAUTH_REGISTRATION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Production MCP Client",
    "client_type": "confidential",
    "redirect_uris": ["https://client.example.com/callback"],
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "https://www.googleapis.com/auth/gmail.readonly"
  }'
```

Response:
```json
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_name": "Production MCP Client",
  ...
}
```

**IMPORTANT**: Save the `client_secret` - it's only shown once!

### 2. Check Server Health

```bash
# Health check
curl https://localhost:8443/health

# Readiness check
curl https://localhost:8443/ready
```

### 3. View Metadata

```bash
# OAuth Protected Resource Metadata
curl https://localhost:8443/.well-known/oauth-protected-resource

# Authorization Server Metadata
curl https://localhost:8443/.well-known/oauth-authorization-server
```

### 4. Authorization Flow

See the basic example for the complete OAuth flow.

## Security Considerations

### Encryption Key Management

**DO NOT** hardcode encryption keys in code or config files!

Best practices:

1. **AWS Secrets Manager**:
   ```bash
   aws secretsmanager get-secret-value --secret-id oauth-encryption-key \
     --query SecretString --output text
   ```

2. **Google Cloud Secret Manager**:
   ```bash
   gcloud secrets versions access latest --secret=oauth-encryption-key
   ```

3. **HashiCorp Vault**:
   ```bash
   vault kv get -field=key secret/oauth/encryption-key
   ```

4. **Kubernetes Secrets**:
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: oauth-secrets
   type: Opaque
   data:
     encryption-key: <base64-encoded-key>
   ```

### Registration Token

The registration token protects the client registration endpoint:

```bash
# Generate a secure token
openssl rand -base64 32

# Use it in registration requests
curl -H "Authorization: Bearer $OAUTH_REGISTRATION_TOKEN" ...
```

Share this token ONLY with trusted client developers.

### Rate Limiting

The production setup uses **three layers of rate limiting** for defense in depth:

1. **IP-based Rate Limiting**: Prevents DoS attacks from external sources
   ```go
   rateLimiter := security.NewRateLimiter(10, 20, logger)
   server.SetRateLimiter(rateLimiter)
   ```

2. **User-based Rate Limiting**: Prevents abuse from authenticated users
   ```go
   userRateLimiter := security.NewRateLimiter(100, 200, logger)
   server.SetUserRateLimiter(userRateLimiter)
   ```

3. **Security Event Rate Limiting**: Prevents log flooding during attacks
   ```go
   // Limits logging of security events (code reuse, token reuse detection)
   // Prevents attackers from causing DoS via excessive logging
   securityEventRateLimiter := security.NewRateLimiter(1, 5, logger)
   server.SetSecurityEventRateLimiter(securityEventRateLimiter)
   ```

**Why three layers?**
- IP limiting stops attacks before authentication
- User limiting prevents authenticated abuse
- Security event limiting prevents log-based DoS attacks

Adjust based on your threat model and traffic:
```go
// More permissive (high-traffic production)
rateLimiter := security.NewRateLimiter(100, 200, logger)

// More restrictive (sensitive environments)
rateLimiter := security.NewRateLimiter(5, 10, logger)
```

Monitor rate limit violations in logs:
```json
{
  "level": "warn",
  "msg": "Rate limit exceeded",
  "ip": "203.0.113.42",
  "user": "user@example.com"
}
```

### Audit Logging

All security events are logged:

```json
{
  "level": "info",
  "msg": "Token issued",
  "client_id": "abc123",
  "user_email_hash": "sha256:...",
  "scopes": "gmail.readonly",
  "timestamp": "2025-11-23T10:30:00Z"
}
```

Sensitive data (tokens, emails) is hashed before logging.

## Monitoring

### Structured Logs

Use JSON logs for easy parsing:

```bash
# Filter by level
cat app.log | jq 'select(.level == "error")'

# Find rate limit violations
cat app.log | jq 'select(.msg == "Rate limit exceeded")'

# Track user activity
cat app.log | jq 'select(.user_email_hash != null)'
```

### Metrics

Enable Prometheus metrics:

```bash
export ENABLE_METRICS=true
curl https://localhost:8443/metrics
```

### Alerts

Set up alerts for:
- High error rates
- Rate limit violations (IP, user, or security event)
- **Token reuse detection** (CRITICAL - indicates attack!)
- **Authorization code reuse** (CRITICAL - indicates attack!)
- **Provider revocation failures** (tokens remain valid at provider)
- Failed authentication attempts
- Unusual client registration activity

**Critical Security Alerts:**
```json
{
  "level": "error",
  "event_type": "authorization_code_reuse_detected",
  "severity": "critical",
  "action": "all_tokens_revoked",
  "user_id": "user@example.com",
  "client_id": "abc123"
}
```

These indicate potential token theft attacks and should trigger immediate investigation.

## Deployment

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o mcp-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/mcp-server /usr/local/bin/
EXPOSE 8443
CMD ["mcp-server"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: mcp-server
        image: your-registry/mcp-server:latest
        env:
        - name: GOOGLE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: google-client-id
        - name: OAUTH_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: encryption-key
        ports:
        - containerPort: 8443
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
            scheme: HTTPS
```

## Troubleshooting

### Tokens Not Persisting

If tokens don't persist across restarts, ensure:
- `OAUTH_ENCRYPTION_KEY` is set and consistent
- Key is exactly 32 bytes (base64 encoded)
- Using persistent storage (not in-memory only)

### Rate Limiting Too Strict

Adjust limits in configuration:
```go
Rate: 100,    // Increase limits
Burst: 200,
```

### TLS Certificate Errors

For development, accept self-signed certs:
```bash
curl -k https://localhost:8443/health
```

For production, use valid certificates from Let's Encrypt or your CA.

## Next Steps

- Set up log aggregation (ELK, Splunk, CloudWatch)
- Configure metrics and monitoring (Prometheus, Grafana)
- Implement backup and disaster recovery
- Set up CI/CD pipeline
- Load testing and performance tuning
- Security audit and penetration testing

