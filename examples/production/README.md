# Production OAuth Example

This example demonstrates a production-ready OAuth 2.1 setup with all security features enabled.

## Features

- ✅ Token encryption at rest (AES-256-GCM)
- ✅ Refresh token rotation with reuse detection (OAuth 2.1)
- ✅ Comprehensive audit logging
- ✅ Multi-layered rate limiting (IP, user, client registration)
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

### 1. Secret Management (REQUIRED for Production)

**CRITICAL: NEVER use environment variables for production secrets!**

Production deployments **MUST** use a secret management solution. Choose one:

#### Option 1: HashiCorp Vault (Recommended)

```bash
# 1. Generate and store encryption key
vault kv put secret/oauth/encryption-key \
  value="$(openssl rand -base64 32)"

# 2. Store OAuth credentials
vault kv put secret/oauth/google \
  client_id="your-client-id.apps.googleusercontent.com" \
  client_secret="your-client-secret"

# 3. Store registration token
vault kv put secret/oauth/registration \
  token="$(openssl rand -base64 32)"

# 4. Retrieve secrets in your application
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"

# Read secrets from Vault
OAUTH_ENCRYPTION_KEY=$(vault kv get -field=value secret/oauth/encryption-key)
GOOGLE_CLIENT_ID=$(vault kv get -field=client_id secret/oauth/google)
GOOGLE_CLIENT_SECRET=$(vault kv get -field=client_secret secret/oauth/google)
```

See [Vault documentation](https://www.vaultproject.io/docs) for production setup with AppRole or Kubernetes auth.

#### Option 2: AWS Secrets Manager

```bash
# 1. Generate and store encryption key
aws secretsmanager create-secret \
  --name oauth-encryption-key \
  --secret-string "$(openssl rand -base64 32)"

# 2. Store OAuth credentials
aws secretsmanager create-secret \
  --name oauth-google-credentials \
  --secret-string '{
    "client_id": "your-client-id.apps.googleusercontent.com",
    "client_secret": "your-client-secret"
  }'

# 3. Retrieve in application (use AWS SDK in production)
OAUTH_ENCRYPTION_KEY=$(aws secretsmanager get-secret-value \
  --secret-id oauth-encryption-key \
  --query SecretString --output text)

# Or use IAM roles for EC2/ECS/EKS (recommended)
```

Example Go code:
```go
import (
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/secretsmanager"
)

func getEncryptionKey() (string, error) {
    sess := session.Must(session.NewSession())
    svc := secretsmanager.New(sess)
    
    result, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
        SecretId: aws.String("oauth-encryption-key"),
    })
    if err != nil {
        return "", err
    }
    
    return *result.SecretString, nil
}
```

#### Option 3: Google Cloud Secret Manager

```bash
# 1. Generate and store encryption key
echo -n "$(openssl rand -base64 32)" | \
  gcloud secrets create oauth-encryption-key --data-file=-

# 2. Store OAuth credentials
gcloud secrets create oauth-google-client-id \
  --data-file=- <<< "your-client-id.apps.googleusercontent.com"

gcloud secrets create oauth-google-client-secret \
  --data-file=- <<< "your-client-secret"

# 3. Retrieve in application
OAUTH_ENCRYPTION_KEY=$(gcloud secrets versions access latest \
  --secret=oauth-encryption-key)

# Or use Workload Identity for GKE (recommended)
```

#### Option 4: Kubernetes with External Secrets Operator

Best for Kubernetes deployments - syncs secrets from external secret managers:

```yaml
# Install External Secrets Operator first:
# helm install external-secrets external-secrets/external-secrets

# 1. Configure SecretStore (for Vault)
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: mcp-oauth
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "mcp-oauth"

---
# 2. Create ExternalSecret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: oauth-secrets
  namespace: mcp-oauth
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: oauth-secrets
    creationPolicy: Owner
  data:
  - secretKey: encryption-key
    remoteRef:
      key: oauth/encryption-key
      property: value
  - secretKey: google-client-id
    remoteRef:
      key: oauth/google
      property: client_id
  - secretKey: google-client-secret
    remoteRef:
      key: oauth/google
      property: client_secret

---
# 3. Reference in Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  template:
    spec:
      containers:
      - name: mcp-server
        env:
        - name: OAUTH_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: encryption-key
        - name: GOOGLE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: google-client-id
        - name: GOOGLE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: google-client-secret
```

### 2. Development Only: Environment Variables

**⚠️ WARNING: For local development ONLY! NEVER use in production!**

For local testing, you can use environment variables, but this is **INSECURE** for production.

Create a `.env` file (DO NOT commit this):

```bash
# Required
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Security
OAUTH_ENCRYPTION_KEY=$(openssl rand -base64 32)
OAUTH_REGISTRATION_TOKEN=$(openssl rand -base64 32)

# Server
MCP_RESOURCE=http://localhost:8080
LISTEN_ADDR=:8080

# Logging
LOG_LEVEL=debug
LOG_JSON=false
```

**Why environment variables are UNSAFE for production:**
- Visible in process listings (`ps aux`, `docker inspect`)
- Leaked in error messages, stack traces, and logs
- Exposed in container orchestration metadata (Docker, Kubernetes)
- Not rotatable without restarting the application
- No audit trail of secret access
- No encryption at rest
- Vulnerable to memory dumps and side-channel attacks

**Migration path from development to production:**
1. Set up a secret manager (Vault, AWS Secrets Manager, etc.)
2. Store all secrets in the secret manager
3. Update application code to read from secret manager
4. Remove `.env` file and environment variables
5. Rotate all secrets that were previously in environment variables
6. Add secret access monitoring and alerting

Load environment variables (development only):

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

## Production Security Checklist

Before deploying to production, verify all items:

**Secret Management:**
- [ ] All secrets stored in a secret manager (NOT environment variables)
- [ ] Secret rotation policy configured and documented
- [ ] Secrets encrypted at rest in the secret manager
- [ ] Secrets encrypted in transit (TLS for all connections)
- [ ] Secret access restricted by IAM/RBAC with least privilege
- [ ] Audit logging enabled for all secret access
- [ ] No secrets in version control (verify with `git log -p | grep -i 'secret\|password\|key'`)
- [ ] No secrets in container images (verify with `docker history`)
- [ ] No secrets in CI/CD logs or build artifacts

**Network Security:**
- [ ] HTTPS/TLS enabled for all endpoints (no HTTP in production)
- [ ] Valid TLS certificates from a trusted CA (not self-signed)
- [ ] TLS 1.2 or higher enforced
- [ ] Strong cipher suites configured
- [ ] HSTS headers enabled
- [ ] Firewall rules restrict access to authorized networks

**Application Security:**
- [ ] All security features enabled (rate limiting, audit logging, encryption)
- [ ] Rate limits tuned for production traffic patterns
- [ ] PKCE enforced for all OAuth flows
- [ ] Refresh token rotation enabled
- [ ] Token encryption at rest enabled
- [ ] Secure session timeouts configured
- [ ] Input validation on all endpoints

**Monitoring & Alerting:**
- [ ] Audit logs centralized and monitored (SIEM integration)
- [ ] Alerts configured for critical security events:
  - [ ] Authorization code reuse detection
  - [ ] Refresh token reuse detection
  - [ ] Rate limit violations
  - [ ] Failed authentication attempts
  - [ ] Unusual client registration activity
  - [ ] Provider token revocation failures
- [ ] Metrics collection enabled (Prometheus/OpenTelemetry)
- [ ] Dashboard created for security metrics
- [ ] On-call rotation defined for security alerts

**Operational Security:**
- [ ] Principle of least privilege applied to all service accounts
- [ ] Regular security updates and patching schedule
- [ ] Disaster recovery and backup procedures documented
- [ ] Incident response plan created and tested
- [ ] Security audit completed
- [ ] Penetration testing performed
- [ ] Compliance requirements verified (GDPR, SOC2, etc.)

**Documentation:**
- [ ] Architecture diagram updated
- [ ] Runbook created for common operations
- [ ] Security documentation complete
- [ ] Secret rotation procedures documented
- [ ] Incident response procedures documented

## Security Considerations

### Encryption Key Management

**Encryption keys MUST be managed through a secret manager** (see Setup section above).

Key requirements:
- **32 bytes** (256 bits) of cryptographically secure random data
- **Base64 encoded** for storage and transmission
- **Never hardcoded** in code, config files, or environment variables
- **Rotated regularly** (recommend every 90 days)
- **Backed up securely** with the secret manager's backup features

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

The production setup uses **multiple layers of rate limiting** for defense in depth:

1. **IP-based Rate Limiting**: Prevents DoS attacks from external sources
   ```go
   rateLimiter := security.NewRateLimiter(10, 20, logger)
   defer rateLimiter.Stop()
   server.SetRateLimiter(rateLimiter)
   ```

2. **User-based Rate Limiting**: Prevents abuse from authenticated users
   ```go
   userRateLimiter := security.NewRateLimiter(100, 200, logger)
   defer userRateLimiter.Stop()
   server.SetUserRateLimiter(userRateLimiter)
   ```

3. **Client Registration Rate Limiting**: Prevents registration DoS
   ```go
   clientRegRateLimiter := security.NewClientRegistrationRateLimiter(logger)
   defer clientRegRateLimiter.Stop()
   server.SetClientRegistrationRateLimiter(clientRegRateLimiter)
   ```

**Why multiple layers?**
- IP limiting stops attacks before authentication
- User limiting prevents authenticated abuse
- Client registration limiting prevents registration/deletion cycle DoS

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
- Rate limit violations (IP, user, or client registration)
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

**CRITICAL: Never bake secrets into Docker images!**

Secure multi-stage build example:

```dockerfile
# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-server .

# Runtime stage
FROM alpine:latest

# Security: Run as non-root user
RUN addgroup -g 1000 mcp && \
    adduser -D -u 1000 -G mcp mcp && \
    apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/mcp-server /usr/local/bin/mcp-server

# Security: Use non-root user
USER mcp

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider https://localhost:8443/health || exit 1

CMD ["mcp-server"]
```

**Docker Security Practices:**
```bash
# Build image
docker build -t your-registry/mcp-server:latest .

# Verify no secrets in image layers
docker history your-registry/mcp-server:latest

# Run with secrets from secret manager (Docker Swarm)
docker service create \
  --name mcp-server \
  --secret oauth-encryption-key \
  --secret google-client-secret \
  your-registry/mcp-server:latest

# Or use Docker secrets mount (Docker Compose)
# See docker-compose.yml with secrets from files
```

**NEVER:**
- Use `ENV` or `ARG` for secrets in Dockerfile
- Copy `.env` files into the image
- Hardcode secrets in the image
- Use `docker commit` with running containers that have secrets

**Docker Scout will flag these as critical vulnerabilities!**

### Kubernetes

**Production Kubernetes deployments should use External Secrets Operator** (see Setup section above).

Example deployment referencing synced secrets:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
  namespace: mcp-oauth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      # Use Workload Identity or IRSA for secret access
      serviceAccountName: mcp-oauth
      containers:
      - name: mcp-server
        image: your-registry/mcp-server:latest
        env:
        # Secrets synced from External Secrets Operator
        - name: GOOGLE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oauth-secrets  # Created by ExternalSecret
              key: google-client-id
        - name: GOOGLE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: google-client-secret
        - name: OAUTH_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: oauth-secrets
              key: encryption-key
        # Non-secret configuration
        - name: MCP_RESOURCE
          value: "https://mcp.example.com"
        - name: LOG_JSON
          value: "true"
        ports:
        - containerPort: 8443
          name: https
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
```

**Important Kubernetes Security Notes:**
- Use External Secrets Operator to sync from Vault/AWS/GCP secret managers
- Never create Kubernetes Secrets manually with `kubectl create secret`
- Use Workload Identity (GKE) or IRSA (EKS) for secret manager authentication
- Enable Pod Security Standards (restricted profile)
- Use NetworkPolicies to limit pod-to-pod communication
- Enable audit logging for secret access

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

