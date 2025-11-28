# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

This library is designed with security as a top priority. Key security features include:

### Built-in Security Features

- ✅ **Token Encryption at Rest**: AES-256-GCM authenticated encryption
- ✅ **Refresh Token Rotation**: OAuth 2.1 token rotation with reuse detection
- ✅ **Comprehensive Audit Logging**: All security events logged with hashed sensitive data
- ✅ **Rate Limiting**: Per-IP and per-user protection against brute force and DoS
- ✅ **PKCE Enforcement**: Only S256 method supported (plain disabled)
- ✅ **Cryptographic Security**: All tokens generated with crypto/rand
- ✅ **Client Type Validation**: Enforces proper authentication for confidential clients
- ✅ **HTTPS Enforcement**: Required for production (except localhost)

### Security Best Practices

When using this library in production:

1. **Enable Token Encryption**:
   ```go
   import "github.com/giantswarm/mcp-oauth/security"
   
   encKey, _ := security.GenerateKey()
   encryptor, _ := security.NewEncryptor(encKey)
   server.SetEncryptor(encryptor)
   ```

2. **Store Encryption Keys Securely**:
   - Use a Key Management Service (KMS) like AWS KMS, Google Cloud KMS, or HashiCorp Vault
   - Never commit encryption keys to version control
   - Rotate keys periodically

3. **Enable Audit Logging**:
   ```go
   import "github.com/giantswarm/mcp-oauth/security"
   
   auditor := security.NewAuditor(logger, true)
   server.SetAuditor(auditor)
   ```

4. **Configure Rate Limiting**:
   ```go
   import "github.com/giantswarm/mcp-oauth/security"
   
   ipRateLimiter := security.NewRateLimiter(10, 20, logger)
   defer ipRateLimiter.Stop()
   server.SetRateLimiter(ipRateLimiter)
   
   userRateLimiter := security.NewRateLimiter(100, 200, logger)
   defer userRateLimiter.Stop()
   server.SetUserRateLimiter(userRateLimiter)
   ```

5. **Use HTTPS in Production**:
   - The library enforces HTTPS for non-localhost URLs
   - Use TLS 1.2 or higher
   - Configure proper certificate validation

6. **Secure Client Registration**:
   ```go
   &oauth.ServerConfig{
       AllowPublicClientRegistration: false,
       RegistrationAccessToken: "secure-random-token",
       MaxClientsPerIP: 10,
   }
   ```

7. **Monitor Audit Logs**:
   - Set up log aggregation and monitoring
   - Alert on security events (rate limits, token reuse, failed auth)
   - Review logs regularly for suspicious activity

8. **Monitor Scope Validation Failures**:
   - Track repeated scope validation failures from the same client (potential attack indicator)
   - Set up alerts for `scope_escalation_attempt` events (high severity)
   - Monitor for patterns of unauthorized scope requests across multiple clients
   - Review clients requesting scopes they're not authorized for
   - Example alert queries:
     ```
     # Alert on scope escalation attempts
     event_type:"scope_escalation_attempt" AND severity:"high"
     
     # Alert on repeated failures from same client
     COUNT(event_type:"scope_validation_failed" by client_id) > 5 in 1h
     ```

## Security Monitoring

### Critical Security Events to Monitor

The library logs the following security events through the audit interface. Set up monitoring and alerting for:

#### Scope Validation Events

| Event Type | Severity | Description | Recommended Action |
|------------|----------|-------------|-------------------|
| `scope_escalation_attempt` | HIGH | Client attempted to obtain tokens with unauthorized scopes | Investigate client activity; possible compromise |
| `scope_validation_failed` | MEDIUM | Scope validation failed during auth flow | Review if legitimate misconfiguration or attack |

**Monitoring Recommendations**:

1. **Alert Thresholds**:
   - Single `scope_escalation_attempt`: Immediate alert (possible attack)
   - 3+ `scope_validation_failed` from same client in 1 hour: Warning
   - 10+ `scope_validation_failed` from same IP in 1 hour: Critical alert

2. **Log Analysis**:
   ```go
   // Audit events include these fields for correlation:
   {
       "type": "scope_escalation_attempt",
       "user_id": "user-123",
       "client_id": "client-456",
       "details": {
           "severity": "high",
           "requested_scope": "admin:all read:api",
           "reason": "client not authorized for requested scopes"
       }
   }
   ```

3. **Response Procedures**:
   - **Scope escalation attempt**: 
     - Review client registration details
     - Check if client credentials are compromised
     - Consider temporarily disabling the client
     - Investigate user account for compromise
   - **Repeated validation failures**:
     - May indicate misconfiguration
     - Check if client's allowed scopes need updating
     - Verify client application is requesting correct scopes

4. **Metrics to Track**:
   - Count of scope validation failures per client (hourly)
   - Count of scope escalation attempts (daily)
   - Most frequently requested unauthorized scopes
   - Clients with highest scope validation failure rates

### Extracting Metrics from Audit Logs

The library logs all security events through structured logging (slog). You can extract metrics from these logs using various tools:

#### Using Prometheus with Log-based Metrics

If using Grafana Loki or similar:

```promql
# Count scope escalation attempts
count_over_time({job="oauth-server"} |= "scope_escalation_attempt" [1h])

# Scope validation failures by client
sum by (client_id) (
  count_over_time({job="oauth-server"} |= "scope_validation_failed" [1h])
)

# High severity security events
rate({job="oauth-server"} |= "scope_escalation_attempt" [5m])
```

#### Using ELK Stack

Create visualizations and alerts based on:

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event_type": "scope_escalation_attempt" } },
        { "match": { "details.severity": "high" } }
      ]
    }
  }
}
```

#### Custom Metrics Collector

You can implement a custom auditor that also exports Prometheus metrics:

```go
type MetricsAuditor struct {
    *security.Auditor
    scopeValidationFailures *prometheus.CounterVec
    scopeEscalationAttempts prometheus.Counter
}

func (m *MetricsAuditor) LogEvent(event security.Event) {
    // Call original auditor
    m.Auditor.LogEvent(event)
    
    // Export metrics
    switch event.Type {
    case "scope_escalation_attempt":
        m.scopeEscalationAttempts.Inc()
    case "scope_validation_failed":
        m.scopeValidationFailures.WithLabelValues(event.ClientID).Inc()
    }
}
```

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. Report Via Private Channel

Send details to: **security@giantswarm.io**

Include in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if any)
- Your contact information for follow-up

### 2. What to Expect

- **Initial Response**: Within 48 hours acknowledging receipt
- **Assessment**: We'll assess the vulnerability and determine severity
- **Communication**: Regular updates on the progress of a fix
- **Resolution**: 
  - **Critical**: Fixed within 7 days
  - **High**: Fixed within 30 days
  - **Medium**: Fixed within 90 days
  - **Low**: Included in next regular release

### 3. Disclosure Policy

We follow **Coordinated Vulnerability Disclosure**:

1. You report the vulnerability privately
2. We acknowledge and assess the issue
3. We develop and test a fix
4. We prepare a security advisory
5. We release the fix and publish the advisory
6. After 90 days (or earlier if agreed), full disclosure is permitted

### 4. Recognition

Security researchers who report valid vulnerabilities will be:
- Credited in the security advisory (if desired)
- Listed in our Hall of Fame (with permission)
- Eligible for our bug bounty program (when available)

## Security Advisories

Published security advisories can be found at:
- [GitHub Security Advisories](https://github.com/giantswarm/mcp-oauth/security/advisories)

Subscribe to notifications:
- Watch this repository for security alerts
- Subscribe to our mailing list (TBD)

## Security Considerations

### Token Storage

**In-Memory Storage**: 
- Tokens are stored in memory by default
- Enable encryption for at-rest protection
- Consider external storage (Redis, PostgreSQL) for production

**Encryption**:
- Use `Security.EncryptionKey` to enable AES-256-GCM encryption
- Manage keys through KMS or secure vault
- Rotate encryption keys periodically

### Logging Security

**Sensitive Data Protection**:
- All tokens, passwords, and PII are hashed before logging (SHA-256)
- Audit logs use structured logging (slog)
- Never log raw tokens or credentials

**Log Storage**:
- Store logs securely with appropriate access controls
- Consider log encryption at rest
- Implement log retention policies

**Production Logging Configuration**:

DEBUG-level logging may expose detailed error information that could aid attackers.
Always disable DEBUG logging in production environments:

```go
// Production logging configuration
import "log/slog"

// Use INFO level or higher in production
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo, // Use LevelWarn or LevelError for minimal logging
}))

// Pass to OAuth server
server, err := oauth.NewServer(provider, store, store, store, config, logger)
```

**Recommended log levels by environment**:
| Environment | Level | Rationale |
|------------|-------|-----------|
| Development | DEBUG | Full debugging information |
| Staging | INFO | Operational insights without sensitive details |
| Production | INFO or WARN | Minimize exposure; sensitive errors are logged internally |

**Security-sensitive log entries** (DEBUG level only):
- Token prefixes (first 8 characters)
- PKCE validation details
- Authorization state lookups
- Refresh token rotation details

These are logged at DEBUG level and will NOT appear when using INFO or higher.

### Network Security

**HTTPS Required**:
- Production deployments must use HTTPS
- HTTP allowed only for localhost/loopback (development)
- Configure TLS 1.2 or higher

**Proxy Considerations**:
- Set `RateLimit.TrustProxy` only behind trusted proxies
- Validate X-Forwarded-For headers
- Use proper proxy configuration (X-Real-IP, X-Forwarded-For)

### OAuth Security

**PKCE Enforcement**:
- Only S256 code challenge method supported
- Plain method disabled (OAuth 2.1 requirement)
- Code verifier: 43-128 characters

**Token Rotation**:
- Refresh token rotation enabled by default
- Detects token theft via reuse detection
- Don't disable unless absolutely necessary

**Client Authentication**:
- Confidential clients must use client_secret_basic or client_secret_post
- Public clients can use "none" but must use PKCE
- Client type validation enforced

## Common Security Issues

### 1. Exposed Secrets

**Problem**: Credentials in code, logs, or version control

**Solution**:
- Use environment variables
- Use secret management tools (Vault, AWS Secrets Manager)
- Never commit secrets to Git
- Scan for secrets in CI/CD

### 2. Insufficient Rate Limiting

**Problem**: API abuse, brute force, DoS attacks

**Solution**:
- Configure appropriate rate limits
- Monitor rate limit violations
- Implement progressive rate limiting
- Consider geographic restrictions

### 3. Token Leakage

**Problem**: Tokens exposed in logs, error messages, or URLs

**Solution**:
- Never include tokens in URLs (use Authorization header)
- Use token hashing in logs
- Sanitize error messages
- Implement token expiration

### 4. Insecure Redirect URIs

**Problem**: Open redirects, redirect URI manipulation

**Solution**:
- Validate all redirect URIs during registration
- Exact matching of redirect URIs (no wildcards)
- Block dangerous schemes (javascript:, data:, file:)
- Validate custom schemes

### 5. Missing HTTPS

**Problem**: Token interception via man-in-the-middle attacks

**Solution**:
- Enforce HTTPS in production
- Use HSTS headers
- Configure proper TLS settings
- Validate certificates

## Security Checklist

Before deploying to production:

- [ ] HTTPS configured with valid certificates
- [ ] Encryption key generated and stored securely
- [ ] Rate limiting configured appropriately
- [ ] Audit logging enabled and monitored
- [ ] Client registration access token configured
- [ ] Refresh token rotation enabled
- [ ] Log aggregation and monitoring set up
- [ ] Security headers configured (HSTS, CSP, etc.)
- [ ] Secrets stored in KMS or vault (not in code)
- [ ] Regular security updates scheduled
- [ ] Incident response plan documented
- [ ] Backup and recovery procedures tested
- [ ] Log level set to INFO or higher (DEBUG disabled)
- [ ] CORS configured with specific origins (not wildcard)
- [ ] MinStateLength at recommended default (32 characters)

## Dependencies

We regularly update dependencies to patch security vulnerabilities:

```bash
# Check for vulnerable dependencies
go list -json -m all | nancy sleuth

# Update dependencies
go get -u ./...
go mod tidy
```

Monitor:
- [Go vulnerability database](https://pkg.go.dev/vuln/)
- Dependabot alerts
- GitHub security advisories

## Contact

For security-related questions or concerns:

- **Email**: security@giantswarm.io
- **PGP Key**: Available on request
- **Response Time**: Within 48 hours

For general questions, use:
- GitHub Discussions
- GitHub Issues (non-security)

---

**Last Updated**: 2025-11-23

We review and update this security policy quarterly.

