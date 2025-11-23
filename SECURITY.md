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
   encKey, _ := oauth.GenerateEncryptionKey()
   Security: oauth.SecurityConfig{
       EncryptionKey: encKey,
   }
   ```

2. **Store Encryption Keys Securely**:
   - Use a Key Management Service (KMS) like AWS KMS, Google Cloud KMS, or HashiCorp Vault
   - Never commit encryption keys to version control
   - Rotate keys periodically

3. **Enable Audit Logging**:
   ```go
   Security: oauth.SecurityConfig{
       EnableAuditLogging: true, // Enabled by default
   }
   ```

4. **Configure Rate Limiting**:
   ```go
   RateLimit: oauth.RateLimitConfig{
       Rate: 10,        // Adjust based on your threat model
       Burst: 20,
       UserRate: 100,
       UserBurst: 200,
   }
   ```

5. **Use HTTPS in Production**:
   - The library enforces HTTPS for non-localhost URLs
   - Use TLS 1.2 or higher
   - Configure proper certificate validation

6. **Secure Client Registration**:
   ```go
   Security: oauth.SecurityConfig{
       AllowPublicClientRegistration: false,
       RegistrationAccessToken: "secure-random-token",
       MaxClientsPerIP: 10,
   }
   ```

7. **Monitor Audit Logs**:
   - Set up log aggregation and monitoring
   - Alert on security events (rate limits, token reuse, failed auth)
   - Review logs regularly for suspicious activity

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

