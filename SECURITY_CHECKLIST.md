# Security Review Checklist

This checklist should be completed for all pull requests that modify security-sensitive code, including authentication, authorization, cryptography, input validation, or network communication.

## Pre-Merge Security Review

### 1. Secrets Management ✓

- [ ] No hardcoded secrets, passwords, API keys, or tokens
- [ ] Secrets loaded from environment variables or secure vaults
- [ ] Test files use mock/fake credentials only (never real secrets)
- [ ] Secret values never logged or included in error messages

### 2. SSRF (Server-Side Request Forgery) Protection ✓

- [ ] All external URLs validated with `ValidateIssuerURL()` or equivalent
- [ ] Private IP ranges blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- [ ] Loopback addresses blocked (127.0.0.1, ::1)
- [ ] Link-local addresses blocked (169.254.169.254 - metadata services)
- [ ] HTTPS enforced for all external communications
- [ ] HTTP redirects validated to prevent SSRF via redirects
- [ ] `skipValidation` flag ONLY used in test files with `NewTestDiscoveryClient`

### 3. Input Validation ✓

- [ ] All external inputs validated (query params, headers, request bodies)
- [ ] String inputs have maximum length limits (prevent DoS)
- [ ] Array/slice inputs have maximum count limits (prevent memory exhaustion)
- [ ] Numeric inputs have range validation
- [ ] Regex patterns use `^` and `$` anchors
- [ ] Character whitelisting used instead of blacklisting
- [ ] SQL/NoSQL inputs properly parameterized (if applicable)

### 4. Timeout & Resource Management ✓

- [ ] All external HTTP requests have timeouts (default: 30s)
- [ ] Context deadlines enforced on all I/O operations
- [ ] Database queries have timeouts (if applicable)
- [ ] Maximum request/response body sizes enforced
- [ ] Goroutines have proper cleanup/cancellation
- [ ] File descriptors and connections properly closed (defer or explicit)

### 5. Error Handling & Information Disclosure ✓

- [ ] Error messages don't leak sensitive information to clients
- [ ] Stack traces not exposed in production error responses
- [ ] Internal errors logged but not returned to untrusted clients
- [ ] HTTP status codes appropriate (don't leak existence of resources)
- [ ] Debug information only available in development mode

### 6. Authentication & Authorization ✓

- [ ] OAuth 2.1 flows properly implemented with PKCE
- [ ] State parameter validated for CSRF protection
- [ ] Authorization codes are one-time use only
- [ ] Tokens have appropriate expiration times
- [ ] Refresh token rotation implemented correctly
- [ ] Token revocation works as expected
- [ ] Session fixation attacks prevented

### 7. Cryptography ✓

- [ ] Use standard crypto libraries (crypto/*, golang.org/x/crypto)
- [ ] No custom/homemade crypto algorithms
- [ ] Random values use crypto/rand (not math/rand)
- [ ] PKCE verifiers are cryptographically random (43-128 chars)
- [ ] Hash functions are collision-resistant (SHA-256+)
- [ ] Encryption uses authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- [ ] TLS 1.2+ required, weak cipher suites disabled

### 8. Rate Limiting & DoS Protection ✓

- [ ] Rate limiting implemented for sensitive endpoints
- [ ] Client registration has rate limits
- [ ] Maximum request body sizes enforced
- [ ] Maximum array/slice sizes enforced
- [ ] Maximum string lengths enforced
- [ ] Request timeouts prevent resource exhaustion
- [ ] Pagination limits enforced (if applicable)

### 9. Logging & Monitoring ✓

- [ ] Security events logged via audit interface
- [ ] Authentication failures logged
- [ ] Authorization failures logged
- [ ] Rate limit violations logged
- [ ] Token revocations logged
- [ ] No sensitive data in logs (tokens, passwords, secrets)
- [ ] Logs include correlation IDs for debugging

### 10. Dependencies ✓

- [ ] All dependencies are up-to-date (check with `go list -m -u all`)
- [ ] No known vulnerabilities in dependencies (check with `govulncheck`)
- [ ] Dependencies from trusted sources only
- [ ] Minimal dependency footprint (avoid unnecessary deps)
- [ ] Transitive dependencies reviewed

### 11. Code Quality ✓

- [ ] Linter passes (`make lint`)
- [ ] Tests pass (`make test`)
- [ ] Code coverage ≥ 80% for new code
- [ ] No data races (`go test -race`)
- [ ] No goroutine leaks (verify with `-count=1000` tests)

### 12. HTTP Security Headers ✓

- [ ] `X-Request-ID` header added for request tracking
- [ ] `X-Content-Type-Options: nosniff` set
- [ ] Appropriate CORS headers (if applicable)
- [ ] No sensitive data in HTTP headers

## Provider-Specific Security

### Dex Provider

- [ ] `connector_id` validated with character whitelist
- [ ] Groups claim validated (max 100 groups, max 256 chars each)
- [ ] Refresh token rotation handled correctly
- [ ] Discovery endpoint cached with TTL
- [ ] Revocation endpoint gracefully degrades if unavailable

### Google Provider

- [ ] Scopes validated before use
- [ ] User info endpoint requires valid access token
- [ ] Token expiry properly checked

### Custom Providers

- [ ] Provider implements all required interface methods
- [ ] Provider validates all inputs from external systems
- [ ] Provider enforces HTTPS
- [ ] Provider handles errors gracefully

## Test Security

- [ ] Test-only security bypasses have build tags or clear documentation
- [ ] `NewTestDiscoveryClient` only used in `*_test.go` files
- [ ] `skipValidation` only set to `true` in test code
- [ ] Test servers use `httptest.Server` (not real external services)
- [ ] No test credentials committed to repository

## Documentation

- [ ] Security considerations documented in code comments
- [ ] README updated if new security features added
- [ ] SECURITY.md updated if new vulnerability class addressed
- [ ] Breaking security changes noted in CHANGELOG.md

## Deployment

- [ ] HTTPS enforced in production (no `AllowInsecureHTTP`)
- [ ] Secrets managed via environment variables or vault
- [ ] Health check endpoints don't leak sensitive information
- [ ] Monitoring and alerting configured for security events

---

## Sign-Off

By checking this box, I confirm that:
- [ ] I have reviewed all items in this checklist
- [ ] All applicable items have been addressed
- [ ] Security-sensitive changes have been tested
- [ ] I understand the security implications of this change

**Reviewer:** ____________________  
**Date:** ____________________

---

## Automated Checks

The following are automatically enforced by CI/CD:

- ✅ Linter passes (including forbidigo security rules)
- ✅ All tests pass
- ✅ No vulnerabilities in dependencies (govulncheck)
- ✅ Code coverage meets minimum threshold
- ✅ No data races detected

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Go Security Practices](https://golang.org/doc/security/)
- [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

