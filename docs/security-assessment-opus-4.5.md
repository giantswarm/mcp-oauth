# Security Assessment Report: mcp-oauth

**Assessment Conducted By:** Claude Opus 4.5 (Anthropic)  
**Assessment Date:** January 2026  
**Library Version:** OAuth 2.1 Authorization Server for MCP  
**Assessment Scope:** Full codebase security review

---

## Executive Summary

The `mcp-oauth` library demonstrates a **mature security posture** with OAuth 2.1 compliance as a core design principle. The library follows a "secure by default" philosophy, implements defense-in-depth, and addresses common OAuth vulnerabilities comprehensively. The codebase shows evidence of security-conscious development practices throughout.

**Overall Security Rating: Strong**

| Category | Rating | Notes |
|----------|--------|-------|
| Authentication & Authorization | Excellent | PKCE enforced, state validation, constant-time comparisons |
| Cryptography | Excellent | AES-256-GCM, proper nonce handling, bcrypt |
| Input Validation | Excellent | Comprehensive SSRF/redirect protection |
| Rate Limiting | Good | Multi-layer protection with LRU eviction |
| Security Headers | Excellent | Strict CSP, HSTS, anti-clickjacking |
| Audit Logging | Excellent | Comprehensive security event tracking |
| OAuth 2.1 Compliance | Full | All requirements implemented |

---

## 1. Authentication & Authorization Security

### 1.1 PKCE Implementation

**Rating: Excellent**

The library enforces PKCE (Proof Key for Code Exchange) by default with S256 only:

```go
// From server/config.go
// AllowPKCEPlain allows the 'plain' code_challenge_method (NOT RECOMMENDED)
// WARNING: The 'plain' method is insecure and deprecated in OAuth 2.1
AllowPKCEPlain bool // default: false

// RequirePKCE enforces PKCE for all authorization requests
// WARNING: Disabling this significantly weakens security
RequirePKCE bool // default: true
```

**Security Controls:**
- S256-only by default - The insecure "plain" method is disabled
- `RequirePKCE=true` by default - Cannot be bypassed without explicit configuration
- Public clients require PKCE - Additional protection via `AllowPublicClientsWithoutPKCE=false`
- PKCE validation uses SHA-256 with proper base64url encoding

### 1.2 State Parameter Validation

**Rating: Good**

CSRF protection via state parameter:

```go
// From server/config.go
// MinStateLength is the minimum length for state parameters to prevent
// timing attacks and ensure sufficient entropy for CSRF protection.
// OAuth 2.1 recommends at least 128 bits (16 bytes) of entropy.
MinStateLength int // default: 32 characters (192 bits of entropy)

// AllowNoStateParameter allows authorization requests without state.
// WARNING: Disabling state parameter validation weakens CSRF protection!
AllowNoStateParameter bool // default: false
```

**Security Controls:**
- Required by default (`AllowNoStateParameter=false`)
- Minimum length enforcement (32 characters = 192 bits entropy)
- Constant-time comparison using `crypto/subtle.ConstantTimeCompare`

### 1.3 Token Security

**Rating: Excellent**

**Cryptographically secure token generation:**

```go
// From server/server.go
const MinTokenBytes = 32 // 256 bits of entropy

func generateRandomToken() string {
    b := make([]byte, MinTokenBytes)
    if _, err := rand.Read(b); err != nil {
        // CRITICAL: System RNG failure - cannot generate secure tokens
        panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
    }
    return base64.RawURLEncoding.EncodeToString(b)
}
```

**Security Controls:**
- 32 bytes (256 bits) entropy - Exceeds NIST recommendations
- `crypto/rand` - Uses system's cryptographic RNG
- Panic on RNG failure - Fails safely rather than generating weak tokens
- Base64url encoding without padding for URL-safe tokens

**Refresh token rotation with reuse detection:**

```go
// From server/flows.go - OAuth 2.1 compliant reuse detection
func (s *Server) handleRefreshTokenReuseDetection(ctx context.Context, ...) error {
    family, famErr := familyStore.GetRefreshTokenFamily(ctx, refreshToken)
    // ... token family tracking with generation counters ...
    
    // Token is deleted but family exists → REUSE DETECTED!
    // Revoke entire token family
    if err := familyStore.RevokeRefreshTokenFamily(ctx, family.FamilyID); err != nil {
        s.Logger.Error("Failed to revoke token family", "error", err)
    }
    // Revoke all tokens for this user+client
    if err := s.RevokeAllTokensForUserClient(ctx, family.UserID, family.ClientID); err != nil {
        s.Logger.Error("Failed to revoke user tokens", "error", err)
    }
}
```

---

## 2. Encryption & Cryptography

### 2.1 Token Encryption at Rest

**Rating: Excellent**

AES-256-GCM implementation:

```go
// From security/encryption.go
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(e.key)
    gcm, err := cipher.NewGCM(block)
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
    // Prepend nonce to ciphertext for storage
    nonce = append(nonce, ciphertext...)
    return base64.StdEncoding.EncodeToString(nonce), nil
}
```

**Security Controls:**
- Random nonce per encryption - Proper nonce handling prevents reuse
- Key length validation - Exactly 32 bytes enforced
- Authenticated encryption - GCM provides confidentiality + integrity
- ID tokens (containing PII) are also encrypted

### 2.2 Client Secret Hashing

**Rating: Good**

```go
// From storage/memory/memory.go
func (s *Store) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error {
    // SECURITY: Always perform the same operations to prevent timing attacks
    hashToCompare := storage.DummyBcryptHash
    
    if err == nil {
        if client.ClientType == "public" {
            isPublicClient = true
        } else if client.ClientSecretHash != "" {
            hashToCompare = client.ClientSecretHash
        }
    }
    
    // ALWAYS perform bcrypt comparison (constant-time by design)
    bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(clientSecret))
}
```

**Security Controls:**
- bcrypt for password hashing (industry standard)
- Dummy hash comparison when client not found - Prevents timing attacks
- Constant-time operations throughout

---

## 3. Input Validation & Injection Prevention

### 3.1 Redirect URI Validation

**Rating: Excellent**

Comprehensive SSRF and open redirect protection with secure defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| `ProductionMode` | `true` | HTTPS required for non-loopback URIs |
| `DNSValidation` | `true` | Resolve hostnames to check IPs |
| `DNSValidationStrict` | `true` | Fail-closed on DNS failures |
| `ValidateRedirectURIAtAuthorization` | `true` | Re-validate at auth time (TOCTOU protection) |
| `AllowLocalhostRedirectURIs` | `false` | Loopback blocked by default |
| `AllowPrivateIPRedirectURIs` | `false` | RFC 1918 private IPs blocked |
| `AllowLinkLocalRedirectURIs` | `false` | 169.254.x.x blocked (cloud SSRF) |

**DNS rebinding protection:**

```go
// From providers/oidc/validation.go
func SSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        // Resolve the hostname to IP addresses
        ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
        
        // SECURITY: Validate ALL resolved IPs before attempting any connection
        for _, ip := range ips {
            if isPrivateOrRestrictedIP(ip) {
                return nil, fmt.Errorf("DNS rebinding attack detected: %q resolved to restricted IP %s", host, ip)
            }
        }
        // All IPs are safe, connect to the first one
        safeAddr := net.JoinHostPort(ips[0].String(), port)
        return dialer.DialContext(ctx, network, safeAddr)
    }
}
```

**Blocked dangerous URI schemes:**
- `javascript:` - XSS attacks via script execution
- `data:` - XSS attacks via inline content
- `file:` - Local filesystem access
- `vbscript:` - Legacy XSS (Internet Explorer)
- `blob:` - XSS via Blob URLs
- `ms-appx:` / `ms-appx-web:` - Windows app package access

### 3.2 Scope Validation

**Rating: Good**

```go
// From providers/oidc/validation.go
func ValidateScopes(scopes []string) error {
    // Check for empty scopes first
    for i, scope := range scopes {
        if scope == "" {
            return fmt.Errorf("scope at index %d is empty", i)
        }
    }
    // Validate size and length constraints
    return validateStringSlice(scopes, "scopes", 50, 256)
}
```

**Security Controls:**
- Maximum 50 scopes per request
- Maximum 256 characters per scope
- Empty scope detection
- Scope string length limit (default 1000 chars) to prevent DoS

### 3.3 JWT Algorithm Confusion Prevention

**Rating: Excellent**

```go
// From providers/oidc/jwt.go
// SECURITY: This explicitly checks the Method type (not just the "alg" header)
// to prevent algorithm confusion attacks (CVE-2015-9235)
func classifySigningMethod(token *jwt.Token) signingMethodType {
    switch token.Method.(type) {
    case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
        return signingMethodRSA
    case *jwt.SigningMethodECDSA:
        return signingMethodECDSA
    default:
        return signingMethodUnknown // Rejects HMAC and other methods
    }
}
```

This correctly prevents algorithm confusion attacks where an attacker changes the `alg` header to `HS256` and signs with the public key.

### 3.4 Connector ID Validation (Dex Provider)

```go
// From providers/oidc/validation.go
var connectorIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func ValidateConnectorID(connectorID string) error {
    if !connectorIDRegex.MatchString(connectorID) {
        return fmt.Errorf("connector_id contains invalid characters")
    }
    if len(connectorID) > 64 {
        return fmt.Errorf("connector_id exceeds maximum length of 64 characters")
    }
    return nil
}
```

---

## 4. Rate Limiting & DoS Protection

### 4.1 Rate Limiting Implementation

**Rating: Good**

Token bucket algorithm with LRU eviction:

```go
// From security/ratelimit.go
func (rl *RateLimiter) Allow(identifier string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    if elem, exists := rl.limiters[identifier]; exists {
        rl.lruList.MoveToFront(elem)
        entry := elem.Value.(*rateLimiterEntry)
        entry.lastAccess = now
        return entry.limiter.Allow()
    }
    
    // Need to create new limiter - check if at capacity
    if rl.maxEntries > 0 && len(rl.limiters) >= rl.maxEntries {
        rl.evictLRU()  // Prevents unbounded memory growth
    }
    // ... create new limiter ...
}
```

**Multiple rate limiting layers:**

| Rate Limiter | Purpose |
|--------------|---------|
| IP-based | Protects all endpoints from brute force |
| User-based | Limits authenticated request volume |
| Client registration | Time-windowed limit (default 10/hour) |
| Security event | Prevents log flooding DoS |
| Metadata fetch | Per-domain limit for CIMD fetches |

### 4.2 Memory Exhaustion Protection

**Rating: Good**

```go
// From storage/memory/memory.go
const (
    maxFamilyMetadataEntries     = 10000  // Warning threshold
    hardMaxFamilyMetadataEntries = 50000  // Hard limit - blocks saves
)

// SECURITY: Enforce hard limit on family metadata
if currentCount >= hardMaxFamilyMetadataEntries {
    return fmt.Errorf("refresh token family metadata limit exceeded (%d entries)", currentCount)
}
```

**JWKS response limits:**

```go
// From providers/oidc/jwt.go
const (
    maxJWKSDocumentSize = 1024 * 1024  // 1MB
    maxJWKSKeyCount     = 100
)
```

---

## 5. Security Headers & CSP

### 5.1 HTTP Security Headers

**Rating: Excellent**

```go
// From security/headers.go
func SetSecurityHeaders(w http.ResponseWriter, serverURL string) {
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    w.Header().Set("Referrer-Policy", "no-referrer")
    
    // HSTS for HTTPS deployments
    if parsed.Scheme == "https" {
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    }
    
    // Prevent caching of sensitive responses
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
    w.Header().Set("Pragma", "no-cache")
}
```

### 5.2 CSP for Interstitial Pages

**Rating: Good**

Hash-based script allowlisting instead of `unsafe-inline`:

```go
// From security/headers.go
const InterstitialScriptHash = "sha256-BSPDdcxaKPs2IRkTMWvH7KxMRr/MuFv1HaDJlxd1UTI="

csp := "default-src 'none'; " +
       "script-src '" + InterstitialScriptHash + "'; " +
       "style-src 'unsafe-inline'; " +
       "img-src https: data:; " +
       "frame-ancestors 'none'"
```

**Note:** `style-src 'unsafe-inline'` is necessary due to dynamic CSS (branding customization) but is an acceptable trade-off since CSS cannot execute arbitrary code.

---

## 6. Client IP Extraction

**Rating: Good**

Secure proxy header parsing:

```go
// From security/ip.go
func GetClientIP(r *http.Request, trustProxy bool, trustedProxyCount int) string {
    if trustProxy {
        if ip := extractIPFromXFF(r.Header.Get("X-Forwarded-For"), trustedProxyCount); ip != "" {
            return ip
        }
        if ip := extractIPFromXRealIP(r.Header.Get("X-Real-IP")); ip != "" {
            return ip
        }
    }
    return extractIPFromRemoteAddr(r.RemoteAddr)
}

// Client IP is at: len(ips) - trustedProxyCount - 1
func calculateClientIPIndex(numIPs, trustedProxyCount int) int {
    proxyCount := trustedProxyCount
    if proxyCount == 0 {
        proxyCount = 1
    }
    clientIndex := numIPs - proxyCount - 1
    if clientIndex < 0 {
        return 0
    }
    return clientIndex
}
```

**Security Controls:**
- `TrustProxy=false` by default - Secure default
- `TrustedProxyCount` configuration - Prevents X-Forwarded-For spoofing
- IP validation via `net.ParseIP`

---

## 7. Audit Logging

**Rating: Excellent**

Comprehensive security event logging:

| Event Type | Description | Severity |
|------------|-------------|----------|
| `token_issued` | Access token issued | Info |
| `token_refreshed` | Token refreshed | Info |
| `token_revoked` | Token revoked | Info |
| `auth_failure` | Authentication failure | Warning |
| `rate_limit_exceeded` | Rate limit violation | Warning |
| `authorization_code_reuse` | Code reuse attempt | Critical |
| `token_reuse_detected` | Refresh token reuse | Critical |
| `pkce_validation_failed` | PKCE validation failure | Warning |
| `scope_escalation_attempt` | Unauthorized scope request | High |
| `audience_mismatch` | RFC 8707 audience mismatch | Critical |

**Example audit event:**

```go
// From server/flows.go
s.Auditor.LogEvent(security.Event{
    Type:     security.EventAuthorizationCodeReuseDetected,
    UserID:   authCode.UserID,
    ClientID: clientID,
    Details: map[string]any{
        "severity":   "critical",
        "action":     "all_tokens_revoked",
        "oauth_spec": "OAuth 2.1 Section 4.1.2",
    },
})
```

---

## 8. OAuth 2.1 Compliance Summary

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| PKCE Required | **Compliant** | `RequirePKCE=true` default, S256 only |
| Refresh Token Rotation | **Compliant** | Automatic with family tracking |
| Reuse Detection | **Compliant** | Token family revocation on reuse |
| HTTPS Enforcement | **Compliant** | `ProductionMode=true` default |
| State Parameter | **Compliant** | Required by default with min length |
| Redirect URI Validation | **Compliant** | Comprehensive validation with DNS checks |
| Authorization Code One-Time Use | **Compliant** | Atomic check-and-mark with reuse detection |
| Token Binding (RFC 8707) | **Compliant** | Audience validation with `ResourceIdentifier` |

---

## 9. Areas for Improvement

### 9.1 Low Severity Issues

1. **CORS Wildcard Handling**
   - The library warns but allows `AllowedOrigins: ["*"]`
   - Consider enforcing `AllowWildcardOrigin: true` requirement

2. **Token Cleanup Timing**
   - Default cleanup interval (1 minute) could allow brief usage of expired tokens
   - Consider documenting this window in security guide

3. **Style CSP**
   - `style-src 'unsafe-inline'` is used for interstitial pages
   - Acceptable but could be improved with CSS-in-JS hash approach

### 9.2 Recommendations

1. **Key Rotation Documentation**
   - Add documentation for encryption key rotation procedures
   - Consider built-in key rotation support with key versioning

2. **Certificate Pinning Option**
   - For high-security deployments, consider optional certificate pinning for JWKS/provider endpoints

3. **Security Headers Customization**
   - Allow customization of security headers for specific deployment requirements
   - Consider adding `Permissions-Policy` header

4. **Timing Attack Surface**
   - Review all string comparisons for potential timing leaks
   - Consider `subtle.ConstantTimeCompare` in additional locations

---

## 10. Security Checklist for Deployments

### Required for Production

- [ ] Use HTTPS (TLS 1.2+ recommended)
- [ ] Configure `Issuer` with HTTPS URL
- [ ] Use external secret manager for credentials (not environment variables)
- [ ] Enable token encryption (`SetEncryptor()`)
- [ ] Configure audit logging (`SetAuditor()`)
- [ ] Set `RegistrationAccessToken` or disable public registration
- [ ] Review and configure rate limiters appropriately

### Recommended

- [ ] Enable all rate limiters (IP, user, registration, security event)
- [ ] Configure `TrustedProxyCount` if behind reverse proxy
- [ ] Set appropriate token TTLs for your security requirements
- [ ] Monitor audit logs for security events
- [ ] Set up alerts for `authorization_code_reuse` and `token_reuse_detected`
- [ ] Review `SupportedScopes` configuration
- [ ] Configure `ResourceIdentifier` for multi-resource deployments

### High-Security Environments

- [ ] Keep `DNSValidation=true` and `DNSValidationStrict=true`
- [ ] Keep `ValidateRedirectURIAtAuthorization=true`
- [ ] Set `HideEndpointPathInErrors=true`
- [ ] Review `TrustedAudiences` carefully for SSO scenarios
- [ ] Consider custom `InterstitialConfig` for branded security pages

---

## 11. Conclusion

The `mcp-oauth` library demonstrates strong security practices throughout its implementation:

**Key Strengths:**
- Secure-by-default configuration philosophy
- Comprehensive OAuth 2.1 compliance
- Defense-in-depth with multiple security layers
- Proper cryptographic implementations (AES-256-GCM, bcrypt, crypto/rand)
- Extensive SSRF and redirect validation with DNS rebinding protection
- Well-designed audit logging with security event tracking
- JWT algorithm confusion attack prevention
- Constant-time operations for sensitive comparisons

**Assessment:** This library is suitable for production use in security-sensitive environments. The developers have clearly prioritized security and followed industry best practices. The codebase shows evidence of security-conscious development with comprehensive documentation of security considerations.

**Recommendation:** Approved for use with standard deployment hardening practices.

---

*This assessment was conducted through static code analysis by Claude Opus 4.5. A complete security audit would include dynamic testing, penetration testing, and formal threat modeling.*
