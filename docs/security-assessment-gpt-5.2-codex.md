## Security Assessment Report (GPT-5.2-Codex)

Date: 2026-01-19
Repository: `mcp-oauth`
Version scope: Current worktree snapshot

### Executive Summary

This review finds the library to be security-focused and largely aligned with OAuth 2.1 best practices (PKCE by default, strict redirect URI validation, SSRF protections, token rotation, and security logging). One high-severity finding remains: the refresh token grant does not enforce client authentication or bind refresh tokens to the requesting client. This weakens confidentiality for confidential clients and enables cross-client refresh if a token leaks.

### Scope

Reviewed components:
- OAuth server flow implementation (`server/`, `handler.go`)
- Security controls (`security/`)
- Storage interfaces and implementations (`storage/`)
- OIDC discovery and JWKS validation (`providers/oidc/`)
- Configuration defaults and validation (`server/config*.go`)
- Security documentation (`docs/security.md`, `SECURITY_ARCHITECTURE.md`)

Out of scope:
- External provider behavior (Google, GitHub, Dex) beyond integration points
- Runtime configuration and deployment environment
- External tooling (SAST/DAST, dependency scanning)

### Methodology

Static code review with a focus on:
- OAuth 2.1 compliance and threat model alignment
- Token lifecycle security (issuance, refresh, revocation)
- SSRF and redirect URI validation
- Cryptographic use and at-rest protections
- Logging, rate limiting, and observability controls

### Findings

#### High: Refresh token grant lacks client authentication and binding

The refresh token endpoint does not require client authentication, and refresh operations are not bound to the requesting client ID. A refresh token holder can refresh without proving client identity, which is a material risk for confidential clients and enables cross-client use if tokens leak.

Evidence:
- `handler.go`: refresh grant validates client credentials only if Basic Auth is present.
- `server/flows.go`: refresh token logic does not validate `client_id` against token metadata or token family ownership.

Impact:
- Confidential clients are not protected against refresh token replay across clients.
- Enables silent token renewal by any party with the refresh token.

Recommendation:
- Require client authentication for confidential clients on refresh.
- Enforce refresh token binding to `client_id` (via token metadata or family metadata).
- Return `invalid_client` or `invalid_grant` on mismatch or missing credentials.

### Strengths and Positive Controls

- Secure defaults: PKCE required, S256-only, HTTPS enforcement, strict redirect URI validation, DNS validation with strict mode.
- Defense in depth: dual-layer state parameters, short-lived one-time authorization codes, provider-leg PKCE.
- Refresh token rotation with reuse detection and revocation for attack response.
- Strong SSRF mitigations for redirect URIs, CIMD metadata fetch, OIDC discovery, and JWKS fetch.
- Optional AES-256-GCM token encryption at rest with OIDC extra field preservation.
- Comprehensive security logging and event auditing with hashed PII.
- Security headers and cache-control protections on HTTP endpoints.

### Recommendations

1. Enforce refresh token client binding and authentication for confidential clients.
2. Treat encryption at rest as production baseline (configure `SetEncryptor`).
3. Require storage implementations to support token revocation and family tracking.
4. Keep all secure defaults enabled unless a documented compatibility need exists.
5. When enabling private IP allowances for JWKS or CIMD, add network egress controls.

### Limitations

This report is based on static analysis of the repository. It does not include:
- Dynamic testing, threat simulation, or penetration testing.
- External dependency or container scanning.
- Provider-side security posture verification.

### Appendix: Referenced Documents

- `docs/security.md`
- `SECURITY_ARCHITECTURE.md`
- `SECURITY.md`
