# Silent Authentication

This guide explains how to use OIDC prompt parameters for silent re-authentication flows, enabling MCP clients to refresh tokens seamlessly without user interaction.

## Overview

Silent authentication allows clients to attempt token refresh without displaying any login UI when the user already has an active session at the Identity Provider (IdP). This is the same pattern used by tools like Teleport's `tsh kube login` for seamless re-authentication.

### How It Works

1. Client builds authorization URL with `prompt=none`
2. Browser opens briefly to the IdP
3. IdP recognizes existing session and immediately redirects back with authorization code
4. No user interaction required - no account selection, no consent screen
5. Client exchanges code for new tokens

If no IdP session exists, the IdP returns an error (`login_required`, `consent_required`, or `interaction_required`) and the client falls back to interactive login.

## OIDC Parameters Supported

The `AuthorizationURLOptions` struct supports all standard OIDC authentication request parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `prompt` | Controls authentication UX | `none`, `login`, `consent`, `select_account` |
| `login_hint` | Pre-fills username/email field | `user@example.com` |
| `max_age` | Maximum authentication age (seconds) | `3600` (1 hour) |
| `acr_values` | Authentication context class references | `urn:mace:incommon:iap:silver` |
| `id_token_hint` | Previously issued ID token as session hint | JWT string |
| `Extra` | Additional custom parameters | `map[string]string` |

### Prompt Values

| Value | Behavior |
|-------|----------|
| `none` | Silent authentication - no UI displayed. Returns error if login or consent required. |
| `login` | Force re-authentication even if session exists. |
| `consent` | Force consent even if previously granted. |
| `select_account` | Force account selection even if only one account. |

Multiple values can be combined with spaces: `login consent`

## Usage Example

### Building Authorization URLs with Silent Auth

```go
import "github.com/giantswarm/mcp-oauth/providers"

// Attempt silent re-authentication
opts := &providers.AuthorizationURLOptions{
    Prompt:    "none",
    LoginHint: "user@example.com", // Optional: hint about which user
}

authURL := provider.AuthorizationURL(
    state,
    pkceChallenge,
    "S256",
    []string{"openid", "email", "profile"},
    opts,
)

// Redirect user to authURL
```

### Handling Silent Auth Failures

Silent authentication can fail when:
- No active session at the IdP (`login_required`)
- User hasn't granted required scopes (`consent_required`)
- IdP needs user interaction (`interaction_required`)
- Multiple accounts and none selected (`account_selection_required`)

Use `IsSilentAuthError()` to detect these failures and fall back to interactive login:

```go
import oauth "github.com/giantswarm/mcp-oauth"

func handleCallback(w http.ResponseWriter, r *http.Request) {
    // Parse callback parameters
    q := r.URL.Query()
    result := oauth.ParseCallbackQuery(
        q.Get("code"),
        q.Get("state"),
        q.Get("error"),
        q.Get("error_description"),
        q.Get("error_uri"),
    )

    // Check for errors
    if err := result.Err(); err != nil {
        if oauth.IsSilentAuthError(err) {
            // Silent auth failed - fall back to interactive login
            log.Info("Silent auth failed, starting interactive login")
            startInteractiveLogin(w, r)
            return
        }
        // Handle other errors
        handleError(w, err)
        return
    }

    // Success - exchange code for tokens
    token, err := server.ExchangeAuthorizationCode(ctx, result.Code, ...)
}
```

### Complete Silent Auth Flow

Here's a complete example of implementing silent re-authentication with fallback:

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "log/slog"
    "net/http"

    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/providers"
)

type AuthHandler struct {
    provider providers.Provider
    server   *oauth.Server
    logger   *slog.Logger
}

// TrySilentAuth attempts silent authentication first
func (h *AuthHandler) TrySilentAuth(w http.ResponseWriter, r *http.Request, userEmail string) {
    state := generateSecureState()
    challenge, verifier := newPKCEPair()

    // First, try silent auth
    opts := &providers.AuthorizationURLOptions{
        Prompt:    "none",
        LoginHint: userEmail,
    }

    authURL := h.provider.AuthorizationURL(
        state,
        challenge,
        "S256",
        []string{"openid", "email", "profile"},
        opts,
    )

    // Store state and PKCE verifier for the callback
    h.storeAuthState(state, verifier, true) // true = silent attempt

    http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    result := oauth.ParseCallbackQuery(
        q.Get("code"),
        q.Get("state"),
        q.Get("error"),
        q.Get("error_description"),
        q.Get("error_uri"),
    )

    authState := h.getAuthState(result.State)

    if err := result.Err(); err != nil {
        if oauth.IsSilentAuthError(err) && authState.WasSilentAttempt {
            // Silent auth failed - try interactive login
            h.logger.Info("silent auth failed, falling back to interactive",
                "error", err.Error())
            h.startInteractiveLogin(w, r, authState.UserEmail)
            return
        }
        h.handleError(w, err)
        return
    }

    // Success!
    h.exchangeCodeAndComplete(w, r, result.Code, authState)
}

func (h *AuthHandler) startInteractiveLogin(w http.ResponseWriter, r *http.Request, userEmail string) {
    state := generateSecureState()
    challenge, verifier := newPKCEPair()

    // Interactive login - no prompt=none
    opts := &providers.AuthorizationURLOptions{
        LoginHint: userEmail, // Still provide hint for convenience
    }

    authURL := h.provider.AuthorizationURL(
        state,
        challenge,
        "S256",
        []string{"openid", "email", "profile"},
        opts,
    )

    h.storeAuthState(state, verifier, false) // false = interactive

    http.Redirect(w, r, authURL, http.StatusFound)
}

// newPKCEPair returns an RFC 7636 S256 PKCE challenge and its verifier.
// The verifier is the raw secret to keep server-side; the challenge is
// what's sent in the authorization request.
func newPKCEPair() (challenge, verifier string) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        panic(err) // crypto/rand must not fail
    }
    verifier = base64.RawURLEncoding.EncodeToString(b)
    sum := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(sum[:])
    return challenge, verifier
}
```

The helper uses `crypto/rand`, `crypto/sha256`, and `encoding/base64` from the standard library. Keep the verifier in your own per-flow state (the `authState` map above) and pass it to `Server.ExchangeAuthorizationCode` when the callback fires.

## Error Types

### SilentAuthError

The `SilentAuthError` type represents errors from silent authentication attempts:

```go
type SilentAuthError struct {
    Code        string // login_required, consent_required, etc.
    Description string // Optional error description from IdP
}
```

### Error Constants

```go
const (
    ErrorCodeLoginRequired            = "login_required"
    ErrorCodeConsentRequired          = "consent_required"
    ErrorCodeInteractionRequired      = "interaction_required"
    ErrorCodeAccountSelectionRequired = "account_selection_required"
)
```

### Helper Functions

| Function | Description |
|----------|-------------|
| `IsSilentAuthError(err)` | Returns `true` if error indicates silent auth failed |
| `ParseOAuthError(code, desc)` | Parses OAuth error into appropriate error type |
| `ParseCallbackQuery(...)` | Creates `CallbackResult` from URL query parameters |

## Provider Support

| Provider | Silent Auth Support | Notes |
|----------|---------------------|-------|
| Google | Full | All OIDC parameters supported |
| Azure AD | Full | All OIDC parameters supported |
| Okta | Full | All OIDC parameters supported |
| Auth0 | Full | All OIDC parameters supported |
| Keycloak | Full | All OIDC parameters supported |
| Dex | **None** | Does not honor `prompt=none` - see [Dex Limitation](#dex-limitation-prompt-none-not-supported) |
| GitHub | Partial | Uses `login` parameter instead of `prompt` |
| Mock | Full | For testing |

### Dex Limitation: `prompt=none` Not Supported

**Silent re-authentication using `prompt=none` does not work when mcp-oauth forwards to Dex.** This is a known Dex limitation, not an mcp-oauth bug.

#### Background

mcp-oauth correctly:
1. Accepts `prompt`, `login_hint`, and `id_token_hint` parameters in authorization requests
2. Forwards these parameters to the upstream IdP (Dex)
3. Provides `ApplyAuthorizationURLOptions()` helper for clients

However, **Dex does not honor `prompt=none`**:
- Dex doesn't maintain browser sessions between requests
- Dex ignores `prompt=none` and shows its login UI anyway
- Current Dex versions do not return `login_required` error as required by the OIDC spec

#### Related Dex Issues

- [dexidp/dex#990](https://github.com/dexidp/dex/issues/990) - Original feature request (2017, still open)
- [dexidp/dex#4325](https://github.com/dexidp/dex/pull/4325) - PR to check for `prompt=none` (2025, open)
- [dexidp/dex#4086](https://github.com/dexidp/dex/pull/4086) - PR to respect `promptType=none` (2025, open)

#### Impact

When mcp-oauth is configured to use Dex as the upstream IdP:
- `prompt=none` is forwarded to Dex but ignored
- Users must always interact with the browser to complete login
- Silent re-authentication falls back to interactive login

#### Workaround

If Dex uses an OIDC connector (e.g., Azure AD), the upstream IdP may have an active session. While Dex still requires user interaction to proceed through its UI, the upstream IdP won't require re-entering credentials.

#### Recommendation

If your use case requires true silent re-authentication:
1. Use a direct OIDC provider (Google, Azure AD, Okta, Auth0, Keycloak) instead of Dex
2. Monitor the Dex issues above for future `prompt=none` support

### GitHub Notes

GitHub doesn't implement the OIDC `prompt` parameter. Instead:
- `login_hint` is mapped to GitHub's `login` parameter
- Silent authentication is not supported (GitHub always shows UI)

## HTTP-Level Parameter Forwarding (Proxy Mode)

When mcp-oauth acts as an OAuth proxy (receiving authorization requests from clients and forwarding them to an upstream IdP), it automatically extracts and forwards all OIDC parameters from the incoming HTTP request to the upstream provider.

### Supported Query Parameters

The `/authorize` endpoint extracts and forwards:

| Query Parameter | Forward Behavior | Validation |
|-----------------|------------------|------------|
| `prompt` | Forwarded if valid | Whitelist: `none`, `login`, `consent`, `select_account` (max 128 chars) |
| `login_hint` | Forwarded as-is | Length limit: 256 characters |
| `id_token_hint` | Forwarded as-is | Length limit: 64KB |
| `max_age` | Parsed as integer | Non-negative integers only; invalid values silently ignored |
| `acr_values` | Forwarded as-is | Length limit: 1024 characters |

### Security: Input Validation

All OIDC parameters are validated before forwarding to provide defense-in-depth:

1. **Length Limits**: Each parameter has a maximum length to prevent DoS attacks via oversized payloads
2. **Prompt Whitelist**: Only valid OIDC prompt values are forwarded; unknown values are rejected
3. **Silent Rejection**: Invalid or oversized parameters are silently ignored (not forwarded), matching OIDC spec behavior where the IdP handles defaults

Parameters that fail validation are **not forwarded** to the upstream IdP, and no error is returned to the client. This follows the principle of being strict in what we accept while allowing the IdP to apply its own defaults.

### Security: Trust Model

When using mcp-oauth as an OAuth proxy, the following trust model applies:

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| **Upstream IdP** | Trusted | The IdP is assumed to properly validate all OIDC parameters, handle malformed inputs safely, and not be vulnerable to parameter injection |
| **Client Application** | Untrusted | Client-provided parameters are validated for length and content before forwarding |
| **Network** | Assumed Secure | TLS is required for all IdP communication |

**Important**: mcp-oauth performs input validation as defense-in-depth, but the upstream IdP is ultimately responsible for:
- Validating parameter semantics (e.g., checking if `prompt=none` is allowed for the client)
- Handling authentication/consent requirements
- Returning appropriate errors for invalid requests

If you're using mcp-oauth with an IdP that may not properly validate inputs, consider implementing additional validation at the ingress layer.

### Example Client Request

A client can include OIDC parameters in the authorization request:

```
GET /authorize?client_id=abc123
    &redirect_uri=https://app.example.com/callback
    &response_type=code
    &scope=openid+profile+email
    &state=xyz789
    &code_challenge=...
    &code_challenge_method=S256
    &prompt=none
    &login_hint=user@example.com
    &max_age=3600
```

mcp-oauth will forward `prompt=none`, `login_hint=user@example.com`, and `max_age=3600` to the upstream IdP.

### Use Case: Aggregator Proxy

This is particularly useful when mcp-oauth is used as an aggregator proxy (like muster) that sits between MCP clients and upstream identity providers. Clients can:

1. Send `prompt=none` for silent re-authentication attempts
2. Include `login_hint` with the known user's email for better UX
3. Specify `max_age` to require fresh authentication for sensitive operations
4. Request specific `acr_values` for enhanced security (e.g., MFA)

The proxy transparently forwards these to the upstream IdP, enabling seamless silent authentication flows through the proxy.

## Best Practices

### 1. Always Have a Fallback

Silent auth can fail for many reasons. Always implement an interactive fallback:

```go
if oauth.IsSilentAuthError(err) {
    return startInteractiveLogin(w, r)
}
```

### 2. Use login_hint for Better UX

When you know the user's email, provide it as a hint:

```go
opts := &providers.AuthorizationURLOptions{
    Prompt:    "none",
    LoginHint: storedUserEmail,
}
```

### 3. Use id_token_hint for Stronger Session Binding

For more reliable silent auth, pass the previously issued ID token:

```go
opts := &providers.AuthorizationURLOptions{
    Prompt:      "none",
    IDTokenHint: previousIDToken,
}
```

### 4. Consider max_age for Security

Use `max_age` to require re-authentication if the IdP session is too old:

```go
maxAge := 3600 // 1 hour
opts := &providers.AuthorizationURLOptions{
    Prompt: "none",
    MaxAge: &maxAge,
}
```

### 5. Handle All Error Cases

Don't just check for silent auth errors - handle other failures too:

```go
if err := result.Err(); err != nil {
    if oauth.IsSilentAuthError(err) {
        return startInteractiveLogin(w, r)
    }
    // Log and handle other errors appropriately
    log.Error("OAuth callback error", "error", err)
    return showErrorPage(w, "Authentication failed")
}
```

## Migrating Existing Code

If you have existing code using `AuthorizationURL`, add `nil` as the last parameter:

```go
// Before
authURL := provider.AuthorizationURL(state, challenge, "S256", scopes)

// After (no behavior change)
authURL := provider.AuthorizationURL(state, challenge, "S256", scopes, nil)

// After (with silent auth)
authURL := provider.AuthorizationURL(state, challenge, "S256", scopes, &providers.AuthorizationURLOptions{
    Prompt: "none",
})
```

## Accepting a Forwarded ID Token Directly

Silent authentication is one half of the "upstream-IdP pass-through" story. The other half is the case where a trusted intermediary (an aggregator, a gateway, an AgentCore Runtime bridge) already holds a valid ID token from the upstream IdP and presents it as the Bearer credential to this server. `Server.AcceptForwardedIDToken` is the library entry point for that case.

Unlike the auth-code flow, this path never touches the authorization_code grant — there is no family, no refresh token, no `SessionCreationHandler` firing, and no entry created in `TokenStore`. It is a pure validation function that returns the verified claims plus a deterministic session identifier.

### When to use it

Use `AcceptForwardedIDToken` when:

- An upstream intermediary (muster, a bridge, a sidecar) receives an MCP request with a Bearer token it obtained from the same IdP this server trusts.
- The intermediary wants to hand the token directly to this server rather than translate it into a server-issued access token.
- This server needs to attribute the request to the original end user (per-user RBAC, audit) without running its own auth-code flow.

The classic deployment is the Bedrock AgentCore Runtime bridge: user authenticates to Dex, gets an ID token, presents it to the bridge, bridge forwards it unchanged to an MCP server configured with Dex's audience in `Config.TrustedAudiences`.

### Preconditions

1. The configured `providers.Provider` implements `providers.JWKSProvider`. GitHub's provider does not qualify (OAuth 2.0 only) — the function returns a clear error in that case.
2. `Config.TrustedAudiences` contains the audience the upstream IdP minted the token for.
3. The provider's `IssuerURL()` matches the JWT's `iss` claim (the signature check requires this anyway).

### Usage

```go
acc, err := oauthServer.AcceptForwardedIDToken(r.Context(), bearerToken)
if err != nil {
    if errors.Is(err, server.ErrTrustedAudienceMismatch) {
        // Audience is not in TrustedAudiences → 401.
    }
    // Other errors (sig_invalid, iss_mismatch, expired, no_jwks, parse_error) → 401.
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}

// acc.SessionID is "ext-<hex16>", deterministic from the token.
// acc.Subject is the validated `sub` claim.
// acc.UserInfo.TokenSource == providers.TokenSourceSSO.
// acc.ExpiresAt matches the JWT exp — the library does NOT refresh forwarded tokens.
```

### What it does NOT do

- **Does not fire `SessionCreationHandler`.** That handler is gated on `RefreshTokenFamilyStore` and the authorization-code family lifecycle. Forwarded tokens have neither. Callers that want a "first time we've seen this session" hook should build that on top with their own seen-set keyed on `acc.SessionID` and TTL bounded by `acc.ExpiresAt`.
- **Does not mirror the token into `TokenStore`.** `TokenStore.SaveToken` is keyed by userID; two concurrent bridged sessions for the same user would overwrite each other. Aggregators that need to retrieve the forwarded token later (for example, to attach it to downstream MCP calls) must store it in their own structure.
- **Does not refresh expired tokens.** When the JWT expires, validation fails and the caller must propagate 401 so the MCP client re-authenticates against the upstream IdP.

### Aggregator fan-out

When the caller is itself an aggregator (muster fanning out to mcp-prometheus, mcp-kubernetes, mcp-opsgenie) and forwards the same token to every downstream, each downstream independently calls `AcceptForwardedIDToken` and derives the **same** `SessionID`. That gives cross-hop audit-log correlation without coordination — see the session-ID section in [security.md](./security.md) for the correlation property, the `Config.SessionIDHMACKey` escape hatch for multi-tenant isolation, and the operator caveat around key agreement.

## References

- [OpenID Connect Core 1.0 - Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [OpenID Connect Core 1.0 - Authentication Error Response](https://openid.net/specs/openid-connect-core-1_0.html#AuthError)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 8725 - JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
