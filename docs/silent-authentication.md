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
    pkce := oauth.GeneratePKCE()

    // First, try silent auth
    opts := &providers.AuthorizationURLOptions{
        Prompt:    "none",
        LoginHint: userEmail,
    }

    authURL := h.provider.AuthorizationURL(
        state,
        pkce.Challenge,
        "S256",
        []string{"openid", "email", "profile"},
        opts,
    )

    // Store state and PKCE for callback
    h.storeAuthState(state, pkce, true) // true = silent attempt

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
    pkce := oauth.GeneratePKCE()

    // Interactive login - no prompt=none
    opts := &providers.AuthorizationURLOptions{
        LoginHint: userEmail, // Still provide hint for convenience
    }

    authURL := h.provider.AuthorizationURL(
        state,
        pkce.Challenge,
        "S256",
        []string{"openid", "email", "profile"},
        opts,
    )

    h.storeAuthState(state, pkce, false) // false = interactive

    http.Redirect(w, r, authURL, http.StatusFound)
}
```

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
| Dex | Full | All OIDC parameters supported |
| GitHub | Partial | Uses `login` parameter instead of `prompt` |
| Mock | Full | For testing |

### GitHub Notes

GitHub doesn't implement the OIDC `prompt` parameter. Instead:
- `login_hint` is mapped to GitHub's `login` parameter
- Silent authentication is not supported (GitHub always shows UI)

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

## References

- [OpenID Connect Core 1.0 - Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [OpenID Connect Core 1.0 - Authentication Error Response](https://openid.net/specs/openid-connect-core-1_0.html#AuthError)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
