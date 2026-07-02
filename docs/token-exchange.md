# Token Exchange (RFC 8693)

Token exchange lets a client present an external token (an OIDC ID token, an access token from another issuer, or a Kubernetes ServiceAccount token) and receive a new access token issued by this server. The issued token carries an `act` claim recording the original identity as the acting party.

## When to use it

- Service-to-service calls where the caller already holds a token from a trusted issuer (Dex, Google Workspace, another cluster's OIDC provider).
- Kubernetes workloads that have a projected ServiceAccount token and need an mcp-oauth-issued access token.
- Headless processes that cannot perform the interactive authorization code flow.

## Server setup

### Trusting external OIDC issuers

```go
import "github.com/giantswarm/mcp-oauth/server"

srv, _ := oauth.NewServer(
    provider, store, store, store,
    &oauth.ServerConfig{Issuer: "https://example.com"},
    logger,
    server.WithTrustedIssuers([]server.TrustedIssuer{
        {
            Issuer:           "https://dex.example.com",
            JwksURL:          "https://dex.example.com/keys",
            AllowedAudiences: []string{"mcp-server"},   // empty = any audience accepted
            AllowedScopes:    []string{"openid", "email", "groups"}, // caps issued scopes
        },
        {
            Issuer:           "https://accounts.google.com",
            JwksURL:          "https://www.googleapis.com/oauth2/v3/certs",
            AllowedAudiences: []string{"my-client-id.apps.googleusercontent.com"},
        },
    }),
)
```

`WithTrustedIssuers` registers an `OIDCValidator` for `id_token`, `access_token`, and `jwt` subject token types **and** as a Bearer validator on `ValidateToken`. A peer-issued JWT presented at `/mcp` is accepted when its `iss` matches a configured entry; the audience is checked against the entry's `AllowedAudiences` (or the server's `ResourceIdentifier` when empty), and RFC 9068 §4 requires the `typ: at+jwt` header on this path. The `Issuer` and `JwksURL` are independent — set `JwksURL` explicitly when the issuer's discovery document is unavailable or its JWKS is hosted separately.

`AllowedScopes` caps the scopes the server will include in the issued token for this issuer. `nil` means no restriction.

### Restricting which tokens are accepted (AllowedClaims)

`AllowedClaims` adds a claim-level gate after signature verification. Each entry requires the named JWT claim to match a pattern. Patterns support `*` (matches any sequence of characters, including `/`) and `?` (matches any single character). An absent claim or a non-string claim value is rejected.

**Kubernetes ServiceAccount tokens** — restrict to a specific namespace:

```go
server.WithTrustedIssuers([]server.TrustedIssuer{
    {
        Issuer:  "https://kubernetes.default.svc.cluster.local",
        JwksURL: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
        AllowedClaims: map[string]string{
            "sub": "system:serviceaccount:ai-platform:*",
        },
    },
})
```

The `sub` claim of a projected SA token has the form `system:serviceaccount:<namespace>:<name>`. The pattern above accepts any SA in the `ai-platform` namespace and rejects all others.

To restrict to a single SA: `"sub": "system:serviceaccount:ai-platform:my-worker"`.

**GitHub Actions OIDC tokens** — restrict to a specific repository:

```go
server.WithTrustedIssuers([]server.TrustedIssuer{
    {
        Issuer:           "https://token.actions.githubusercontent.com",
        JwksURL:          "https://token.actions.githubusercontent.com/.well-known/jwks",
        AllowedAudiences: []string{"https://mcp.example.com"},
        AllowedClaims: map[string]string{
            "sub":        "repo:org/repo:*",   // any branch/tag/environment in the repo
            "repository": "org/repo",           // belt-and-suspenders: exact repo match
        },
    },
})
```

Multiple entries in `AllowedClaims` are ANDed: all must match.

K8s SA and GHA tokens both use `subject_token_type=urn:ietf:params:oauth:token-type:jwt`.

### Custom validators

Implement `server.SubjectTokenValidator` and register it for a specific URN:

```go
server.WithSubjectTokenValidator("urn:example:custom-token-type", myValidator)
```

## Token type URNs

| `subject_token_type` | Validator | Notes |
|---|---|---|
| `urn:ietf:params:oauth:token-type:id_token` | `OIDCValidator` | OIDC ID token |
| `urn:ietf:params:oauth:token-type:access_token` | `OIDCValidator` | Opaque or JWT access token |
| `urn:ietf:params:oauth:token-type:jwt` | `OIDCValidator` | Kubernetes projected SA token, GHA OIDC token |

## Client request

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<external-token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&scope=openid email
```

Optional parameters:
- `resource` (RFC 8707): target resource server URI to bind the issued token's `aud`.
- `scope`: requested scope subset; intersected with the issuer's `AllowedScopes`.
- `DPoP` header: if present, the issued token is DPoP-bound (see [DPoP guide](./dpop.md)).

## Issued token

The issued access token contains an `act` claim per RFC 8693 §4.4:

```json
{
  "sub": "user@example.com",
  "act": {
    "iss": "https://dex.example.com",
    "sub": "user@example.com"
  },
  "scope": "openid email",
  "iss": "https://example.com",
  "aud": ["https://resource.example.com"]
}
```

`act.iss` records the original issuer; `act.sub` records the original subject. The delegation chain is preserved if the issued token is exchanged again.

## Injecting identity claims

Programmatic callers wrapping `Server.SelfIssuedExchange` (for example a broker that resolves a Kubernetes ServiceAccount `sub` to a machine principal, or an on-behalf-of flow that needs to carry the original user's identity) can populate the issued JWT's `email`, `email_verified`, `name`, `groups`, and arbitrary extra top-level claims by passing `Options`. When `Options` leaves a field unset, it defaults from the validated subject's claims; an explicit `Options` value takes precedence:

```go
result, err := srv.SelfIssuedExchange(ctx, server.SelfIssuedExchangeRequest{
    SubjectExchange: server.SubjectExchange{
        Subject:  server.TypedToken{Token: subjectToken, Type: subjectTokenType},
        Resource: resource,
        Scope:    scope,
    },
    DPoPJKT: dpopJKT,
    Options: server.ExchangeOptions{
        Email:         "klaus-sre@machine.giantswarm.io",
        EmailVerified: true,
        Groups:        []string{"klaus-sre"},
        Extra:         map[string]any{"principal_kind": "machine"},
    },
})
```

The resulting JWT carries `email`, `email_verified: true`, `groups: ["klaus-sre"]`, and `principal_kind: "machine"` alongside the standard exchanged-token claims (`sub`, `iss`, `aud`, `act`, etc).

`Extra` is merged into the JWT body after the standard claims. RFC 7519 §4.1 registered claim names (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) are rejected: `SelfIssuedExchange` returns an error if `Extra` contains any of them. OIDC-profile claims already set via struct fields (`email`, `name`, `groups`, `email_verified`) are not guarded and `Extra` can override them.

This is library API only: the HTTP `/oauth/token` endpoint does not extract these from the request form (it relies on the subject-claim defaulting). Use `Options` from in-process wrappers that have already resolved the identity out-of-band.

## Brokered exchange (audience parameter)

When the client sends an RFC 8693 `audience` parameter, the server acts as a **token broker** instead of issuing a local JWT: it validates the subject token, enforces policy, and delegates the downstream exchange to a host-provided `Exchanger`. The returned token comes from the downstream issuer verbatim — useful when the target (e.g. a Kubernetes API server behind its own Dex) will not accept tokens minted by this server.

### Host setup

```go
type myExchanger struct{ /* audience -> downstream Dex issuer + credentials */ }

func (e *myExchanger) Exchange(ctx context.Context, req *server.ExchangerRequest) (*server.ExchangerResult, error) {
    // req.Subject is the validated identity; req.SubjectToken is the raw token,
    // typically forwarded as the subject_token of the downstream RFC 8693 request.
    token, expiry, err := e.exchangeAtRemoteDex(ctx, req.Audience, req.SubjectToken, req.Scope)
    if err != nil {
        return nil, err // reported to the client as a generic invalid_grant
    }
    return &server.ExchangerResult{AccessToken: token, ExpiresAt: expiry}, nil
}

srv, _ := server.New(provider, store, store, store,
    &server.Config{
        Issuer: "https://broker.example.com",
        // Per-client audience allowlist: which audiences each broker client
        // may request. A miss returns invalid_target (RFC 8693 §2.2.2).
        TokenExchangeClientAudiences: map[string][]string{
            "backstage-backend-client-id": {"gaggle", "gauss"},
        },
    },
    logger,
    server.WithTrustedIssuers([]server.TrustedIssuer{ /* subject-token issuers */ }),
    server.WithExchanger(&myExchanger{}),
)
```

Return an error wrapping `server.ErrInvalidTarget` from `Exchange` to signal an audience the host cannot map; the client receives `invalid_target`.

### Policy enforced by the broker path

- **Client authentication is mandatory** and only confidential clients are accepted — the allowlist is keyed by client ID, which is spoofable for public clients (`unauthorized_client` otherwise).
- **Per-client audience allowlist**: `Config.TokenExchangeClientAudiences`; a client requesting an audience outside its list gets `invalid_target`. Without `WithExchanger`, every audience request gets `invalid_target`.
- **No refresh tokens** are issued; `expires_in` is bounded by the downstream token's expiry and clients are expected to re-exchange.
- **DPoP is rejected** on this path (`invalid_request`) — the downstream issuer never saw the proof, so the binding would be a lie.
- **Audit**: success and failure events carry the client ID, subject, requested audience, granted scope, and the deterministic cross-hop session ID (`ext-<hex>`, same derivation as forwarded-token acceptance, keyed by `Config.SessionIDHMACKey`) so broker audit lines correlate with downstream MCP server audit lines for the same token.

### Client request

```
POST /oauth/token
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<id-token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&audience=gaggle
&scope=openid groups
```

## Route registration

Token exchange is handled by `ServeToken` — no separate route is required. It activates automatically when the `grant_type` is `urn:ietf:params:oauth:grant-type:token-exchange` and at least one `SubjectTokenValidator` is registered. No `SubjectTokenValidator` = token exchange returns `unsupported_grant_type`. The brokered flow additionally requires `server.WithExchanger`.
