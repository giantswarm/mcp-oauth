# Token Exchange (RFC 8693)

Token exchange lets a client present an external token (an OIDC ID token, an access token from another issuer, or a Kubernetes ServiceAccount token) and receive a new access token issued by this server. The subject remains in `sub`; an optional actor token adds the acting party in `act` for delegation.

`SelfIssuedExchange` and `BrokeredExchange` are this library's names for locally issued and downstream-issued tokens. Both use the RFC 8693 token exchange grant. Locally issued access tokens are signed by this authorization server; this is separate from OpenID Connect's Self-Issued OpenID Provider profile. The `client_id` claim records the requesting client and ownership for revocation; DPoP provides proof of possession separately.

The HTTP token endpoint calls `SelfIssuedExchange` when no `audience` is supplied. Local issuance requires JWT access-token mode and a signing key; applications configured for opaque tokens cannot use it. An `audience` selects `BrokeredExchange` and its host-provided downstream issuer instead.

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

`WithTrustedIssuers` registers an `OIDCValidator` for `id_token`, `access_token`, and `jwt` subject token types **and** as a Bearer validator on `ValidateToken`. A peer-issued JWT presented at `/mcp` is accepted when its `iss` matches a configured entry; the audience is checked against the entry's `AllowedAudiences` (or the server's `ResourceIdentifier` when empty), and RFC 9068 §4 requires the `typ: at+jwt` header on this path. The `Issuer` and `JwksURL` are independent; set `JwksURL` explicitly when the issuer's discovery document is unavailable or its JWKS is hosted separately.

`AllowedScopes` caps the scopes the server will include in the issued token for this issuer. `nil` means no restriction. A subject token's own `scope` claim, when present, narrows the grant further: an exchange never issues a scope the subject token does not carry. When these bounds leave nothing to grant, the exchange fails with `invalid_scope` rather than issuing an unscoped token.

For local issuance, `SubjectIdentity.Subject` must identify the intended principal uniquely within this server's issuer namespace. Independent issuers can reuse the same `sub`, for example Kubernetes ServiceAccounts with the same namespace and name in different clusters. Configure each issuer's `SubjectClaim` to a verified canonical identifier only when those identities are intended to be equivalent, or use a custom `SubjectTokenValidator` that maps the issuer and subject together. Local issuance preserves the validated subject; it does not automatically prefix it with its original issuer. Email mappings require `email_verified`, and the configured issuer must be trusted to assert that canonical identity.

### Restricting which tokens are accepted (AllowedClaims)

`AllowedClaims` adds a claim-level gate after signature verification. Each entry requires the named JWT claim to match a pattern. Patterns support `*` (matches any sequence of characters, including `/`) and `?` (matches any single character). An absent claim or a non-string claim value is rejected.

**Kubernetes ServiceAccount tokens**: restrict to a specific namespace:

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

**GitHub Actions OIDC tokens**: restrict to a specific repository:

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

### Restricting the acting party (Actors)

A delegated token names its acting party in the `act` claim (RFC 8693 §4.1). `Actors` limits which issuers a trusted issuer may name as the current actor, the outermost `act`. Nested `act` entries are earlier actors, informational only, and are not checked. A token without `act` is unaffected.

```go
server.TrustedIssuer{
    Issuer:           "https://dex.example.com",
    JwksURL:          "https://dex.example.com/keys",
    AllowedAudiences: []string{"muster"},
    Actors: &server.ActorPolicy{
        Issuers: []string{"https://idp.agents.example.internal", "https://kubernetes.default.svc"},
        Subjects: map[string]string{
            "https://kubernetes.default.svc": "system:serviceaccount:muster:*",
        },
    },
}
```

`Subjects` maps a listed issuer to a pattern, in `AllowedClaims` syntax, that the current actor's `sub` must match. An issuer without an entry accepts any `sub`, so an issuer shared by many workloads, such as a cluster's ServiceAccount issuer, needs one. `NewOIDCValidator` refuses a pattern for an issuer not in `Issuers` and a malformed pattern.

`Actors: &server.ActorPolicy{}` refuses every token from the issuer that carries `act`. With `Actors` unset, `act` is accepted unchecked. A refusal wraps `server.ErrActorNotTrusted`; on a bearer it is audited with reason `trusted_issuer_actor_not_trusted`.

The policy also applies to forwarded ID tokens (`TrustedAudiences`) from the provider's issuer when that issuer has a `TrustedIssuer` entry. The accepted token's `scope` claim is available as `UserInfo.Scopes`.

### Custom validators

Implement `server.SubjectTokenValidator` and register it for a specific URN:

```go
server.WithSubjectTokenValidator("urn:example:custom-token-type", myValidator)
```

Return an error wrapping `server.ErrProviderUnavailable` from `Validate` when an issuer the validator depends on did not answer. A trusted issuer whose JWKS endpoint answers 5xx or 429, times out or cannot be reached is classified the same way. The token endpoint answers either as `503 Service Unavailable` with `Retry-After`, and the audit log records reason `provider_unavailable`, so the client retries the same request instead of discarding the subject token.

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
Authorization: Basic <base64(form-encoded-client-id:form-encoded-client-secret)>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<external-token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&scope=openid email
```

The request must authenticate a registered confidential client with its registered method (`client_secret_basic`, `client_secret_post` or `private_key_jwt`). This is the server's deployment policy under RFC 8693 §2.1: client authentication prevents any holder of a trusted subject token from exchanging it without client credentials. RFC 9068 §2.2 requires the requesting client's `client_id` claim; it does not itself require confidential-client authentication. The issued token records that client, so the owner can revoke it (RFC 7009) and deleting the client retires it. The client's registered `grant_types` (RFC 7591 §2) must include `urn:ietf:params:oauth:grant-type:token-exchange`. `EnsureConfidentialClient` registers it; dynamic client registration does not, so a self-registered client cannot exchange tokens.

A request without client authentication is answered `400 invalid_client`, a public client or a client not registered for the grant `400 unauthorized_client`. Failed authentication attempted through the Authorization header returns `401 invalid_client` with a challenge matching its scheme, including unsupported schemes and requests without a separate `client_id` parameter. Mixed or duplicate credentials return `400 invalid_request`. In-process callers of `Server.SelfIssuedExchange` must authenticate a registered confidential client and pass its ID in `SelfIssuedExchangeRequest.ClientID`; an empty, unknown, public or retired client fails with `server.ErrExchangeClientRequired`. A client without the token exchange grant fails with `server.ErrExchangeGrantNotRegistered`.

Resource servers that verify these tokens offline against the JWKS do not see revocation or client deletion; for them a token stays valid until `exp` (`AccessTokenTTL`, default one hour). Only `ValidateToken` on this server consults the revocation and client-retirement state.

When upgrading, configure client credentials for HTTP callers and pass the authenticated `ClientID` from in-process callers before enabling exchange. Previously issued tokens without client ownership are not retroactively associated with a client; their prior validation and revocation behavior lasts until expiry. To invalidate those JWTs before expiry, resource servers must stop trusting their signing key; this also invalidates other tokens signed with that key.

Optional parameters:

- `requested_token_type`: local issuance supports `urn:ietf:params:oauth:token-type:access_token`. Brokered requests also support `id_token` and `jwt` token-type URNs. An omitted or empty value lets the broker host choose its output type. An explicit type is forwarded to the host `Exchanger`; a mismatched or invalid result returns `500 server_error`, without returning its token or auditing a successful issuance. `ExchangerResult.TokenType` states how to use the token independently of its representation: `Bearer` for an access token or `N_A` for an assertion. JWT results require this field because a JWT can serve either purpose. Empty usage metadata defaults to `Bearer` for `access_token` and `N_A` for `id_token`. Other usage methods, including DPoP output binding, are unsupported. An ID token cannot be marked `Bearer`, and an access token cannot be marked `N_A`.
- `actor_token` and `actor_token_type`: supply both for delegation. A nonempty actor token without its type, or a nonempty actor type without an actor token, returns `invalid_request`. Empty optional values are treated as omitted.
- `resource` (RFC 8707): an absolute URI with no fragment component or `#` delimiter, to bind the issued token's `aud`. The maximum length is 2,048 bytes. When omitted, `aud` defaults to the server's own `ResourceIdentifier`. Malformed values return `invalid_target` on either exchange flow.
- `scope`: requested scope subset; intersected with the issuer's `AllowedScopes` and with the subject token's `scope` claim when it has one; an empty intersection is refused with `invalid_scope`.
- `DPoP` header: if present, the issued token is DPoP-bound (see [DPoP guide](./dpop.md)).

Singleton parameters (`grant_type`, `subject_token`, `subject_token_type`, `actor_token`, `actor_token_type`, `requested_token_type` and `scope`) must not be repeated; duplicates return `invalid_request`. This endpoint supports one `resource` and one `audience`; multiple targets return `invalid_target`.

Local issuance policy (`SelfIssuedExchange`):
- **Resource allowlist**: `Config.TokenExchangeAllowedResources` caps the `resource` values that may be minted. Empty (the default) accepts any resource. When non-empty, a request whose `resource` is neither the server's own `ResourceIdentifier` nor a listed value is rejected with `invalid_target`. HTTP identifiers are compared ignoring scheme and host case, a default port and a trailing slash. Opaque URI contents and escaped reserved characters remain distinct: `urn:example:one` does not match `urn:example:two`, and `/a%2Fb` does not match `/a/b`.
- **Self-renewal**: a token this server issued cannot be re-exchanged without adding a new actor; a bare renewal (or re-attaching the actor already outermost on the subject's chain) is rejected with `invalid_request` to prevent open-ended TTL extension. Re-exchange to add a *different* actor extends the delegation chain and is allowed.
- **Key-bound subjects**: if the subject token carries an RFC 9449 `cnf.jkt` confirmation, the request must present a DPoP proof for that same key; otherwise the exchange is rejected. This prevents a bearer who lacks the confirmation key from laundering the binding into a token bound to a different key.

## Issued token

When a distinct actor token is supplied, the issued access token contains an `act` claim per RFC 8693 §4.1:

```json
{
  "sub": "user@example.com",
  "act": {
    "iss": "https://kubernetes.default.svc.cluster.local",
    "sub": "system:serviceaccount:ai-platform:worker"
  },
  "scope": "openid email",
  "iss": "https://example.com",
  "aud": ["https://resource.example.com"]
}
```

`act.iss` and `act.sub` identify the acting party. Without a distinct actor, the exchange does not add an `act` claim. Any existing actor chain on the subject is preserved, and a new actor wraps that chain when another delegation hop is added.

## Injecting identity claims

Programmatic callers wrapping `Server.SelfIssuedExchange` (for example a broker that resolves a Kubernetes ServiceAccount `sub` to a machine principal, or an on-behalf-of flow that needs to carry the original user's identity) can populate the issued JWT's `email`, `email_verified`, `name`, `groups`, and arbitrary extra top-level claims by passing `Options`. When `Options` leaves a field unset, it defaults from the validated subject's claims; an explicit `Options` value takes precedence:

```go
result, err := srv.SelfIssuedExchange(ctx, server.SelfIssuedExchangeRequest{
    SubjectExchange: server.SubjectExchange{
        Subject:  server.TypedToken{Token: subjectToken, Type: subjectTokenType},
        Resource: resource,
        Scope:    scope,
    },
    ClientID: authenticatedClientID,
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

`Extra` is merged into the JWT body after the standard claims. RFC 7519 §4.1 registered claim names (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) and `client_id` are rejected: `SelfIssuedExchange` returns an error if `Extra` contains any of them. OIDC-profile claims already set via struct fields (`email`, `name`, `groups`, `email_verified`) are not guarded and `Extra` can override them.

This is library API only: the HTTP `/oauth/token` endpoint does not extract these from the request form (it relies on the subject-claim defaulting). Use `Options` from in-process wrappers that have already resolved the identity out-of-band.

## Brokered exchange (audience parameter)

When the client sends an RFC 8693 `audience` parameter, the server acts as a **token broker** instead of issuing a local JWT: it validates the subject token, enforces policy, and delegates the downstream exchange to a host-provided `Exchanger`. The returned token comes from the downstream issuer verbatim; useful when the target (e.g. a Kubernetes API server behind its own Dex) will not accept tokens issued by this server.

### Host setup

```go
type myExchanger struct{ /* audience -> downstream Dex issuer + credentials */ }

func (e *myExchanger) Exchange(ctx context.Context, req *server.ExchangerRequest) (*server.ExchangerResult, error) {
    // req.Subject is the validated identity; req.SubjectToken is the raw token,
    // typically forwarded as the subject_token of the downstream RFC 8693 request.
    token, expiry, err := e.exchangeAtRemoteDex(ctx, req.Audience, req.SubjectToken, req.Scope)
    if err != nil {
        return nil, err // reported to the client as a generic invalid_request
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

Return an error wrapping `server.ErrInvalidTarget` from `Exchange` to signal an audience the host cannot map; the client receives `invalid_target`. Return an error wrapping `server.ErrProviderUnavailable` when the downstream issuer did not answer; the client receives `503 Service Unavailable` with `Retry-After` and retries the same request.

`ExchangerRequest.RequestedTokenType` carries the requested output type. HTTP and in-process callers can omit it to use the host's default, or provide a supported type. A mismatched result returns `server.ErrIssuedTokenTypeMismatch` before a success audit event is emitted.

`ExchangerResult.TokenType` carries the downstream usage method. Hosts returning `jwt` or another representation without a fixed usage method must set it explicitly to `Bearer` or `N_A`; upgrading hosts that return only `access_token` or `id_token` does not require setting it. Missing, unsupported or inconsistent usage metadata, and an empty result token, return `server.ErrInvalidExchangerResult` before a success audit event. The HTTP endpoint answers `500 server_error`. Only access tokens issued for the MCP resource may be used as MCP access tokens; a JWT representation alone does not establish that authority.

`ExchangerResult.Scope` must describe the effective downstream grant. If the downstream response omits `scope`, resolve it against the scope sent downstream, which may differ from the inbound client's request. The broker returns this value to the client and includes it in the issuance audit.

### Policy enforced by the broker path

- **Client authentication is mandatory** and only confidential clients are accepted; the allowlist is keyed by client ID, which is spoofable for public clients (`unauthorized_client` otherwise).
- **Per-client audience allowlist**: `Config.TokenExchangeClientAudiences`; a client requesting an audience outside its list gets `invalid_target`. Without `WithExchanger`, every audience request gets `invalid_target`.
- **No refresh tokens** are issued; `expires_in` is bounded by the downstream token's expiry and clients are expected to re-exchange.
- **DPoP is rejected** on this path (`invalid_request`); the downstream issuer never saw the proof, so the binding would be a lie.
- **Key-bound subjects are rejected** (`invalid_request`) before contacting the host. This path cannot verify possession of the subject token's confirmation key; rejecting an output DPoP request alone does not protect a bound input token.
- **Audit**: success and failure events carry the client ID, subject, requested audience, granted scope, and the deterministic cross-hop session ID (`ext-<hex>`, same derivation as forwarded-token acceptance, keyed by `Config.SessionIDHMACKey`) so broker audit lines correlate with downstream MCP server audit lines for the same token.

### Client request

```
POST /oauth/token
Authorization: Basic <base64(form-encoded-client-id:form-encoded-client-secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<id-token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&audience=gaggle
&scope=openid groups
```

## Route registration

Token exchange is handled by `ServeToken`; no separate route is required. It activates automatically when the `grant_type` is `urn:ietf:params:oauth:grant-type:token-exchange` and at least one `SubjectTokenValidator` is registered. No `SubjectTokenValidator` = token exchange returns `invalid_request`. The brokered flow additionally requires `server.WithExchanger`.
