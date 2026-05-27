# Token Exchange (RFC 8693)

Token exchange lets a client present an external token (an OIDC ID token, an access token from another issuer, or a Kubernetes ServiceAccount token) and receive a new access token issued by this server. The issued token carries an `act` claim recording the original identity as the acting party.

## When to use it

- Service-to-service calls where the caller already holds a token from a trusted issuer (Dex, Google Workspace, another cluster's OIDC provider).
- Kubernetes workloads that have a projected ServiceAccount token and need an mcp-oauth-issued access token.
- M2M flows where a headless process cannot perform the interactive authorization code flow.

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

`WithTrustedIssuers` registers an `OIDCValidator` for both `urn:ietf:params:oauth:token-type:id_token` and `urn:ietf:params:oauth:token-type:access_token`. The `Issuer` and `JwksURL` are independent — set `JwksURL` explicitly when the issuer's discovery document is unavailable or its JWKS is hosted separately.

`AllowedScopes` caps the scopes the server will include in the issued token for this issuer. `nil` means no restriction.

### Trusting Kubernetes ServiceAccount tokens

```go
server.WithKubernetesSATrust([]server.KubernetesSATrust{
    {
        Issuer:                 "https://kubernetes.default.svc",
        JwksURL:                "https://kubernetes.default.svc/openid/v1/jwks",
        AllowedNamespaces:      []string{"my-namespace"},      // optional; nil = any
        AllowedServiceAccounts: []string{"my-sa"},             // optional; nil = any
    },
})
```

K8s SA tokens use `subject_token_type=urn:ietf:params:oauth:token-type:jwt`.

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
| `urn:ietf:params:oauth:token-type:jwt` | `K8sSAValidator` | Kubernetes projected SA token |

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

## Route registration

Token exchange is handled by `ServeToken` — no separate route is required. It activates automatically when the `grant_type` is `urn:ietf:params:oauth:grant-type:token-exchange` and at least one `SubjectTokenValidator` is registered. No `SubjectTokenValidator` = token exchange returns `unsupported_grant_type`.
