# DPoP (RFC 9449)

DPoP (Demonstrating Proof of Possession) binds access tokens to a client's private key. Even if a token is stolen from a log, a header, or in transit, it cannot be replayed without the corresponding private key.

## How it works

At issuance, when the client includes a `DPoP` proof header in the token request, the server:

1. Validates the proof (signature, `htm`, `htu`, `iat`, and `jti` claims).
2. Computes the JWK thumbprint (`jkt`) of the proof key.
3. Embeds `cnf: { jkt: "<thumbprint>" }` in the issued JWT access token, or stores the JKT in `storage.TokenMetadata` for opaque tokens.
4. Returns `token_type: DPoP`. Introspection includes the same type and `cnf.jkt`.

A public client's bound refresh token requires a fresh proof from the original
key on every refresh. Missing, malformed, duplicate and wrong-key proofs do not
consume the grant. Confidential clients authenticate separately; each refresh
can select a new DPoP access-token key, or obtain a Bearer access token by
omitting the proof. Memory and Valkey preserve token key bindings.

The token handlers validate proofs before calling `RefreshAccessTokenWithDPoP`
with authenticated client metadata. Direct calls to `RefreshAccessToken` and
`RefreshAccessTokenForResource` require the caller to authenticate the client
and enforce request proof requirements.

At every subsequent API call, `DPoPMiddleware` and `Handler.ValidateToken` enforce that:

- The request carries `Authorization: DPoP <token>` (not `Bearer`).
- The `DPoP` proof header is present, valid, and its key thumbprint matches the `cnf.jkt` in the token.
- The proof JTI has not been seen before (replay protection).
- The `ath` claim matches the presented access token.

If a DPoP-bound token is presented as plain `Authorization: Bearer`, `Handler.ValidateToken` rejects it with `401 invalid_token`.

## Server setup

```go
import (
    "time"

    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/server"
    valkeystore "github.com/giantswarm/mcp-oauth/storage/valkey"
    valkeygo "github.com/valkey-io/valkey-go"
)

replayClient, err := valkeygo.NewClient(valkeygo.ClientOption{
    InitAddress: []string{"valkey:6379"},
})
if err != nil {
    return err
}
replayCache := valkeystore.NewDPoPReplayCache(replayClient, "oauth:dpop:")
srv, err := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{Issuer: "https://example.com"},
    logger,
    server.WithDPoPReplayCache(replayCache),
    server.WithDPoPNonceProvider(
        server.NewHMACNonceProvider(nonceSecret, 5*time.Minute, time.Now),
    ),
)
if err != nil {
    replayClient.Close()
    return err
}
```

The owner closes `replayClient` after the OAuth server shuts down. Configure
its authentication and TLS for the shared backend. `tokenStore`, `clientStore`
and `flowStore` are the application's configured stores.

`WithDPoPReplayCache` is optional for single-process deployments;
`NewMemoryDPoPReplayCache()` is the default. A shared cache is required for
multi-pod deployments to prevent per-pod replay protection.

## Wiring the middleware

Use `Handler.DPoPMiddleware()` (the method form). It reads the replay cache, nonce provider, and trusted proxy CIDRs from the server, so the issuance path and resource path always share the same cache instance:

```go
h := handler.New(srv, nil)

mux := http.NewServeMux()
h.RegisterOAuthRoutes(mux, handler.OAuthRoutesOptions{IncludeMetadata: true})

// DPoP enforcement on the protected resource.
mux.Handle("/mcp", h.DPoPMiddleware()(h.ValidateToken(mcpHandler)))

http.ListenAndServe(":8080", mux)
```

The standalone `handler.DPoPMiddleware(replayCache, nonceProvider, trustedProxies)` function is also available for callers that do not use `handler.Handler`. When `replayCache` is `nil` it falls back to an in-process cache and logs a warning — safe for single-process deployments, not for multi-pod.

### Middleware ordering

`DPoPMiddleware` **must wrap** `ValidateToken`. It normalises `Authorization: DPoP <token>` to `Authorization: Bearer <token>` and stores the validated proof JKT in the request context. `ValidateToken` reads that JKT to enforce sender-constraint.

```
DPoPMiddleware → ValidateToken → your handler
```

Reversing the order breaks sender-constraint enforcement.

## Nonce enforcement (RFC 9449 §8)

When a `DPoPNonceProvider` is configured, every DPoP proof must carry a currently valid server-issued nonce. Clients that present a proof without a nonce (or with an expired one) receive:

```
HTTP 401
WWW-Authenticate: DPoP error="use_dpop_nonce", ...
DPoP-Nonce: <new-nonce>
```

The token endpoint returns HTTP 400 `use_dpop_nonce` with `DPoP-Nonce` for the
same condition. The client retries with the supplied nonce and a fresh proof.
`NewHMACNonceProvider` rotates nonces on a configurable window (e.g., 5 minutes)
and accepts proofs from either the current or the previous window.

A replay-store outage returns HTTP 503 with `Retry-After`, without consuming
the grant or treating the outage as a malformed proof. The token and resource
endpoints reject requests containing multiple DPoP proof headers.

## Supported algorithms

```
RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512
```

EC keys are recommended for performance. RSA is supported for compatibility.

## Multi-pod deployments

The replay cache and nonce provider must be shared across all pods. Use the
Valkey replay adapter with the same backend and prefix on every replica:

```go
server.WithDPoPReplayCache(valkeystore.NewDPoPReplayCache(replayClient, "oauth:dpop:"))
```

For the nonce provider, share a common HMAC secret across pods (e.g., from a Kubernetes Secret mounted as an env var). Each pod computes and validates nonces independently from the same key.
