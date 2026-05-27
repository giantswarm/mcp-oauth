# DPoP (RFC 9449)

DPoP (Demonstrating Proof of Possession) binds access tokens to a client's private key. Even if a token is stolen from a log, a header, or in transit, it cannot be replayed without the corresponding private key.

## How it works

At issuance, when the client includes a `DPoP` proof header in the token request, the server:

1. Validates the proof (signature, `htm`, `htu`, `iat`, `jti`, `ath` claims).
2. Computes the JWK thumbprint (`jkt`) of the proof key.
3. Embeds `cnf: { jkt: "<thumbprint>" }` in the issued JWT access token, or stores the JKT in `storage.TokenMetadata` for opaque tokens.

At every subsequent API call, the `DPoPMiddleware` enforces that:

- The request carries `Authorization: DPoP <token>` (not `Bearer`).
- The `DPoP` proof header is present, valid, and its key thumbprint matches the `cnf.jkt` in the token.
- The proof JTI has not been seen before (replay protection).

If a DPoP-bound token is presented as plain `Authorization: Bearer`, `ValidateToken` rejects it with `401 invalid_token`.

## Server setup

```go
import (
    "github.com/giantswarm/mcp-oauth/server"
    "github.com/giantswarm/mcp-oauth/storage/valkey"
)

// Single-process: use the built-in memory cache.
// Multi-pod: back it with the shared Valkey store (same instance used for tokens).
valkeyStore := valkey.New(...)
srv, _ := oauth.NewServer(
    provider, valkeyStore, valkeyStore, valkeyStore,
    &oauth.ServerConfig{Issuer: "https://example.com"},
    logger,
    server.WithDPoPReplayCache(valkeyStore),           // shared replay cache
    server.WithDPoPNonceProvider(                       // optional: enforce nonces
        server.NewHMACNonceProvider(nonceSecret, 5*time.Minute, time.Now),
    ),
)
```

`WithDPoPReplayCache` is optional for single-process deployments — `NewMemoryDPoPReplayCache()` is the default. It is **required** for multi-pod deployments to prevent per-pod replay-cache split-brain.

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

The client retries with the supplied nonce. `NewHMACNonceProvider` rotates nonces on a configurable window (e.g., 5 minutes) and accepts proofs from either the current or the previous window to tolerate clock skew and in-flight requests.

## Supported algorithms

```
RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512
```

EC keys are recommended for performance. RSA is supported for compatibility.

## Multi-pod deployments

The replay cache and nonce provider must be **shared** across all pods. Use `valkey.New(...)` (the same store instance used for tokens) as the `DPoPReplayCache`:

```go
// valkeyStore implements DPoPReplayCache, TokenStore, ClientStore, FlowStore.
server.WithDPoPReplayCache(valkeyStore)
```

For the nonce provider, share a common HMAC secret across pods (e.g., from a Kubernetes Secret mounted as an env var). Each pod computes and validates nonces independently from the same key.
