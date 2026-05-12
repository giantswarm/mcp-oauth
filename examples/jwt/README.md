# JWT Access Token Mode Example

Demonstrates `AccessTokenFormatJWT` — the server signs access tokens as
RFC 9068 JWTs and publishes the public key at `/.well-known/jwks.json`
so an MCP-aware proxy (e.g. agentgateway) can verify bearers locally
without an introspection round-trip.

For the trade-off vs the default opaque mode, see
[SECURITY_ARCHITECTURE.md → Access Token Format Modes](../../SECURITY_ARCHITECTURE.md#access-token-format-modes).

## Run

The example uses Dex as the upstream IdP — point it at any running Dex
instance. The signing key is generated **ephemerally** on startup; in a
real deployment the operator would mount a stable key from a Secret/HSM/KMS.

```sh
export DEX_ISSUER_URL="https://dex.example.com"
export DEX_CLIENT_ID="demo-client"
export DEX_CLIENT_SECRET="demo-secret"
# Optional: skip Dex connector selection
export DEX_CONNECTOR_ID="github"

go run ./
```

Then open <http://localhost:8080>.

## End-to-end curl walkthrough

Replace `$TOKEN` with the access token returned at the end of the auth-code flow.

### 1. Inspect the JWKS

```sh
curl -s http://localhost:8080/.well-known/jwks.json | jq .
```

Returns one key, `kty=RSA`, `alg=RS256`, `use=sig`, with the matching `kid`.

### 2. Inspect the discovery document

```sh
curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq .
```

`jwks_uri` and `access_token_signing_alg_values_supported` are present
because the server is in JWT mode.

### 3. Decode an issued JWT

After completing the auth-code flow, decode the bearer at <https://jwt.io>
or with the `jose-util` CLI:

```sh
echo "$TOKEN" | cut -d. -f1 | base64 -d | jq .   # header → typ:"at+jwt", alg:"RS256", kid
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq .   # claims → iss, sub, aud, exp, iat, jti, client_id, scope, family_id, email, groups
```

### 4. Validate locally with an external script

A resource server fetches the JWKS, finds the key by `kid`, and verifies
the signature locally — no call back to the OAuth server. With `jose-util`:

```sh
curl -s http://localhost:8080/.well-known/jwks.json > /tmp/jwks.json
echo "$TOKEN" | jose-util verify --keys /tmp/jwks.json
```

Or programmatically with `github.com/go-jose/go-jose/v4` in Go.

### 5. Hit the protected endpoint

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/whoami
```

Returns `{"sub": "...", "email": "...", "groups": [...], "token_source": "jwt"}`.

### 6. Revoke the token

```sh
curl -X POST -d "token=$TOKEN" http://localhost:8080/oauth/revoke
```

The server records the JWT's `jti` in its denylist. The denylist entry
auto-expires when the JWT itself does.

### 7. Verify post-revocation rejection

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/whoami
# HTTP/1.1 401 Unauthorized
```

## Production considerations

- **Key storage.** Replace `rsa.GenerateKey(...)` on startup with a load
  from a Kubernetes Secret, an HSM, or a cloud KMS. The library accepts
  any `crypto.Signer`.
- **Rotation.** Change `AccessTokenSigningKeyID` and the key together,
  then restart. The JWKS is served with `Cache-Control: max-age=3600`
  so caching resource servers refresh within an hour.
- **TTL.** The example sets `AccessTokenTTL: 900` (15 min). JWT mode
  benefits from short TTLs because revocation is stateless — the
  compensating control for in-flight tokens is bounded lifetime.
- **Storage backend.** This example uses in-memory storage. In
  production use Valkey for `RevokedTokenStore` so the denylist
  survives restarts.
