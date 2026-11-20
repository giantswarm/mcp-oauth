# Private key client authentication

Confidential clients can authenticate with `private_key_jwt` (RFC 7523 §2.2,
OIDC Core §9). The authorization code flow still requires S256 PKCE. Assertions
authenticate the client; they do not grant access to an MCP resource or replace
its access token.

Register with the existing registration bearer token:

```json
{
  "client_name": "gateway",
  "redirect_uris": ["https://gateway.example.com/oauth/callback"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks": {
    "keys": [{
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "use": "sig",
      "kid": "gateway-2026-01",
      "x": "<base64url public X coordinate, 32 bytes>",
      "y": "<base64url public Y coordinate, 32 bytes>"
    }]
  }
}
```

Replace the redirect URI and public coordinates with the client's values.
For AWS KMS ECC_NIST_P256, these are the coordinates of the public key returned
by GetPublicKey, each encoded as an unsigned 32-byte value without base64 padding.
The private key stays in KMS. No client secret is generated.

ES256 requires EC P-256. RS256 and PS256 require RSA keys of at least 2048 bits.
The signing algorithm must be explicitly pinned per client. Private key
parameters, symmetric keys, unsupported algorithms and `jwks_uri` are rejected.
An optional JWK `alg` must match the pin; `use` must be absent or `sig`, and
`key_ops`, if present, must contain only `verify`.

## Assertions

Send `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and `client_assertion=<signed compact JWT>` as form fields to the token endpoint
for both code exchange and refresh. The same authentication works for revocation,
introspection and token exchange, subject to their existing authorization rules.
Do not send Basic credentials or a client secret alongside an assertion.

Discovery advertises authentication methods and signing algorithms separately
for the token, revocation and introspection endpoints. Lifecycle authentication
uses registered or configured clients without fetching a submitted metadata URL.
Revocation verifies token ownership before invalidating a token or its family.

Claims must contain `iss = sub = client_id`, `exp`, `iat` and a unique
nonempty `jti`. An optional form `client_id` must match. The audience may be a
string or array containing either the exact configured token endpoint URL or
the exact issuer identifier. No URL normalization or request-host inference is
performed. These audiences also apply at revocation and introspection.

Requiring `iat` and enforcing `0 < exp - iat <= 300 seconds` are this server's
local security policy, stricter than the baseline OIDC assertion definition.
Expiry, future issuance and optional `nbf` allow 30 seconds of clock skew.
An assertion can therefore be accepted up to 30 seconds after its expiry.
Each assertion is consumed once across all client-authentication endpoints;
use a fresh assertion for every request and retry.

The signature must use the registered algorithm and a registered key matching
the protected `kid`. If `kid` is absent, exactly one registered key is required.
Keys or URLs in assertion headers never select a verification key.

Invalid assertions return HTTP 401 `invalid_client`. Mixing assertions with
secret credentials returns HTTP 400 `invalid_request`. Client lookup or replay
storage outages return HTTP 503 with `Retry-After`, without consuming a grant.
Audit events contain a specific failure reason without assertion contents.

## Replay storage and rotation

The default replay store is process-local memory. Multiple replicas must receive
a shared `ClientAssertionReplayStore` through `WithClientAssertionReplayStore`.
`storage/valkey.NewClientAssertionReplayStore` uses atomic SET NX EX with an
application-supplied prefix. Entries are scoped to client and JTI, retained until
expiry plus skew, with TTL rounded up. Storage failures fail closed and remain
retryable rather than being reported as invalid credentials.

Use the RFC 7592 management endpoint and its registration access bearer token
to replace the inline JWKS. For rotation, publish old and new keys together with
distinct nonempty `kid` values, switch signing to the new key, then replace the
set with only the new key. Management retains its separate bearer credential.
Failed metadata validation leaves the existing registration unchanged.
