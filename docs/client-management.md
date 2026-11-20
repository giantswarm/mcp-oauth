# Client Management (RFC 7592)

RFC 7592 extends Dynamic Client Registration (RFC 7591) with a per-client management endpoint. Clients that registered dynamically can read, update, or delete their own registration without operator involvement.

An update must include the registered client ID. If `client_secret` is supplied,
it must match the issued secret; empty, null and mismatched values are rejected
without changing metadata or rotating the registration access token. Standard
`scope` strings use RFC 6749 scope tokens separated by single ASCII spaces.

For inline JWKS validation and key rotation, see [Private key client authentication](private-key-jwt.md). Management uses its separate registration access bearer token for all client authentication methods.

Deleting a registration permanently retires its client ID. Memory and Valkey keep a revocation marker, and issued opaque and self-issued JWT access tokens are checked against that marker on every validation. Existing access tokens, refresh requests and further client authentication are refused after deletion; another client's grants remain usable. A storage read failure returns an unavailable response instead of accepting a token or presenting an outage as invalid credentials.

Retired IDs cannot be registered again. Provision a new client for replacement; use metadata updates for signing-key rotation without deleting the client. Valkey stores the compact marker in the client record without an expiry, so replica reconnects do not lose retirement state. Persistence and backup policies must preserve these records: restoring an older snapshot can restore older authorization state. Upgrade all authorization-server replicas before relying on this behavior; old binaries do not check retirement markers.

Custom client stores must implement `storage.ClientRevocationStore` for server-side deletion. A store without that capability cannot complete a deletion that would leave its access tokens valid. This capability does not revoke the shared upstream identity-provider token, which may serve other clients belonging to the same person.

Losing revocation state can make previously retired, unexpired self-issued JWTs validate again if their signing keys are retained. After a wipe or rollback, JWT deployments must replace the access-token signing keys or keep protected traffic closed until previously issued tokens have expired. Opaque grants depend on stored token records, which a complete wipe removes.

Token revocation identifies public CIMD clients without fetching metadata, even
on a replica with no cached metadata. Token ownership is checked before mutation;
unknown, already revoked and other-client tokens receive the same HTTP 200 response.
With built-in stores, revoking a refresh token invalidates its family's access
tokens while leaving other families and clients usable.
A storage write failure returns HTTP 503 with `Retry-After`; retry the same
revocation because some writes may already have completed. Unknown, invalid and
other-client tokens retain the RFC 7009 success response for authenticated clients.
Client deletion and rejected use of a deleted client's tokens emit audit reasons
`client_deleted` and `client_revoked`.

## Enabling

```go
&oauth.ServerConfig{
    Issuer:                        "https://example.com",
    EnableClientManagementEndpoint: true,
}
```

When enabled, `RegisterOAuthRoutes` mounts `ServeClientManagement` at `/oauth/register/{client_id}`. Authorization-server metadata includes the local extension `registration_management_endpoint`, which is not a standard discovery field. Clients use their registration response's `registration_client_uri`.

## Registration access token

Each dynamically registered client receives a **registration access token (RAT)** at registration time:

```json
{
  "client_id": "abc123",
  "client_secret": "...",
  "registration_access_token": "rat-<high-entropy-random>",
  "registration_client_uri": "https://example.com/oauth/register/abc123"
}
```

The RAT is initially issued in the registration response and stored only as a hash (`RegistrationAccessTokenHash`). A successful GET echoes the authenticated request's RAT; it cannot recover a lost token. Treat it like a bearer token and store it securely on the client side.

## Endpoints

All management requests authenticate with `Authorization: Bearer <registration-access-token>`.

### GET /oauth/register/{client_id}

Returns the current client metadata:

```
GET /oauth/register/abc123
Authorization: Bearer rat-<token>
```

```json
{
  "client_id": "abc123",
  "client_name": "My App",
  "registration_access_token": "rat-<token>",
  "redirect_uris": ["https://app.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid email"
}
```

### PUT /oauth/register/{client_id}

Replaces the client metadata and **rotates the registration access token**. The response includes a new `registration_access_token`; the old one is invalidated immediately.

Send the authenticated `client_id` and complete metadata, including `redirect_uris`. Missing optional metadata resets to its registration default. The same name, scope, key and redirect validation applies as at registration. A client changing to a secret authentication method without an existing secret must register a replacement client.

```
PUT /oauth/register/abc123
Authorization: Bearer rat-<old-token>
Content-Type: application/json

{
  "client_id": "abc123",
  "client_name": "My App v2",
  "redirect_uris": ["https://app.example.com/callback", "https://app.example.com/callback2"]
}
```

Response includes a new `registration_access_token` — store it immediately.

### DELETE /oauth/register/{client_id}

Permanently retires the client ID. Existing access tokens fail validation, and further client authentication and refresh requests are refused.

```
DELETE /oauth/register/abc123
Authorization: Bearer rat-<token>
```

Returns `204 No Content` on success.

## Token rotation

This server rotates the RAT on every successful PUT. Clients must:

1. Send the PUT request.
2. Extract `registration_access_token` from the response.
3. Replace their stored RAT with the new value before making any further management calls.

A race condition where the old RAT is used after a successful PUT will result in `401 Unauthorized`.

## Security considerations

- Management tokens authenticate with the same `Authorization: Bearer` scheme as access tokens, but they are validated separately against the per-client `RegistrationAccessTokenHash` — they are not OAuth access tokens and cannot be used to call protected resources.
- Rate limiting is applied on the management endpoint per client IP, using the same IP rate limiter as the rest of the OAuth endpoints.
- Keep management endpoints behind your ingress auth layer or restrict access by IP if clients should not be able to self-manage.
- The endpoint is opt-in (`EnableClientManagementEndpoint: false` by default) to avoid exposing it unintentionally.
