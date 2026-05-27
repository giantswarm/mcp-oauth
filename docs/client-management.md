# Client Management (RFC 7592)

RFC 7592 extends Dynamic Client Registration (RFC 7591) with a per-client management endpoint. Clients that registered dynamically can read, update, or delete their own registration without operator involvement.

## Enabling

```go
&oauth.ServerConfig{
    Issuer:                        "https://example.com",
    EnableClientManagementEndpoint: true,
}
```

When enabled, `RegisterOAuthRoutes` mounts `ServeClientManagement` at `/oauth/register/{client_id}`. The base URL is advertised in the authorization server metadata as `registration_management_endpoint`.

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

The RAT is returned **exactly once** in the registration response. It is stored as a hash (`RegistrationAccessTokenHash`) — the plaintext is never retrievable again. Treat it like a bearer token: store it securely on the client side.

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
  "redirect_uris": ["https://app.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid email"
}
```

### PUT /oauth/register/{client_id}

Replaces the client metadata and **rotates the registration access token**. The response includes a new `registration_access_token`; the old one is invalidated immediately.

Updatable fields: `client_name`, `redirect_uris`, `scope`, `token_endpoint_auth_method`. Fields absent from the request body retain their current values.

```
PUT /oauth/register/abc123
Authorization: Bearer rat-<old-token>
Content-Type: application/json

{
  "client_name": "My App v2",
  "redirect_uris": ["https://app.example.com/callback", "https://app.example.com/callback2"]
}
```

Response includes a new `registration_access_token` — store it immediately.

### DELETE /oauth/register/{client_id}

Deletes the client. All tokens issued to the client remain valid until they expire; revoke them explicitly via `/oauth/revoke` if immediate invalidation is required.

```
DELETE /oauth/register/abc123
Authorization: Bearer rat-<token>
```

Returns `204 No Content` on success.

## Token rotation

Every successful PUT rotates the RAT. This is mandatory per RFC 7592 §2.3. Clients must:

1. Send the PUT request.
2. Extract `registration_access_token` from the response.
3. Replace their stored RAT with the new value before making any further management calls.

A race condition where the old RAT is used after a successful PUT will result in `401 Unauthorized`.

## Security considerations

- Management tokens authenticate with the same `Authorization: Bearer` scheme as access tokens, but they are validated separately against the per-client `RegistrationAccessTokenHash` — they are not OAuth access tokens and cannot be used to call protected resources.
- Rate limiting is applied on the management endpoint per client IP, using the same IP rate limiter as the rest of the OAuth endpoints.
- Keep management endpoints behind your ingress auth layer or restrict access by IP if clients should not be able to self-manage.
- The endpoint is opt-in (`EnableClientManagementEndpoint: false` by default) to avoid exposing it unintentionally.
