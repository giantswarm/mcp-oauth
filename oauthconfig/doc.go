// Package oauthconfig loads mcp-oauth configuration from environment variables.
//
// It exists because every in-tree consumer of mcp-oauth (muster, mcp-prometheus,
// mcp-observability-platform, and the examples under ./examples/) reimplements
// the same ~50 lines of env-reading, base64 decoding, and k8s secret-file
// handling. This package owns that plumbing.
//
// # Variables
//
// Base variables, all optional except OAUTH_ISSUER:
//
//   - OAUTH_ISSUER                            (required) — server issuer URL
//
//   - OAUTH_ALLOW_INSECURE_HTTP               (default false) — permit http:// issuer
//     (loopback issuers — http://localhost, http://127.0.0.1, http://[::1] —
//     are exempt from this gate per RFC 8252 §7.3, so dev loops don't have to
//     enable the global insecure flag)
//
//   - OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION  (default false)
//
//   - OAUTH_ENABLE_CLIENT_ID_METADATA_DOCUMENTS (default false) - enable URL-based client IDs
//
//   - OAUTH_REGISTRATION_ACCESS_TOKEN         — registration bearer; see _FILE note below
//
//   - OAUTH_ENCRYPTION_KEY                    — 32-byte AES-GCM key, base64 (preferred) or hex
//
//   - OAUTH_REQUEST_STATE_KEY                 — 32-byte key sealing requestState
//     (NewRequestStateSealerFromEnv); OAUTH_REQUEST_STATE_PREVIOUS_KEY during a rotation
//
//   - OAUTH_SESSION_ID_HMAC_KEY               — base64 32-byte HMAC key
//     (see server.Config.SessionIDHMACKey for the operator caveat)
//
//   - OAUTH_FORWARDED_SESSION_IDENTITY        — "bearer" (default) or "principal"
//     (see server.Config.ForwardedSessionIdentity; validated by server.New)
//
//   - OAUTH_ACCESS_TOKEN_TTL                  — Go duration (e.g. "1h")
//
//   - OAUTH_REFRESH_TOKEN_TTL                 — Go duration
//
//   - OAUTH_MAX_CLIENTS_PER_IP                — positive integer
//
//   - OAUTH_TRUST_PROXY                       (default false)
//
//   - OAUTH_TRUSTED_AUDIENCES                 — comma-separated audience list
//
//   - OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS     deprecated, no effect: loopback redirect URIs are always allowed (RFC 8252 §7.3); false logs a warning
//
//   - OAUTH_TRUSTED_REDIRECT_SCHEMES          — comma-separated URI schemes (e.g. "cursor,vscode")
//     populates server.Config.TrustedPublicRegistrationSchemes
//
//   - OAUTH_ALLOW_PRIVATE_IP_CLIENT_METADATA_HOSTS — deprecated: comma-separated hostnames whose CIMD
//     metadata URLs may resolve to private addresses (server.Config.AllowPrivateIPClientMetadataHosts);
//     the server logs a warning, pre-register the clients in OAUTH_PRE_REGISTERED_CLIENT_METADATA instead
//
//   - OAUTH_PRE_REGISTERED_CLIENT_METADATA    — JSON array of Client ID Metadata Documents, used
//     without any fetch (server.Config.PreRegisteredClientMetadata)
//
//   - OAUTH_RESTRICT_CLIENT_METADATA          (default false) — accept only pre-registered client IDs
//     and those on OAUTH_CLIENT_METADATA_HOSTS (server.Config.RestrictClientMetadata)
//
//   - OAUTH_CLIENT_METADATA_HOSTS             — comma-separated exact hostnames whose documents
//     OAUTH_RESTRICT_CLIENT_METADATA lets the server fetch (server.Config.ClientMetadataHosts)
//
//   - OAUTH_ALLOW_PRIVATE_IP_REDIRECT_URI_HOSTS — comma-separated hostnames whose redirect URIs
//     may resolve to private addresses (server.Config.AllowPrivateIPRedirectURIHosts)
//
//   - OAUTH_ALLOW_PRIVATE_IP_JWKS_HOSTS     — comma-separated hostnames whose forwarded-ID-token
//     JWKS endpoint may resolve to private addresses (server.Config.AllowPrivateIPJWKSHosts)
//
//   - OAUTH_TRUSTED_CLIENTS                   — JSON array of {"client_id", "redirect_uris"}
//     objects; populates server.Config.TrustedClients (clients that skip the consent page)
//
//   - OAUTH_CONSENT_COOKIE_KEY                — 32-byte AES-GCM key for the consent cookies,
//     base64 or hex; optional override of the store's automatic issuer-specific key
//
// Protected resources (RFC 8707, RFC 9728). Each value is set once:
//
//   - OAUTH_RESOURCE                          — the main resource identifier, an absolute https URI
//     without a fragment, normally the MCP endpoint URL (server.Config.ResourceIdentifier;
//     defaults to OAUTH_ISSUER)
//
//   - OAUTH_AUTHORIZATION_SERVERS             — comma-separated issuer identifiers the main
//     resource's metadata advertises. [SettingsFromEnv] refuses one that is neither
//     OAUTH_ISSUER nor a trusted issuer. Unset advertises OAUTH_ISSUER
//
//   - OAUTH_ADDITIONAL_RESOURCES              — JSON array of {"resource", "scopesSupported",
//     "authorizationServers"} for extra resources on the main resource's origin, each by its
//     full URL; authorizationServers defaults to OAUTH_AUTHORIZATION_SERVERS
//     (server.Config.ResourceMetadataByPath)
//
//   - OAUTH_TRUSTED_ISSUERS                   — JSON array of issuers whose JWTs are accepted;
//     read by [TrustedIssuersFromEnv], never advertised
//
//   - OAUTH_REQUIRE_RESOURCE_ACCESS_TOKENS    (default false) — accept only tokens whose aud names
//     this server's resource (server.Config.RequireResourceAccessTokens)
//
// Authorization server switches, both default true:
//
//   - OAUTH_ENABLE_AUTHORIZATION_SERVER          — false makes the server a resource server only:
//     no provider is read, OAUTH_PROVIDER is refused, every token is checked against
//     OAUTH_TRUSTED_ISSUERS, which is then required, and each OAUTH_AUTHORIZATION_SERVERS value
//     must be a trusted issuer (server.Config.DisableAuthorizationServer)
//   - OAUTH_ENABLE_DYNAMIC_CLIENT_REGISTRATION   — RFC 7591; false removes /oauth/register and
//     registration_endpoint (server.Config.DisableDynamicClientRegistration)
//
// Endpoint switches, all default false and refused with the authorization server off:
//
//   - OAUTH_ENABLE_INTROSPECTION_ENDPOINT          — RFC 7662
//   - OAUTH_ENABLE_USERINFO_ENDPOINT               — OpenID Connect Core 5.3
//   - OAUTH_ENABLE_CLIENT_CONFIGURATION_ENDPOINT   — RFC 7592 (server.Config.EnableClientManagementEndpoint);
//     refused with Dynamic Client Registration off
//
// [SettingsFromEnv] reads all of the above, the provider and storage into the
// [Settings] that [Setup] takes.
//
// Defaults are not applied in this package. [FromEnv] only populates the
// fields it reads; server.New runs applyDefaults afterwards and is the single
// source of truth for default values.
//
// # Secret files (*_FILE convention)
//
// Every secret variable above accepts a sibling "<NAME>_FILE" variant that
// names a file to read the value from — the standard Kubernetes mounted-secret
// convention. When both the plain and _FILE variants are set, _FILE wins
// (explicit path > env). The file's contents are trimmed of a single trailing
// newline (projected-volume files often have one).
//
//   - OAUTH_REGISTRATION_ACCESS_TOKEN_FILE
//   - OAUTH_ENCRYPTION_KEY_FILE
//   - OAUTH_REQUEST_STATE_KEY_FILE
//   - OAUTH_REQUEST_STATE_PREVIOUS_KEY_FILE
//   - OAUTH_SESSION_ID_HMAC_KEY_FILE
//   - OAUTH_CONSENT_COOKIE_KEY_FILE
//
// OAUTH_TRUSTED_AUDIENCES deliberately has NO _FILE variant — audience
// identifiers are not secrets. The asymmetry is intentional; the list lives in
// deployment configuration (Helm values / ConfigMap) rather than in a Secret.
//
// # OAUTH_TRUSTED_AUDIENCES charset and limits
//
// The value is split on literal commas, then each non-empty entry is validated
// through dex.ValidateAudiences. Allowed characters are [a-zA-Z0-9_-]; the
// per-entry length cap is 256 characters and the total list cap is 50.
// FromEnv returns an error at startup if any entry violates these rules.
//
// This charset matches the Dex cross-client audience scope namespace
// (`audience:server:client_id:<id>`), which is the only context in which
// TrustedAudiences is currently consumed in production. Operators with
// URL-shaped audiences (RFC 8707) or other non-conforming values must
// populate oauth.Config.TrustedAudiences programmatically instead of relying
// on this loader.
//
// # FromEnv vs FromEnvWithPrefix
//
// [FromEnv] reads the names above. [FromEnvWithPrefix] reads the same names
// with a caller-supplied prefix (for consumers that scope env vars to their
// product, e.g. "MUSTER_OAUTH_"). The prefix is applied verbatim — include the
// trailing underscore if you want one.
package oauthconfig
