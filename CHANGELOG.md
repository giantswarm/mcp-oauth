# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`security.SetEncryptionMetricRecorder`**: replaced unprotected package-level variable with `atomic.Pointer`, eliminating a data race when multiple goroutines register or clear the hook concurrently (e.g., parallel test suites).

### Added

- **`nbf` on access tokens.** RFC 9068 JWT access tokens carry `nbf = iat`. RFC 7662 introspection responses emit `nbf = iat` in both JWT and opaque modes.

- **`TrustedIssuer.AllowPrivateIPJWKS`**: opt-in bool allowing a trusted issuer's `JwksURL` to resolve to a private or loopback address.

- **`memory.WithEncryptor`, `memory.WithInstrumentation`, `memory.WithLogger`, `memory.WithCleanupInterval`, `memory.WithRevokedFamilyRetentionDays`**: functional options for `memory.New`. All cross-cutting dependencies are now supplied at construction; the store is immutable afterward.
- **`valkey.WithEncryptor`, `valkey.WithInstrumentation`**: functional options for `valkey.New`. Same construction-time wiring as memory.

### Changed

- **BREAKING — `memory.New` now accepts `...Option`** (was `func New() *Store`). Pass `memory.WithEncryptor(enc)`, `memory.WithInstrumentation(inst)`, etc. at construction instead of calling `SetX` after the fact.
- **BREAKING — `valkey.New` now accepts `...Option`** (was `func New(cfg Config) (*Store, error)`). Signature is now `func New(cfg Config, opts ...Option) (*Store, error)`.
- **BREAKING — `oauthconfig.StorageFromEnv` and `StorageFromEnvWithPrefix` signatures changed.** Both now accept `enc *security.Encryptor, inst *instrumentation.Instrumentation` before the `logger` argument, and wire them into the constructed store.
- Encryption at rest is wired on the store (`memory.WithEncryptor` / `valkey.WithEncryptor`), not the server. Remove any `server.WithEncryptor` / `oauth.WithEncryptor` calls and pass the encryptor directly to the store constructor.
- `server.Config.RevokedFamilyRetentionDays` removed; set the retention period on the memory store via `memory.WithRevokedFamilyRetentionDays` instead.

### Removed

- `memory.SetEncryptor`, `memory.SetInstrumentation`, `memory.SetLogger`, `memory.SetRevokedFamilyRetentionDays` — replaced by construction-time options.
- **`dpop/valkey` package removed.** The Valkey-backed DPoP replay cache is now at `storage/valkey.NewDPoPReplayCache`. Update imports from `github.com/giantswarm/mcp-oauth/dpop/valkey` to `github.com/giantswarm/mcp-oauth/storage/valkey` and replace `valkey.New(client, prefix)` with `valkey.NewDPoPReplayCache(client, prefix)`.
- **`server.Clock` interface and `server.DNSResolver` interface removed.** `clientMetadataCache` now calls `time.Now()` directly; use `testing/synctest` for TTL-sensitive tests. `Config.DNSResolver` is now `*net.Resolver`; pass a `*net.Resolver` with a custom `Dial` function to intercept DNS in tests.
- `memory.NewWithInterval` — replaced by `memory.New(memory.WithCleanupInterval(d))`.
- `valkey.SetEncryptor`, `valkey.SetInstrumentation`, `valkey.SetLogger` — replaced by construction-time options.
- `server.WithEncryptor` / `oauth.WithEncryptor` — the server no longer holds an encryptor; wire it on the store.
- `server.Server.Encryptor` field — removed alongside `WithEncryptor`.
- `server.Config.RevokedFamilyRetentionDays` — moved to `memory.WithRevokedFamilyRetentionDays`.
- **`server.K8sSAValidator`, `server.KubernetesSATrust`, `server.NewK8sSAValidator`, `server.WithKubernetesSATrust` removed.** Use `TrustedIssuer.AllowedClaims` instead.

### Security

- **`handleTokenExchangeGrant` audits handler-level rejections.** Missing `subject_token`, missing `subject_token_type`, missing `resource`, DPoP nonce required, and invalid DPoP proof each fire `EventAuthFailure` with a distinct `token_exchange_*` reason before the HTTP error is written.

- **`Server.ExchangeSubjectToken` now emits audit events on every branch.** Successful exchanges fire `EventTokenIssued` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the audience, granted scope, and the upstream actor issuer. JWT-mode misconfiguration, unsupported `subject_token_type`, subject-token validator rejection, and access-token issuance failure each fire `EventAuthFailure` with a distinct `reason`.

- **Startup `WARN` for development-only overrides.** `AllowInsecureHTTP`, `AllowPrivateIPClientMetadata`, and `AllowPrivateIPJWKS` now emit a `slog.LevelWarn` entry at server initialisation when set, making it harder to accidentally leave these flags enabled in production. `AllowPrivateIPClientMetadata` and `AllowPrivateIPJWKS` previously logged from `server.New` only; the warnings are now unified under `logCoreSecurityWarnings` alongside all other security-posture checks. All three flags are documented in `docs/security.md` under a new "Development-only overrides" subsection. Closes #342.

### Changed

- **BREAKING — HTTP adapter moved to `handler/` subpackage.** The HTTP layer that lived in the root `oauth` package (handler, middleware, route registration, endpoint serve methods, CORS, rate limit, scope plumbing) now lives in `github.com/giantswarm/mcp-oauth/handler`. The root `oauth` package retains protocol-level types (`Error`, `TokenResponse`, `ProtectedResourceMetadata`, etc.) and convenience constructors for `server.Server`. Migration: `oauth.NewHandler(srv, log)` → `handler.New(srv, log)`; `*oauth.Handler` → `*handler.Handler`; `oauth.OAuthRoutesOptions` → `handler.OAuthRoutesOptions`; `oauth.UserInfoFromContext` / `oauth.SessionIDFromContext` / `oauth.ContextWith*` → `handler.UserInfoFromContext` / `handler.SessionIDFromContext` / `handler.ContextWith*`; `oauth.InterstitialRedirectURL` / `oauth.InterstitialAppName` → `handler.InterstitialRedirectURL` / `handler.InterstitialAppName`. The `oauth.NewHandler` name is also dropped in favour of `handler.New` (idiomatic Go constructor naming in the new package). Closes #292, #343.
- **`server/flows.go` and root `handler.go` split by endpoint group.** Mechanical cut, no logic changes — each method moves to a new file unmodified. `server/flows.go` becomes a thin residue of shared helpers; per-flow files are `server/authcode.go`, `server/refresh.go`, `server/revoke.go`, `server/validate.go`, `server/scope.go`. Existing `server/flows_jwt.go` / `flows_sso.go` / `flows_forwarded.go` / `flows_refresh_session.go` lose the `flows_` prefix. The handler split lives in `handler/authorize.go`, `handler/token.go`, `handler/register.go`, `handler/revoke.go`, `handler/discovery.go`, `handler/middleware.go`, `handler/userinfo.go`, `handler/metrics.go`.

### Tests

- **Fuzz coverage** for four parsing / validation primitives: `ParseCallbackQuery` (types.go), `providers/oidc.ValidateExternalURL`, `Server.computePKCEChallenge` (S256 method), and `server.validateCodeVerifierFormat`. Seed corpora committed; each is panic-clean against a 2s exploratory burst. Closes (partial) #311.
- **Coverage gaps closed** for `Handler.handleRegistrationError` (HTTP-error mapping for the registration-limit vs generic branches) and `Server.handleRefreshTokenError` (classification of not-found / expired / transient errors).
- **AEAD authentication regression test** in `security/encryption_test.go` — a single-bit flip of the ciphertext tag must fail `Decrypt`. Catches a regression where AES-GCM gets swapped for a non-authenticated mode.

### Security

- **All public HTTP endpoints now uniformly gated by `gateIPRateLimit` (CWE-307).** `/oauth/callback` was missing the gate entirely (closes #339). `/oauth/register`, `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, and `/oauth/jwks.json` used hand-rolled per-endpoint equivalents that skipped OTel span attributes, endpoint-tagged HTTP metrics, and the JSON error body; replaced with `gateIPRateLimit` throughout. `checkDiscoveryRateLimit` deleted. `ServeClientRegistration` retains its hourly `ClientRegistrationRateLimiter` as a second pass after the IP bucket check. `handleRegistrationError` now matches via `errors.Is(err, storage.ErrClientIPLimitExceeded)` instead of string comparison.
- **Token-at-rest ciphertext envelope is now versioned (`0x01 ‖ kid ‖ nonce ‖ ct`)** — sets up future key rotation by tagging every new write with a 1-byte `kid`. Decrypt accepts both v1 and the legacy v0 (`nonce ‖ ct`) layout, falling through on AEAD-verification failure so the ~1/256 of v0 rows whose first nonce byte coincides with the v1 tag still decode. Rolling upgrades across a multi-replica fleet require updating every replica before allowing v1 writes — old replicas cannot read v1. Memory-only deployments are unaffected. Closes (partial) #309.
- **`security.KeyRing` interface** seam under `security.Encryptor`. The built-in single-key implementation produces and consumes the v1 envelope; consumers wiring external KMS / multi-key rotation supply their own `KeyRing`. Public API of `*Encryptor` is unchanged.
- **`security.WithPIIRedaction(bool)` option on `security.NewAuditor`** — when enabled, audit records emit `client_id_hash`, `ip_address_hash`, and `user_agent_hash` (truncated SHA-256) instead of the cleartext fields. `user_id_hash` is unchanged. Default off — existing slog sinks continue to receive cleartext. CWE-532.
- **`OAUTH_*_FILE` secret-file permission check** — `oauthconfig.optionalSecret` warns when a `_FILE` path is group or world readable, and hard-fails when `OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS=true`. Suppressed on Windows. CWE-732.
- **`oauthconfig.FromEnv` loopback detection** now accepts the full `127.0.0.0/8` range and `::ffff:127.0.0.1` via `helpers.IsLoopbackHostname` — `127.1`, `127.0.0.255`, and IPv4-mapped IPv6 loopback values now bypass the http-issuer gate alongside `localhost`, `127.0.0.1`, and `::1`.

### Added

- **RFC 7592 Dynamic Client Registration Management** (`GET/PUT/DELETE /oauth/register/{client_id}`). Opt-in via `Config.EnableClientManagementEndpoint`. When enabled: DCR responses include `registration_access_token` and `registration_client_uri`; `registration_management_endpoint` is advertised in AS metadata (RFC 8414 §2); PUT replaces mutable fields and rotates the token (old token immediately invalid); DELETE returns 204. Legacy clients have `RegistrationAccessTokenHash == ""` and get 401 after a constant-time dummy comparison. New API: `Config.ClientManagementEndpoint()`, `Server.SaveClient`, `Server.DeleteClient`, `server.GenerateRegistrationAccessToken`. Storage changes: `storage.Client` gains `RegistrationAccessTokenHash` and `UpdatedAt`; `ClientStore` gains `DeleteClient`. Closes #331.
- **`providers.EnsureTimeout(ctx, timeout) (context.Context, context.CancelFunc)`**: nil-safe context deadline helper. The three in-tree providers (dex, google, github) delegate their per-provider `ensureContextTimeout` methods to it. Closes (partial) #310.
- **`providers.CloneScopes([]string) []string`**: nil-safe deep copy used by every provider's `DefaultScopes()` to prevent caller mutation.
- **`providers.FilterScopes(requested, defaults []string, supported func(string) bool) []string`**: generic IdP scope-filter wrapping `CopyScopes` (mandatory-scope merge) + per-provider `supported` predicate. `filterDexScopes` / `filterGoogleScopes` collapse to single-line delegates.
- **`providers/oidc.RevokeAtEndpoint(ctx, httpClient, endpoint, token, clientID, clientSecret) error`**: RFC 7009 revocation primitive. Pass empty `clientID` / `clientSecret` for endpoints that do not require client authentication (e.g. Google).
- **`Config.DiscoveryCacheMaxAge time.Duration`** (default `1h`). Discovery endpoints (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource[...]`, `/.well-known/openid-configuration`) advertise `Cache-Control: public, max-age=<seconds>` per RFC 8414 §3 / RFC 9728 §3.
- **OIDC Discovery 1.0 §3 metadata fields** on the AS metadata document: `subject_types_supported: ["public"]`, `id_token_signing_alg_values_supported` (always includes `RS256`), and `claims_supported`.
- **`Config.EnableUserInfoEndpoint bool`** + **`EndpointPathUserInfo = "/oauth/userinfo"`** + **`Config.UserInfoEndpoint()`**. When enabled, `/oauth/userinfo` (OIDC Core 1.0 §5.3) is mounted behind `Handler.ValidateToken` and `userinfo_endpoint` is advertised in AS / OIDC discovery metadata. The `openid` scope is required; `profile`, `email`, and `groups` scopes gate the corresponding claims; `sub` is always returned. Each 2xx response emits `security.EventUserInfoServed` (`userinfo_served`) with the subject and the scope-derived claim groups returned, and the request is counted under `oauth_http_requests_total{endpoint="userinfo"}`.
- **`ContextWithScopes` / `ScopesFromContext`**. The `ValidateToken` middleware stashes the access token's granted scopes in the request context.
- **RFC 7591 client-registration response fields**: `client_id_issued_at` (always) and `client_secret_expires_at: 0` for confidential clients (RFC 7591 §3.2.1 sentinel for "never expires").
- **`Config.MaxStateLength int`** (default `512`). `/authorize` and `/callback` reject `state` longer than the configured maximum with `invalid_request`.
- **`security.DecodeKey(s string) ([]byte, error)`**: convenience helper that tries [`KeyFromBase64`](security/encryption.go) then falls back to [`KeyFromHex`](security/encryption.go). Consolidates the dual-encoding decode pattern that consumers were re-implementing locally.
- **`storage/valkey.Config.MaxTokenDataSize`**: per-store override for the encrypted-token serialization ceiling. `OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE` exposes the same knob via environment. Values are bounded by `MinMaxTokenDataSize` (64 KiB) and `MaxMaxTokenDataSize` (8 MiB); `New` rejects out-of-range values.
- **`security.EventProviderTokenStorageFailed`**: audit event emitted on every provider-token persistence failure, with stable `reason` enum (`missing_subject`, `save_user_info_by_id`, `save_token_by_id`, `save_user_info_by_email`, `save_token_by_email`).
- **`oauth_provider_token_storage_failed_total{reason}`**: counter that mirrors `EventProviderTokenStorageFailed`; the `reason` label uses the same enum so dashboards can join audit and metric streams.
- **`Server.ValidateRedirectURIForAuthorization(ctx, clientID, redirectURI) (*url.URL, error)`**: runs the client lookup and registered-redirect-URI check and returns the canonical `*url.URL` from server-side storage. Handlers redirecting `/authorize` protocol errors back to the client must use this value as the redirect target (RFC 6749 §3.1.2.4).
- **RFC 8693 token-exchange grant** (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`). A workload presents a signed JWT (Kubernetes projected SA token or OIDC token) and receives a short-lived JWT access token. Requires JWT access-token mode. New API: `Server.ExchangeSubjectToken`, `TokenExchangeResult`, `TokenExchangeUnsupportedTypeError`, `server.GrantTypeTokenExchange`. The grant type is advertised in AS metadata `grant_types_supported`. Scope ceiling per trusted issuer is enforced via `TrustedIssuer.AllowedScopes`. `OIDCValidator` and `WithTrustedIssuers` now accept `urn:ietf:params:oauth:token-type:jwt` in addition to `id_token` and `access_token`, so Kubernetes projected SA tokens can be exchanged without a separate validator.
- **RFC 9449 DPoP (Demonstration of Proof of Possession)**. `server.ValidateDPoPProof` validates a DPoP proof JWT; `handler.DPoPMiddleware` enforces DPoP at the resource endpoint. Token-exchange accepts an optional DPoP JKT and binds it into the issued token's `cnf.jkt` claim. New API: `server.DPoPReplayCache`, `server.NewMemoryDPoPReplayCache`, `server.WithDPoPReplayCache`, `handler.DPoPMiddleware`. Multi-instance deployments can use `storage/valkey.NewDPoPReplayCache` for a shared Valkey-backed replay cache.
- **`TrustedIssuer.AllowedClaims map[string]string`**: optional claim-level gate applied after signature verification. Each key is a JWT claim name; each value is an exact string or a glob pattern where `*` matches any sequence of characters (including `/`) and `?` matches any single character. A missing or non-matching claim is rejected. Use this to express namespace or SA restrictions (`"sub": "system:serviceaccount:ai-platform:*"`) or GHA subject scoping (`"sub": "repo:org/repo:*"`). Nil means no restriction.
- **`AccessTokenClaims.Act *Actor`** and **`AccessTokenClaims.JKT string`**: token-exchange issued tokens carry the RFC 8693 `act` claim (original `iss`/`sub`) and an optional `cnf.jkt` DPoP binding. Both are omitted from standard authorization-code tokens.
- **`security.IsTrustedProxy(remoteAddr string, cidrs []*net.IPNet) bool`**: reports whether a connection originates from a trusted reverse-proxy CIDR, used to decide when to honour `X-Forwarded-Proto`/`X-Forwarded-Host` for DPoP htu reconstruction. Wire proxy CIDRs via `server.WithTrustedProxyCIDRs`.

### Changed

- **`storage/valkey.DefaultMaxTokenDataSize`** raised to 600 KiB (was the previous 256 KiB constant `MaxTokenDataSize`, now removed). `SaveToken` accepts larger OIDC id_tokens, including those carrying extensive `groups` claims. Operators needing a different ceiling set `Config.MaxTokenDataSize` (or `OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE`).
- **OAuth provider-token storage failures are no longer silently swallowed**. `HandleProviderCallback` returns an error when persisting the provider token or `UserInfo` keyed by the subject ID fails, instead of completing the auth flow against an empty store (which previously manifested as broken SSO token forwarding). Email-keyed save failures remain best-effort but are now audited.
- **`providers/oidc.DiscoveryClient.Discover`** coalesces concurrent cold-cache callers for the same issuer URL via `singleflight`. Closes #307.
- **`Retry-After` is computed from the limiter's configured rate**
  - The IP, user, and discovery rate-limit `429` responses now set `Retry-After` to `1` second for any positive rate (sub-second precision isn't expressible per RFC 9110 §10.2.3) and fall back to `60` when the rate is 0. The client-registration limiter uses its configured window. Previously this header was a hardcoded `60` regardless of limiter configuration. New `RateLimiter.Rate()` / `ClientRegistrationRateLimiter.Window()` accessors expose the values.
- **`oauth_http_requests_total{endpoint="authorize"}`** (was `"authorization"`)
  - Renamed for path parity with `/authorize` (matching `token`, `revoke`, `introspect`, `register`, `callback`).

### Fixed

- **`ServeProtectedResourceMetadata` now opens a top-level span (`oauth.http.discovery.prm`), applies the IP rate-limit gate, and records HTTP metrics** — previously the PRM endpoint was unspanned and unlimited while its siblings (AS-metadata, OIDC-config, JWKS) all had these. Closes #340.
- **All discovery and JWKS spans now carry an `oauth.discovery` attribute** (`authorization_server`, `openid_configuration`, `protected_resource`, `jwks`) for filtering in trace backends.
- **AS-metadata and OIDC-config produce distinct span names** (`oauth.http.discovery.as` / `oauth.http.discovery.oidc`) instead of both recording under `oauth.http.discovery`. Dashboards and alerts filtering on the old span name will need updating.

- **Documentation references real APIs**. The root `doc.go` package overview, `docs/security.md`, `docs/getting-started.md`, `docs/silent-authentication.md`, `docs/README.md`, `server/doc.go`, and `SECURITY_ARCHITECTURE.md` no longer reference symbols that do not exist on the current API (`oauth.NewHandler(&oauth.Config{...})`, `oauth.GenerateEncryptionKey`, `oauth.EncryptionKeyFromBase64`, `handler.ValidateGoogleToken`, `server.SetEncryptor` / `SetAuditor`, `providers.AuthOptions` / `ExchangeOptions` / `TokenResponse`, `oauth.GeneratePKCE`, `google.NewProvider(clientID, ...)`, `memory.NewStore()`, `golang-jwt/jwt/v5`). Snippets now show the live functional-option API (`server.WithEncryptor`, `server.WithAuditor`), the real `providers.Provider` interface, the current `google.NewProvider(&google.Config{...})` and `memory.New()` constructors, an inline `crypto/rand` + `sha256` PKCE helper, and `go-jose/go-jose/v4` in the JWT threat-model row. The root overview now also reflects MCP spec date 2025-11-25 and the current spec-compliance list (RFC 7662 / RFC 9068 / RFC 9207 / RFC 9728 / OIDC §3 / OIDC §5.3). `docs/README.md` index gains the missing `silent-authentication.md` link. Closes #308.

- **All four authenticated endpoints reject Basic-Auth / form `client_id` mismatch** (RFC 6749 §2.3.1) — `/token` (authorization_code, refresh_token grants), `/revoke`, and `/introspect` return `400 invalid_client` with the description `client_id in Basic Authorization header does not match form parameter` when the Basic Authorization identity disagrees with the form `client_id`. Audited as `auth_failure` (reason `client_id_mismatch_basic_vs_form`); the audit record pins the Basic-Auth identity. `handleAuthorizationCodeGrant` now reads `oauthErr.Status` before recording the HTTP metric so a 400 is not relabelled as 401.
- **`parseBasicAuth` rejects malformed `Authorization: Basic` headers** — the `ok` flag from `r.BasicAuth()` is now honoured, so an undecodable payload or missing colon is treated as "no credentials" rather than a silent client_id of garbage.
- **`oauth_http_requests_total` now covers all `/token` and `ValidateToken` middleware paths**
  - The HTTP counter previously skipped `/token`'s `405` and unsupported-`grant_type` `400` responses, and the `ValidateToken` middleware's rate-limit `429`s. Dashboards summing by `endpoint` (new label `validate_token`) now see those.
- **`oauth_http_requests_total` now records the 429 on `/register`'s IP-rate path**
  - The IP-gate 429 on `/register` was previously missing from the HTTP counter.
- **OAuth handler spans are now propagated to all downstream metric and audit calls on `/callback`, `/token`, `/revoke`, `/introspect`**
  - Metrics and audit events recorded after `tracer.Start` are now linked to the active span instead of an unspanned context. `/token` now opens a top-level `oauth.http.token` span at handler entry so rate-limit 429s on `/token` also appear in traces (the per-grant `oauth.http.token_exchange` / `oauth.http.token_refresh` spans become children).

### Security

- **IP rate limiter now applied to `/authorize`, `/token`, `/revoke`, `/introspect`** (CWE-307, closes #302)
  - Exceeding the configured per-IP rate on any of these endpoints returns `429` with `Retry-After` and `{"error":"rate_limit_exceeded"}`, and emits the `rate_limit_exceeded` audit event and metric. No-op when no `RateLimiter` is configured.
- **Rate-limit keys now bucket IPv6 to a `/64`**
  - The CWE-307 closure is no longer bypassable by an attacker holding an IPv6 `/64` (the typical end-site allocation): `security.RateLimitBucket` maps every `/128` in the same `/64` to a single key. IPv4 is unchanged. Applies to the IP, discovery, and client-registration rate limiters.
- **Post-authentication rate limit on `/token` and `/revoke` (the issue's optional second pass)**
  - After successful client authentication, requests are also bounded by the `UserRateLimiter` keyed on `client_id`. Caps authenticated abusers (e.g. a single compromised client enumerating refresh tokens). Applies to confidential clients on `/token` and `/revoke`; public clients (PKCE on `/token`) remain bounded by the IP limit only since their `client_id` is public and attacker-controllable.

### Added

- **`Config.TrustedPublicRegistrationRedirectURIs`** — HTTPS redirect-URI allowlist for unauthenticated dynamic client registration.
  - Every `redirect_uris` entry in the request must be in the allowlist; matching is exact after RFC 3986 normalization (lowercase scheme + host, HTTPS default `:443` stripped, trailing slashes stripped from the path; path and query then case-sensitive).
  - Public clients (`token_endpoint_auth_method: "none"`) succeed via this gate.
  - Entries are validated at startup: HTTPS only, no fragment / userinfo, no loopback / private / link-local / unspecified IP literal hosts. Invalid entries are dropped.
  - New audit event `client_registered_via_trusted_redirect_uri` (`security.EventClientRegisteredViaTrustedRedirectURI`) carries the matched URI.
  - Env loader: `OAUTH_TRUSTED_REDIRECT_URIS` (comma-separated).
- **OIDC `nonce` end-to-end (CWE-294)** (closes #305)
  - `/authorize` accepts the `nonce` query parameter and forwards it to the upstream IdP. On OIDC flows the server mints a 256-bit nonce when the client supplied none; on non-OIDC flows (no `openid` scope) a client-supplied nonce is dropped (debug-logged, no rejection).
  - `providers.AuthorizationURLOptions` gains a `Nonce` field; additive, no signature changes.
  - `storage.AuthorizationState` gains a `Nonce` field, persisted by both memory and Valkey backends.
  - New `Config.RequireNonceEcho` (default `true`, opt out via `Config.DisableNonceEchoRequirement`). Upstream id_token must echo the issued nonce; the callback is rejected and `security.EventProviderNonceMismatch` is emitted (severity `high`, `reason` ∈ `{mismatch, absent, wrong_type, id_token_missing, id_token_parse_failed}`). Comparison uses `crypto/subtle.ConstantTimeCompare`.
  - New `oidc.ValidateNonceClaim(claim, expected)` + `oidc.ErrNonceMismatch` sentinel.
  - `IDTokenClaims` gains a `Nonce` JSON tag.
  - Authorization Server Metadata advertises `claims_supported: ["sub", "aud", "iss", "exp", "iat", "nonce"]`.
  - Consumers using mock providers that omit `id_token` for OIDC-scoped flows must opt out via `DisableNonceEchoRequirement` or update fixtures to issue an `id_token` with the bound nonce echoed back.
- **`LogValue()` on `Server`, `storage/memory.Store`, and `storage/valkey.Store`** (slog.LogValuer)
  - Callers can attach a one-shot structured snapshot of the server / store posture to any log line: `logger.Info("oauth ready", "server", srv, "store", store)`. The library no longer emits this state on its own.
  - `Server.LogValue()` exposes `issuer`, `production_mode`, `access_token_format`, `encryption_at_rest`, `instrumentation_on`, a `redirect_uri_policy` group (`dns_validation`, `dns_validation_strict`, `authorization_time_validation`, `dns_timeout`, `allow_localhost`, `allow_private_ip`, `allow_link_local`), and `session_id_hmac_key_fingerprint` (sha256[:8] hex, omitted when unconfigured).
  - `memory.Store.LogValue()` / `valkey.Store.LogValue()` expose `backend`, `encryption_at_rest`, `instrumentation_on`.
- **`Server.RefreshSession(ctx, familyID)` for on-demand session refresh** (closes #285)
  - In-process API to refresh an upstream provider token by family ID, callable from any goroutine. Reuses the existing `RefreshAccessToken` path (same rotation, reuse detection, audit, and `TokenRefreshHandler` dispatch) — just driven by family ID instead of by a refresh token in the request.
  - Concurrent calls for the same family ID are coalesced via `singleflight`: only one provider refresh hits the upstream, the rest share the result.
  - New optional `storage.ActiveRefreshTokenByFamilyStore` interface (memory + Valkey) returns the highest-generation non-revoked refresh token for a family. `RefreshSession` calls this to find the live token.
  - Use case: an integrating server (e.g. `muster`) about to forward a cached ID token discovers it's expired. Pre-PR there was no way to force a refresh on the request thread without constructing a fake `/oauth/token` POST. Now: `srv.RefreshSession(ctx, familyID)` and re-read the cached entry.
- **JWT access-token issuance mode (RFC 9068)**
  - New `Config.AccessTokenFormat` (default `AccessTokenFormatOpaque`, opt-in `AccessTokenFormatJWT`). In JWT mode the server signs access tokens with `Config.AccessTokenSigningKey` (RSA or ECDSA P-256/P-384) under `Config.AccessTokenSigningKeyID`/`Config.AccessTokenSigningAlgorithm` (RS256/RS384/RS512/ES256/ES384). HMAC variants and `none` are rejected at startup as alg-confusion defense.
  - New `/.well-known/jwks.json` endpoint publishes the public half (RFC 7517). Authorization Server Metadata gains `jwks_uri` and `access_token_signing_alg_values_supported` only in JWT mode; opaque mode is byte-identical to v1.
  - New optional `storage.RevokedTokenStore` interface (memory + Valkey implementations) records revoked `jti`s with auto-expiry at the JWT's own `exp`. `/oauth/revoke` writes to the denylist; validation reads from it on every request.
  - New optional `storage.RefreshTokenFamilyByIDStore` interface (memory + Valkey) lets JWT validation invalidate in-flight access tokens when the refresh-token family is revoked. Defense in depth on top of the `jti` denylist.
  - New `providers.TokenSourceJWT` constant + `UserInfo.IsJWT()` so downstream consumers can dispatch on a self-issued JWT bearer (no upstream id_token in TokenStore for it).
  - Validation pipeline is format-agnostic by design: a single `ValidateToken` call accepts self-issued JWT, forwarded ID token (existing `TrustedAudiences` path), and opaque bearers. Operators upgrading or running mixed deployments are not forced to coordinate format across instances.
  - JWT validation is local: signature + typ (`at+jwt`) + iss + exp (with `ClockSkewGracePeriod`) + aud (RFC 8707, parity with the opaque branch) + jti denylist + family revocation. No upstream userinfo round-trip on the hot path.
  - New `examples/jwt/` runnable example with end-to-end `curl` walkthrough.
  - SECURITY_ARCHITECTURE.md gains an "Access Token Format Modes" section documenting threat model, mitigations, key management, and the opaque-vs-JWT trade-off.
  - Refresh tokens stay opaque in both modes (rotation needs server state; there's no win from making them JWTs).
  - Default behavior is unchanged: `AccessTokenFormat=""` → opaque, identical to v1.
- **oauthconfig.StorageFromEnv switch now uses `storage.BackendMemory` / `storage.BackendValkey` instead of string literals**
  - Internal cleanup so the loader and the storage package share one source of truth for backend names. The constants were already exported from the `storage` package — consumers that branch on backend name (e.g. "refuse memory in production") should reference `storage.Backend*`.
- **oauthconfig.FromEnv: loopback issuers bypass the http:// gate**
  - `http://localhost`, `http://127.0.0.1`, and `http://[::1]` (with or without ports) are now accepted as `OAUTH_ISSUER` without setting `OAUTH_ALLOW_INSECURE_HTTP`. Per RFC 8252 §7.3 (native-app loopback). Lookalikes like `http://127.0.0.1.evil` are still rejected.
  - Removes the dev-loop footgun where flipping `OAUTH_ALLOW_INSECURE_HTTP=true` for `http://localhost:5556` weakened every other http:// check at the same time.
- **oauthconfig.DexFromEnv defaults `OAUTH_DEX_REDIRECT_URL` to `${OAUTH_ISSUER}/oauth/callback`**
  - Saves consumers from templating the issuer URL into two env vars (helm value + DEX_REDIRECT_URL). When OAUTH_ISSUER is set and DEX_REDIRECT_URL is unset, the loader derives the canonical provider-callback URL automatically. A trailing slash on the issuer is tolerated.
  - Additive: explicit OAUTH_DEX_REDIRECT_URL still wins. The "required" error still fires when both vars are unset.

### Changed

- **Token introspection (`/oauth/introspect`) now enforces a cross-client gate (#306)**
  - **Breaking**: a client introspecting a token bound to a different client receives `{"active": false}` per RFC 7662 §2.2 with no other claims populated.
  - New `Config.IntrospectionResourceServers []string` allowlists resource servers permitted to introspect tokens they do not own. Empty entries are rejected at `Config.Validate`; entries not resolving to a registered client are rejected at `Server.New`; same-client introspection is always allowed.
  - Cross-client denials emit `security.EventIntrospectionRequesterDenied` (severity `medium`, `reason` ∈ `{empty_requester, empty_token_bound_client, cross_client_probe}`).
  - User attributes (`email`, `email_verified`, `name`, `sub`) flow only on the authorized path.
- **RFC 9068 access tokens (JWT mode) now carry `email_verified` and `name` claims**
  - `AccessTokenClaims.EmailVerified` and `AccessTokenClaims.Name` are populated from `providers.UserInfo` during issuance.
  - Brings JWT-mode introspection into parity with opaque-mode introspection on identity attributes.
- **`security.Auditor` methods take `context.Context`**
  - `LogEvent` and the 11 typed helpers (`LogTokenIssued`, `LogTokenRefreshed`, `LogTokenRevoked`, `LogAuthFailure`, `LogRateLimitExceeded`, `LogClientRegistrationRateLimitExceeded`, `LogClientRegistered`, `LogInvalidPKCE`, `LogTokenReuse`, `LogSuspiciousActivity`, `LogInvalidRedirect`) now take `ctx context.Context` as the first argument. The ctx is forwarded to the underlying `slog.Handler.Handle`, so otelslog-style handlers attach trace/span IDs to audit records.
  - **Breaking**: prepend `ctx` at every call site (`r.Context()` for HTTP-driven flows, `context.Background()` for background emissions).
- **`Server.Instrumentation` is always non-nil**
  - When the caller does not pass `WithInstrumentation(...)`, `server.New` initializes a default `instrumentation.New(Config{})` — no-op meter and tracer providers, zero exporter overhead. Call sites no longer guard with `if h.server.Instrumentation != nil { ... }`.
  - New `instrumentation.Instrumentation.IsEnabled()` reports whether real exporters were wired (vs. the default no-op).
  - **Breaking** for callers that introspected `srv.Instrumentation == nil` to detect "observability not configured" — check `srv.Instrumentation.IsEnabled()` instead.
- **New metrics**
  - `oauth.token_endpoint.failures.total{grant_type, error_code}` — token-endpoint failures by grant_type and RFC 6749 error_code. `grant_type` is coerced to `"unknown"` for non-standard values to bound cardinality.
  - `oauth.audit.drops.total{reason}` — audit events dropped. `reason="disabled"` fires when an `Auditor` is configured with `enabled=false`.
  - `oauth.encryption.operations.total{operation, result}` and `oauth.encryption.duration{operation, result}` gain a `result` label (`ok`/`fail`). `Encryptor.Encrypt` and `Encryptor.Decrypt` now record the metric automatically on every call.
  - **Breaking** for direct callers of `Metrics.RecordEncryptionOperation` (new `result string` argument).
- **OAuth-semantic span attributes**
  - `oauth.http.authorization` sets `oauth.response_type` and `oauth.scope`.
  - `oauth.http.token_exchange` sets `oauth.grant_type=authorization_code`.
  - `oauth.http.token_refresh` sets `oauth.grant_type=refresh_token`.
  - Refresh rotation in `server/flows.go` sets `oauth.token.rotated=true` on the active span.
  - New `oauth.http.introspection` span on the RFC 7662 introspection endpoint, carrying `oauth.client_id` and `oauth.token_type`.
- **Removed unused observability surface**
  - `instrumentation.SanitizeRedirectURI` and `instrumentation.AttrRedirectURI` (declared but never referenced).
- **`docs/observability.md`** rewritten against the actual emit set. Now covers `oauth.audit.events.total`, `oauth.audit.drops.total`, `oauth.encryption.*`, `oauth.cimd.*`, `oauth.refresh_token.legacy_rejected`, `oauth.forwarded_id_token.accepted_total`, and `oauth.token_endpoint.failures.total`.
- **Startup chatter downgraded from INFO to DEBUG; audit logs grouped under `slog.Group("audit", ...)`**
  - Every "X enabled / Using Y / Initialized Z / Registered W" line that fired once at startup is now `slog.LevelDebug`. Affected sites span `server`, `storage/memory`, `storage/valkey`, `security/client_registration_ratelimit`, `providers/oidc`, plus per-request lifecycle Infos (`Token proactively refreshed`, `Refresh token rotated`, `Token revoked`, `Token exchange successful`, ...). WARN/ERROR security warnings are unchanged.
  - The Server-side "Redirect URI security status" Info is removed; the same fields are reachable via `Server.LogValue()`.
  - `Auditor.LogEvent` now emits via `slog.LogAttrs` with every audit field bundled in a single `slog.Group("audit", ...)`. Consumers can route audit records separately by inspecting the group in their `slog.Handler`. The level stays at `INFO` and the message stays `"security_audit"`.
  - Consumers compile unchanged; only their log volume changes. Crank to `slog.LevelDebug` to recover the prior verbosity.
- **Server constructor now accepts functional options; the post-construction `Set*` methods are gone**
  - `server.New` and `server.NewWithCombined` (and the root-package `oauth.NewServer` / `oauth.NewServerWithCombined`) take a variadic `...Option` parameter. New constructors: `WithEncryptor`, `WithAuditor`, `WithRateLimiter`, `WithUserRateLimiter`, `WithSecurityEventRateLimiter`, `WithClientRegistrationRateLimiter`, `WithMetadataFetchRateLimiter`, `WithSessionCreationHandler`, `WithSessionRevocationHandler`, `WithTokenRefreshHandler`, `WithInstrumentation`. `WithEncryptor` and `WithInstrumentation` propagate to the storage backend identically to the old setters.
  - **Breaking**: `Server.SetEncryptor`, `SetAuditor`, `SetRateLimiter`, `SetUserRateLimiter`, `SetSecurityEventRateLimiter`, `SetClientRegistrationRateLimiter`, `SetMetadataFetchRateLimiter`, `SetSessionCreationHandler`, `SetSessionRevocationHandler`, `SetTokenRefreshHandler`, and `SetInstrumentation` are removed. Migration: pass the same value as a `With*` option to the constructor.
  - **Breaking**: `Server.SetTokenFamilyRevocationHandler` and the `TokenFamilyRevocationHandler` type alias (deprecated since the `SessionRevocationHandler` rename) are removed. Use `WithSessionRevocationHandler`.
  - The "partial-init" window between `New(...)` and the last `SetX` call is gone — the server is fully wired before it returns.
- **`storage.TokenMetadataStore`* family collapsed into a single interface; scope helpers consolidated**
  - `storage.TokenMetadataStore`, `storage.TokenMetadataStoreWithAudience`, `storage.TokenMetadataStoreWithScopesAndAudience`, and `storage.TokenMetadataStoreWithFamily` collapsed into a single `storage.TokenMetadataStore` interface taking the existing `storage.TokenMetadata` struct. Adding a new metadata field is now a single-place change.
  - `Server.saveTokenMetadata` no longer fans out through a 4-way runtime type-assertion ladder; it makes one call.
  - `internal/helpers.SplitScopes` and `internal/helpers.JoinScopes` replace the three local `joinScopes` (server/access_token.go), `normalizeScopes` (server/flows.go), and `parseScopes` (server/cimd_cache.go) helpers. `SplitScopes` uses `strings.Fields` (any whitespace splits, matching the prior `parseScopes` behavior) — a tab-character-in-scope edge case that the old `normalizeScopes` preserved as a literal is now treated as a separator. RFC 6749 §3.3 specifies space-delimited scopes only, so legitimate inputs are unaffected.
  - **Breaking** for consumers who directly invoked `store.SaveTokenMetadataWithFamily(tokenID, userID, clientID, tokenType, audience, familyID, scopes)` etc. Migration: `store.SaveTokenMetadata(ctx, tokenID, storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: tokenType, Audience: audience, FamilyID: familyID, Scopes: scopes})`. The new method takes a `context.Context` first argument, matching the rest of the storage interfaces.
- **JWT/JWKS handling consolidated onto `github.com/go-jose/go-jose/v4`; `github.com/golang-jwt/jwt/v5` removed as a dependency**
  - `providers/oidc.JWK`, `providers/oidc.JWKS`, `providers/oidc.JWKSClient.FetchJWKS` now use `jose.JSONWebKey` / `jose.JSONWebKeySet`. The custom RSA/ECDSA public-key reconstruction from base64url N/E/X/Y is gone.
  - `providers/oidc.IDTokenClaims` embeds `josejwt.Claims` instead of `golang-jwt`'s `RegisteredClaims`; the registered-claim field set is preserved (`Issuer`, `Subject`, `Audience`, `IssuedAt`, `NotBefore`) — `ExpiresAt` is now `Expiry` per go-jose naming.
  - `providers/oidc` exports `ErrTokenExpired` and `ErrTokenNotValidYet` sentinels so callers (e.g. `flows_forwarded.go`) can `errors.Is` against the package's own errors instead of a third-party library's.
  - `server.AccessTokenIssuer` (JWT mode) signs via `jose.NewSigner` + `josejwt.Signed(...).Claims(...).Serialize()`. The algorithm allowlist is enforced by go-jose at parse time, removing the need for the manual `t.Method.Alg() != expectedAlg` keyfunc check.
  - Net diff is ~500 LOC removed; alg-confusion defense (CVE-2015-9235 style attacks) now lives in the parser instead of the keyfunc.
  - **Behavior change**: JWKS documents are now strictly validated at JSON-decode time. A malformed `n`/`e`/`x`/`y` value used to silently produce a JWK that would fail at signature verification later; with go-jose, the *whole JWKS document* fails to decode. Strictly an improvement (fail-fast on malformed JWKS) but technically observable: an error from `JWKSClient.FetchJWKS` may now surface earlier than before for the same malformed input.
  - **Breaking** for consumers who imported `oidc.JWK` / `oidc.JWKS` / `oidc.JWK.RSAPublicKey()` / `oidc.JWK.ECDSAPublicKey()` / `oidc.KeyTypeRSA` / `oidc.KeyTypeEC` directly. Use the corresponding `jose.JSONWebKey` / `jose.JSONWebKeySet` types from `github.com/go-jose/go-jose/v4`.
- **oauthconfig.StorageFromEnv: default prefix is now `OAUTH_`, and `VALKEY_ADDRESS` is renamed to `VALKEY_ADDR`**
  - `STORAGE_BACKEND` → `OAUTH_STORAGE_BACKEND`; `VALKEY_*` → `OAUTH_VALKEY_*`. The address var also shortens: `VALKEY_ADDRESS` → `OAUTH_VALKEY_ADDR` (matches Go ecosystem `*_ADDR` naming for env-var-facing names; the underlying `valkey.Config.Address` field is unchanged).
  - Aligns the storage loader's namespace with `FromEnv` (which already defaults to the `OAUTH_` prefix). Consumers using `StorageFromEnvWithPrefix("MUSTER_", …)` must switch to `StorageFromEnvWithPrefix("MUSTER_OAUTH_", …)` and rename their env vars accordingly.
- **oauthconfig.FromEnv validates `OAUTH_TRUSTED_AUDIENCES` at startup**
  - Each entry is now passed through `dex.ValidateAudiences`. Allowed charset is `[a-zA-Z0-9_-]` (per-entry max 256 chars, list max 50). Malformed values fail loudly at startup instead of silently failing token-acceptance later.
  - **Behaviour change**: URL-shaped audiences (e.g. `https://api.example.com`) are rejected. The package documented RFC 8707 URI audiences previously; in practice all in-tree consumers use Dex client-id-shaped audiences. Operators with URL-shaped audiences must populate `oauth.Config.TrustedAudiences` programmatically rather than via env.

### Added

- **oauthconfig.NewEncryptorFromEnv accepts hex-encoded keys**
  - `OAUTH_ENCRYPTION_KEY` is now decoded as base64 first (canonical, `openssl rand -base64 32`); on any failure the value is retried as hex (`openssl rand -hex 32`). Reinstates hex support that was dropped in an earlier refactor and broke operators with hex-generated keys.
  - Additive: existing base64 deployments are unaffected.
- **oauthconfig.FromEnv: cover `AllowLocalhostRedirectURIs` and `TrustedPublicRegistrationSchemes`**
  - New `OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS` (bool) and `OAUTH_TRUSTED_REDIRECT_SCHEMES` (comma-separated) env vars are now read by `FromEnv` / `FromEnvWithPrefix`. `OAUTH_TRUSTED_REDIRECT_SCHEMES` populates `server.Config.TrustedPublicRegistrationSchemes`.
  - Removes the need for downstream consumers (mcp-observability-platform, muster, mcp-prometheus) to set `srvCfg.AllowLocalhostRedirectURIs = true` and `srvCfg.TrustedPublicRegistrationSchemes = []string{...}` manually after `FromEnv()`.

### Fixed

- **`/oauth/introspect` response shape (RFC 7662 §2.2) (#306)**
  - `client_id` reflects the client the token was issued to (from stored token metadata for opaque tokens, from the verified `client_id` JWT claim in JWT mode).
  - `exp`, `iat`, `aud`, `iss`, `scope`, `sub`, `token_type` are populated from token metadata or verified JWT claims. `nbf` is included only when the JWT carries it.
  - `Cache-Control: no-store` + `Pragma: no-cache` are now set on the success path.
  - JWT-mode introspection consumes the verified claim map returned by `validateSelfIssuedJWT` in a single pass (no re-parse, no drift between the two verification paths).

- **`/authorize` validates `response_type` and redirects protocol errors per RFC 6749 §4.1.2.1 (#303)**
  - Missing or non-`code` `response_type` is rejected with `unsupported_response_type`.
  - `invalid_request` (missing or short `state`), `unsupported_response_type`, and `server_error` redirect to `redirect_uri` with `error` / `error_description` / `state` query parameters.
  - `invalid_client` (missing or unregistered `client_id`) and `invalid_redirect_uri` (missing, non-`http(s)`, or not registered for the client) return JSON `400`.

- **Treat email, profile, groups, offline_access as mandatory scopes (#252)**
  - `isMandatoryScope()` now returns true for `email`, `profile`, `groups`, and `offline_access` in addition to `openid` and cross-client audience scopes.
  - When an MCP client sends only custom scopes (e.g., `claudeai`), identity-critical scopes from the provider's defaults are now force-merged into the authorization request.
  - This fixes empty `email` claims and missing `groups` in ID tokens issued by Dex, which caused downstream MCP servers to reject tool calls with "authentication required".

### Changed

- **Raise DefaultMaxGroups from 500 to 600 and MaxTokenDataSize from 64KB to 256KB (#248)**
  - `DefaultMaxGroups` raised from 500 to 600 to accommodate enterprise OIDC environments where users have 500+ group memberships (e.g., large GitHub organizations with many teams).
  - `MaxTokenDataSize` raised from 64KB to 256KB. When Dex issues an `id_token` JWT containing hundreds of groups, the serialized token can exceed 64KB, causing all Valkey save operations to fail and breaking authentication entirely. 256KB still provides DoS protection while accommodating enterprise token sizes.

- **Lower MinStateLength absolute floor from 32 to 24 characters (#228)**
  - The absolute minimum floor for `MinStateLength` has been lowered from 32 to 24 characters.
  - 24 characters still provides 144 bits of entropy, exceeding OAuth 2.1's 128-bit minimum recommendation.
  - This unblocks VS Code web (`vscode.dev`) as an MCP client, which uses 24-character state parameters.
  - The default `MinStateLength` is also lowered from 32 to 24 to align with the new floor.
  - The `AllowNoStateParameter` workaround is no longer needed for VS Code web clients.

### Added

- **TokenRefreshHandler callback for provider token refresh events (#250)**
  - `SetTokenRefreshHandler` registers a callback that fires synchronously after a provider token is refreshed, either proactively (near-expiry) or reactively (expired token during validation).
  - Consumers can use this to update downstream caches (e.g., ID token caches for SSO forwarding) without a separate polling layer.
  - The handler receives the request context, user ID, family ID (session ID), and the freshly obtained provider token.
  - Follows the established `SessionCreationHandler` / `SessionRevocationHandler` pattern.

- **Dex provider scope filtering to strip non-standard client scopes (#245)**
  - Added `filterDexScopes()` mirroring the Google provider's `filterGoogleScopes()` pattern.
  - Non-standard scopes (e.g., `claudeai`) are now stripped before forwarding to Dex.
  - Supported scopes: standard OIDC (`openid`, `profile`, `email`, `offline_access`), Dex-specific (`groups`, `federated:id`), and cross-client audience scopes.

- **SessionCreationHandler callback for session initialization during login (#239)**
  - `SetSessionCreationHandler` registers a callback that fires synchronously during authorization code exchange when a new token family is created.
  - Consumers can use this to initialize per-session state (e.g., establish SSO connections) as part of the login flow itself.
  - The handler receives the request context, user ID, family ID (session ID), and the issued OAuth token (with id_token in Extra for OIDC flows).

- **Rename TokenFamilyRevocationHandler to SessionRevocationHandler (#239)**
  - `SetSessionRevocationHandler` replaces `SetTokenFamilyRevocationHandler` for consistent session lifecycle naming.
  - `TokenFamilyRevocationHandler` and `SetTokenFamilyRevocationHandler` remain as deprecated type aliases for backward compatibility.

- **Session ID exposed through request context for per-session state isolation (#237)**
  - `SessionIDFromContext(ctx)` returns a stable session identifier derived from the OAuth refresh token family.
  - The session ID is persisted in token metadata (survives server restarts).
  - `SetSessionRevocationHandler` (formerly `SetTokenFamilyRevocationHandler`) allows consumers to clean up session state on logout.
  - New `TokenMetadataStoreWithFamily` storage interface extends the progressive-extension chain with `SaveTokenMetadataWithFamily`.
  - Both in-memory and Valkey storage backends implement the new interface.

- **Limit HTTP request body size in handler (gosec G120) (#220)**
  - All POST handler methods (`ServeToken`, `ServeTokenRevocation`, `ServeTokenIntrospection`, `ServeClientRegistration`) now wrap the request body with `http.MaxBytesReader` before parsing form data or JSON payloads, preventing denial-of-service via oversized POST bodies.
  - Oversized requests receive a `413 Request Entity Too Large` response with consistent observability (HTTP metrics and tracing) across all endpoints.
  - New `MaxRequestBodySize` config option in `server.Config` (default: 1 MiB) allows tuning the limit. Negative values are corrected to the default with a warning.
  - Removed `G120` from the gosec exclude list in `Makefile.custom.mk`.

### Fixed

- **AllowNoStateParameter should also accept short state parameters (#225)**
  - **Bug**: When `AllowNoStateParameter=true`, the server correctly accepted empty state parameters but still rejected short (non-empty, < 32 chars) state parameters. This caused authentication failures for clients like VS Code's MCP client that send state parameters shorter than 32 characters.
  - **Root Cause**: The state length validation in `handler.go` (ServeAuthorization) and `server/validation.go` (validateStateParameter) did not check `AllowNoStateParameter` before rejecting short client states. The logic was inconsistent: allowing no state (least secure) while rejecting short state (more secure than none).
  - **Fix**: Split `validateStateParameter` into `validateClientStateParameter` (respects `AllowNoStateParameter`) and `validateProviderStateParameter` (always enforces minimum length). The `AllowNoStateParameter` flag now only affects client-facing state validation in the authorization request; server-generated provider state in OAuth callbacks is always validated unconditionally.
  - **Security**: Provider state validation in `ServeCallback` and `validateAndRetrieveAuthState` is no longer weakened by `AllowNoStateParameter`, maintaining defense-in-depth for the server-to-provider CSRF protection leg.
  - **Affected Components**: `handler.go`, `server/validation.go`, `server/flows.go`
- **ValidateGroups limit of 100 is too low for enterprise environments (#218)**
  - **Bug**: Users in enterprise environments (Active Directory, Azure AD, LDAP) with more than 100 OIDC groups were unable to authenticate. The `ValidateGroups` function rejected the entire authentication flow when the groups claim exceeded 100 items.
  - **Root Cause**: `ValidateGroups` used a hardcoded maximum of 100 groups, which is insufficient for enterprise IdP setups where users commonly have hundreds of group memberships.
  - **Fix**: Increased the default limit from 100 to 500 (`DefaultMaxGroups`). `ValidateGroups` now truncates groups exceeding the limit instead of rejecting the authentication, and returns a defensive copy. The Dex provider logs a warning when truncation occurs, ensuring authentication always succeeds even with very large group counts.
  - **Breaking**: `ValidateGroups` signature changed from `([]string) error` to `([]string, int) ([]string, bool, error)`. The second parameter sets the max group count (pass 0 for `DefaultMaxGroups`).
  - **New Config**: Added `MaxGroups` field to `dex.Config` allowing deployments to tune the limit. Added `Logger` field (`*slog.Logger`) for operational warnings.
  - **Affected Components**: `providers/oidc/validation.go`, `providers/dex/dex.go`
- **Valkey store: provider token TTL causes false refresh token reuse detection (#216)**
  - **Bug**: Valkey `SaveToken` used the upstream provider's access token expiry (e.g., 30 minutes from Dex) as the Valkey key TTL. When a provider token was stored alongside a long-lived refresh token (90 days), Valkey would evict it after 30 minutes. This caused `AtomicGetAndDeleteRefreshToken` to return `TOKEN_NOT_FOUND`, which triggered false positive reuse detection and forced users to re-authenticate.
  - **Root Cause**: `SaveToken` unconditionally used `token.Expiry` as the key TTL, not distinguishing between tokens with and without a refresh token.
  - **Fix**: When a token has a `RefreshToken` field set, `SaveToken` now uses the configurable `RefreshTokenTTL` (default 90 days) instead of the access token expiry. This ensures Valkey keeps the key long enough for the refresh token flow to complete, while still providing automatic cleanup of orphaned keys.
  - **Affected Components**: `storage/valkey/token.go`, `storage/valkey/store.go`
- **Memory store: orphaned provider tokens with refresh tokens never cleaned up**
  - Provider tokens with a `RefreshToken` field were permanently excluded from cleanup, even after the associated MCP refresh token was consumed or expired. This caused a slow memory leak for long-running servers.
  - Cleanup now also removes expired provider tokens whose key is no longer tracked as an active MCP refresh token.

### Changed

- **Remove go.mod from examples to prevent recursive Renovate updates.** Example `go.mod` files are now generated at build time via `make build-examples`. This eliminates the cycle where Renovate bumps the mcp-oauth dependency in examples, triggers a release, which triggers another Renovate update, and so on. CI now uses the same make target instead of a per-example matrix.

### Added

- **Dex cross-client audience scope helper functions (#201)**
  - Added `FormatAudienceScope(audience string) (string, error)` - Formats a client ID as a Dex cross-client audience scope (e.g., `"k8s-auth"` -> `"audience:server:client_id:k8s-auth"`)
  - Added `FormatAudienceScopes(audiences []string) ([]string, error)` - Formats multiple client IDs, filtering out empty strings
  - Added `AppendAudienceScopes(scopes string, audiences []string) (string, error)` - Appends audience scopes to existing OAuth scope strings
  - Added `ValidateAudience(audience string) error` - Validates a single audience string
  - Added `ValidateAudiences(audiences []string) error` - Validates multiple audience strings
  - Added `AudienceScopePrefix` constant - Exported prefix for checking/parsing audience scopes
  - Added `MaxAudienceLength` constant (256) - Maximum allowed audience string length
  - Added `MaxAudienceCount` constant (50) - Maximum audiences per call
  - **Use Case**: Enables SSO scenarios where a token needs to be valid for multiple downstream services (e.g., Kubernetes OIDC via dex-k8s-authenticator)
  - **Security**: All functions validate audience strings to prevent scope injection attacks:
    - Character whitelist: Only `[a-zA-Z0-9_-]` allowed (prevents space-based scope injection)
    - Length limit: Max 256 characters (prevents DoS via memory exhaustion)
    - Count limit: Max 50 audiences (prevents DoS via excessive processing)
  - **Reference**: [Dex Cross-Client Trust Documentation](https://dexidp.io/docs/custom-scopes-claims-clients/#cross-client-trust-and-authorized-party)

### Documentation

- **Documented Dex limitation: `prompt=none` not supported (#197)**
  - Updated `docs/silent-authentication.md` to correctly reflect that Dex does **not** honor `prompt=none`
  - Added detailed section explaining the limitation, related Dex issues, and workarounds
  - Updated Provider Support table with accurate silent auth support status for each provider
  - Added additional providers (Azure AD, Okta, Auth0, Keycloak) that fully support silent authentication

### Fixed

- **Refresh expired provider tokens before rejecting with 401**
  - **Problem**: Token responses advertised `expires_in: 3600` (from `AccessTokenTTL`) but `ValidateToken` checked the upstream provider token's expiry, which is often much shorter (e.g. 10-30 min for Dex). Requests failed with 401 well before the advertised lifetime.
  - **Fix**: `validateStoredToken` now attempts to refresh the provider token using its refresh token before rejecting. As long as the refresh token is valid, requests continue working transparently.
  - **Additional**: `generateAndStoreTokens` and `RefreshAccessToken` now cap token expiry to `min(AccessTokenTTL, providerToken.Expiry)` so `expires_in` accurately reflects the effective lifetime.
  - **Stale mapping fix**: Both the access-token and refresh-token storage keys are now updated when a provider token is refreshed, preventing stale credentials for providers that rotate refresh tokens (e.g. Dex).
  - **Refresh token preservation**: When a provider omits `refresh_token` in a refresh response (allowed by OAuth 2.0 RFC 6749 Section 5.1), the old refresh token is preserved.
  - **Singleflight deduplication**: Concurrent validation requests for the same expired token are coalesced into a single provider refresh call, preventing double-refresh races.
  - **Expiry cap safety**: The expiry cap now ignores provider tokens with past expiry (clock skew, provider bugs), preventing `expires_in <= 0` in token responses.

- **Cross-client audience scopes now merged with client-requested scopes (#203)**
  - **Problem**: When a client requested specific OAuth scopes during authorization, Dex provider's configured cross-client audience scopes were completely ignored instead of being merged. This broke SSO token forwarding scenarios where tokens need multiple audiences.
  - **Root Cause**: `CopyScopes` helper function used either client-requested scopes or provider default scopes, but not both. Cross-client audience scopes configured in provider defaults were lost when clients provided their own scopes.
  - **Fix**: Modified `CopyScopes` to merge mandatory scopes (cross-client audience scopes with prefix `audience:server:client_id:`) from defaults into client-requested scopes while avoiding duplicates.
  - **Use Case**: Enables SSO token forwarding scenarios where muster aggregator forwards tokens to mcp-kubernetes servers that use Kubernetes OIDC authentication. Tokens now correctly contain multiple audiences.
  - **New Constant**: Added `providers.CrossClientAudienceScopePrefix` for checking/parsing cross-client audience scopes.
  - **Startup Logging**: Server now logs configured mandatory audience scopes at startup, helping administrators understand which audiences will be automatically merged into all tokens.
  - **Enhanced Documentation**: Added comprehensive documentation in `providers/helpers.go` and `providers/dex/doc.go` explaining:
    - Mandatory scope merging behavior and its implications
    - That clients cannot opt out of configured audience scopes
    - Impact on token size and downstream service validation
  - **Reference**: [Dex Cross-Client Trust Documentation](https://dexidp.io/docs/custom-scopes-claims-clients/#cross-client-trust-and-authorized-party)

- **OAuth proxy now forwards OIDC parameters to upstream IdP (#195)**
  - **Problem**: When acting as an OAuth proxy, mcp-oauth was ignoring `prompt`, `login_hint`, and `id_token_hint` parameters from client authorization requests. Clients sending `prompt=none` for silent re-authentication would be redirected to the IdP without this parameter, causing the IdP to show the login page instead of attempting silent auth.
  - **Root Cause**: `StartAuthorizationFlow` in `server/flows.go` always passed `nil` for `AuthorizationURLOptions` to the provider, ignoring any OIDC parameters in the incoming request. The handler (`ServeAuthorization`) did not extract these parameters from the query string.
  - **Fix**:
    - `handler.go`: `ServeAuthorization` now extracts `prompt`, `login_hint`, `id_token_hint`, `max_age`, and `acr_values` from the authorization request query parameters
    - `server/flows.go`: `StartAuthorizationFlow` now accepts `*providers.AuthorizationURLOptions` and passes it to the provider's `AuthorizationURL` method
    - Audit logging now includes forwarded OIDC parameters (with privacy-aware handling for sensitive fields)
  - **Use Case**: Enables silent re-authentication through muster aggregator proxy. Users with active IdP sessions can now authenticate without manual account selection.
  - **OIDC Parameters Forwarded**:
    - `prompt=none` - Silent authentication (returns error if login/consent required)
    - `prompt=login` - Force re-authentication
    - `prompt=consent` - Force consent
    - `prompt=select_account` - Force account selection
    - `login_hint` - Pre-fill username/email at IdP
    - `id_token_hint` - Previously issued ID token as session hint
    - `max_age` - Maximum authentication age in seconds (forces re-auth if session too old)
    - `acr_values` - Authentication context class references (e.g., request MFA)
  - **Testing**: Added `TestStartAuthorizationFlow_OIDCParameterForwarding` and `TestHandler_ServeAuthorization_OIDCParameterForwarding` with comprehensive test cases covering all OIDC parameters
  - **References**: [OpenID Connect Core 1.0 Section 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
  - **Security Hardening**: Added input validation for OIDC parameters (defense-in-depth):
    - `prompt`: Whitelist validation - only `none`, `login`, `consent`, `select_account` accepted (max 128 chars)
    - `login_hint`: Length limit of 256 characters (typical email length)
    - `id_token_hint`: Length limit of 64KB (matches `maxSubjectTokenLength`)
    - `acr_values`: Length limit of 1024 characters
    - Invalid/oversized parameters are silently ignored (not forwarded), matching OIDC spec behavior
  - **Documentation**: Updated `docs/silent-authentication.md` with trust model and security validation details

- **Provider Token Not Saved for SSO Token Forwarding (#193)**
  - **Bug**: Provider tokens (from upstream IdP like Dex) were not being saved in Valkey storage, breaking SSO token forwarding. User info was saved but tokens were missing.
  - **Root Cause**: The `SaveToken` function uses the access token's expiry as the storage TTL. When the provider's access token has a short lifetime (5-15 minutes) or is already expired, `SaveToken` would fail with "token already expired" or the token would be evicted quickly by Valkey.
  - **Fix**: Added `ProviderTokenTTL` configuration (default: 24 hours) and extended provider token expiry before saving for user lookup. This ensures tokens remain available for SSO forwarding regardless of access token lifetime.
  - **New Configuration**: `Config.ProviderTokenTTL` - controls how long provider tokens are stored (default: 86400 seconds = 24 hours)
  - **Affected Components**: `server/flows.go` - new `extendTokenExpiryForStorage()` function in `saveUserInfoAndToken()`
  - **Implementation**: Uses `storage.ExtractTokenExtra()` to preserve all `KnownExtraFields` (id_token, scope, expires_in) - ensures consistency with storage layer and future extensibility
  - **Testing**: Added `TestServer_HandleProviderCallback_ShortLivedToken` and `TestServer_ExtendTokenExpiryForStorage` tests covering all edge cases
  - **Security**: Added validation for `ProviderTokenTTL` configuration:
    - Negative values are automatically corrected to default (24 hours) with error log
    - Values below 1 hour generate warning about potential SSO forwarding issues
    - Values exceeding 7 days generate warning about stale token accumulation
    - Defined constants: `MinProviderTokenTTL` (1 hour), `MaxProviderTokenTTL` (7 days), `DefaultProviderTokenTTL` (24 hours)

### Added

- **Valkey Storage Instrumentation Support (#191)**
  - **Feature**: Added OpenTelemetry instrumentation to Valkey storage backend for observability parity with memory storage
  - **Use Case**: Enables Prometheus/Grafana dashboards to monitor storage size metrics (`storage.tokens.count`, `storage.clients.count`, `storage.flows.count`, etc.) when using Valkey backend
  - **New Methods**:
    - `Store.SetInstrumentation(inst)` - Sets OpenTelemetry instrumentation for the store
    - Storage size callbacks for Prometheus gauges using SCAN operations
  - **Tracing**: Added tracing spans for ALL storage operations with `storage.backend=valkey` attribute:
    - Token operations: `save_token`, `get_token`, `delete_token`
    - User info: `save_user_info`, `get_user_info`
    - Client operations: `save_client`, `get_client`, `list_clients`, `validate_client_secret`, `check_ip_limit`, `track_client_ip`
    - Flow operations: `save_authorization_state`, `get_authorization_state`, `get_authorization_state_by_provider_state`, `delete_authorization_state`, `save_authorization_code`, `get_authorization_code`, `atomic_check_and_mark_auth_code_used`, `delete_authorization_code`
    - Refresh token operations: `save_refresh_token`, `get_refresh_token_info`, `delete_refresh_token`, `atomic_get_and_delete_refresh_token`, `save_refresh_token_with_family`, `get_refresh_token_family`, `revoke_refresh_token_family`
    - Revocation: `revoke_all_tokens_for_user_client`, `get_tokens_by_user_client`
  - **Metrics**: Storage operations now record duration and success/error metrics via `RecordStorageOperation`
  - **Span Kind**: All storage spans use `SpanKindClient` for proper trace visualization
  - **Thread Safety**: Instrumentation fields are protected by mutex for safe concurrent access
  - **DRY Implementation**: Refactored instrumentation using `tracedOp` helper struct to reduce boilerplate across all storage methods
  - **Implementation Notes**:
    - Storage size counting uses SCAN operations which are efficient for periodic metrics scraping
    - Tracing spans include operation name and backend type for filtering in observability tools
    - Both memory and Valkey storage backends now include `storage.backend` attribute and `SpanKindClient` for consistent filtering
  - **Grafana Dashboard Support**: Fixes "No data" panels in mcp-kubernetes Grafana dashboards for storage metrics when using Valkey backend

- **OIDC Prompt Parameter and Silent Authentication Support**
  - **Feature**: New `AuthorizationURLOptions` struct for optional OIDC parameters in authorization requests
  - **Use Case**: Enables silent re-authentication flows where MCP clients can attempt token refresh without user interaction when an IdP session already exists
  - **New Types**:
    - `providers.AuthorizationURLOptions` - Contains optional OIDC parameters: `Prompt`, `LoginHint`, `MaxAge`, `ACRValues`, `IDTokenHint`, `Extra`
    - `oauth.SilentAuthError` - Error type for silent authentication failures
    - `oauth.CallbackResult` - Structured result type for OAuth callbacks with `Err()` and `IsError()` methods
  - **New Functions**:
    - `oauth.ParseOAuthError(code, description)` - Parses OAuth error responses into appropriate error types
    - `oauth.IsSilentAuthError(err)` - Detects if an error indicates silent auth failed and interactive login is required
    - `oauth.ParseCallbackQuery(...)` - Convenience function for parsing OAuth callback query parameters
    - `providers.ApplyAuthorizationURLOptions(opts)` - Shared helper for converting options to oauth2.AuthCodeOption
    - `providers.CopyScopes(requested, defaults)` - Shared helper for safe scope copying
  - **New Constants**:
    - `ErrorCodeLoginRequired`, `ErrorCodeConsentRequired`, `ErrorCodeInteractionRequired`, `ErrorCodeAccountSelectionRequired` - OIDC silent auth error codes
  - **New Sentinel Error**: `oauth.ErrSilentAuthFailed` - Indicates silent authentication is not possible
  - **OIDC Parameters Supported**:
    - `prompt=none` - Silent authentication (no UI displayed, error if login/consent required)
    - `prompt=login` - Force re-authentication even if session exists
    - `prompt=consent` - Force consent even if previously granted
    - `prompt=select_account` - Force account selection
    - `login_hint` - Pre-fill username/email at IdP
    - `max_age` - Maximum authentication age in seconds
    - `acr_values` - Authentication context class references
    - `id_token_hint` - Previously issued ID token as session hint
  - **Provider Support**: Google, GitHub (partial - uses `login` param), Dex, and Mock providers updated
  - **References**: [OpenID Connect Core 1.0 Section 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)

### Changed

- **BREAKING**: `Provider.AuthorizationURL` interface signature changed
  - **Old**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string) string`
  - **New**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string, opts *AuthorizationURLOptions) string`
  - **Migration**: Pass `nil` as the last parameter for existing code to maintain current behavior
  - **Reason**: Enables optional OIDC parameters for silent authentication and other advanced flows

- **BREAKING**: `TokenStore.AtomicGetAndDeleteRefreshToken` signature changed
  - **Old**: `AtomicGetAndDeleteRefreshToken(ctx, refreshToken) (userID string, providerToken *oauth2.Token, err error)`
  - **New**: `AtomicGetAndDeleteRefreshToken(ctx, refreshToken) (userID string, clientID string, providerToken *oauth2.Token, err error)`
  - **Reason**: Returns `clientID` for client binding validation per OAuth 2.1 Section 6
  - **Migration**: Update all `TokenStore` implementations to return the `clientID` from token metadata

### Fixed

- **Token endpoint now includes `id_token` from upstream provider in response (#189)**
  - **Problem**: The token endpoint (`/oauth/token`) was not forwarding the `id_token` from upstream OIDC providers (e.g., Dex, Google) to clients, breaking OIDC silent re-authentication flows that rely on `id_token_hint` and `login_hint`
  - **Root Cause**: `writeTokenResponse()` in `handler.go` only included `access_token`, `token_type`, `expires_in`, `refresh_token`, and `scope` in the response. The `id_token` from the provider's token response was stored internally but never forwarded
  - **Fix**:
    - `server/flows.go`: `generateAndStoreTokens()` now extracts `id_token` from `authCode.ProviderToken.Extra("id_token")` and includes it in the token response using `WithExtra()`
    - `server/flows.go`: `RefreshAccessToken()` now forwards `id_token` from the provider's refresh response when present
    - `handler.go`: `writeTokenResponse()` now includes `id_token` in the JSON response when present in the token's Extra field
    - `types.go`: Added `IDToken` field to `TokenResponse` struct for proper deserialization
  - **Impact**: Clients can now extract user identity from `id_token` for `login_hint` and use `id_token_hint` for OIDC silent re-authentication with `prompt=none`
  - **OIDC Compliance**: Per [OpenID Connect Core 1.0 Section 3.1.3.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse), the `id_token` is REQUIRED in token responses for OIDC flows

### Security

- **Input Validation for `client_name` in All Client Registration Paths**
  - **Feature**: Added comprehensive input validation for the `client_name` field during both dynamic client registration (`/register` endpoint) and Client-Initiated Metadata Discovery (CIMD) flows
  - **Defense-in-Depth**: Validation prevents potential stored XSS and script injection if the value is ever displayed in HTML contexts, JavaScript strings, template literals, or markdown renderers
  - **Log Injection Prevention**: Newlines are now rejected to prevent log line splitting attacks where attackers could forge log entries
  - **Validation Rules**:
    - Must not contain HTML-like characters (`<` or `>`)
    - Must not contain quote characters (`'`, `"`, backtick) that enable script/template injection
    - Must not exceed 256 characters (runes, not bytes - proper Unicode handling)
    - Must contain only printable characters (no control characters)
    - Must not contain newline characters (`\n`, `\r`) to prevent log injection
  - **Error Handling**: Invalid `client_name` values return `400 Bad Request` with a descriptive error message
  - **Shared Implementation**: Validation logic moved to `internal/helpers.ValidateClientName` for consistent enforcement across all entry points
  - **References**: [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-117](https://cwe.mitre.org/data/definitions/117.html) (Log Injection)

- **OAuth 2.1 Client Binding for Refresh Tokens**
  - **Feature**: Refresh tokens are now bound to the client that was originally issued the token, per OAuth 2.1 Section 6
  - **Security Benefit**: Prevents cross-client token theft attacks where an attacker with a stolen refresh token attempts to use it from a different client
  - **Secure by Default**: Tokens without client binding are rejected - no insecure fallback option
  - **Implementation Details**:
    - Uses constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks
    - Rate-limited security event logging to prevent DoS via log flooding
    - Comprehensive audit events for security monitoring
  - **Upgrade Impact**: Existing refresh tokens issued before this version will be invalidated - users must re-authenticate
  - **New Metric**: `oauth.refresh_token.legacy_rejected` - Tracks rejected legacy tokens (for observability)
  - **New Security Events**:
    - `EventRefreshTokenMissingClientBinding`: When a token without client binding is rejected
    - `EventRefreshTokenClientBindingMismatch`: Critical event when client IDs don't match (possible attack)
  - **New Handler Method**: `authenticateRefreshTokenClient` - Enforces OAuth 2.1 Section 6 requiring confidential clients to authenticate on refresh

### Added

- **RFC 8693 Token Exchange Client for Cross-Cluster SSO**
  - **Feature**: New `TokenExchangeClient` in `providers/oidc` package implements RFC 8693 OAuth 2.0 Token Exchange
  - **Use Case**: Enables cross-cluster SSO scenarios where each cluster has its own Identity Provider (e.g., separate Dex instances)
  - **Problem Solved**: When Muster on Cluster A needs to call mcp-kubernetes on Cluster B, and each cluster has its own Dex, tokens from Cluster A's Dex are not valid on Cluster B. Token exchange allows exchanging a token from one Dex for a token from another Dex.
  - **New Types**:
    - `oidc.TokenExchangeClient` - Client for performing RFC 8693 token exchanges
    - `oidc.TokenExchangeRequest` - Request parameters including subject token, connector ID, and optional scopes
    - `oidc.TokenExchangeResponse` - Response with the exchanged access token
    - `oidc.TokenExchangeCache` - Thread-safe cache for exchanged tokens to reduce exchange requests
  - **New Constants**:
    - `oidc.GrantTypeTokenExchange` - RFC 8693 grant type URN
    - `oidc.TokenTypeIDToken`, `oidc.TokenTypeAccessToken`, `oidc.TokenTypeRefreshToken`, `oidc.TokenTypeJWT` - Token type URNs
  - **Security Features**:
    - SSRF protection with DNS rebinding prevention (configurable via `AllowPrivateIP` for internal deployments)
    - HTTPS enforcement for all token endpoints
    - Response size limiting (1MB) to prevent memory exhaustion
    - Subject token size limiting (64KB) to prevent DoS attacks
    - Security event logging at Warn level for SSRF detection and monitoring
    - Cache key security documentation to prevent cache poisoning
    - Rate limiting guidance for production deployments
  - **Dex Integration**: Works with Dex's token exchange implementation via the `connector_id` parameter
  - **Example Usage**:
    ```go
    client := oidc.NewTokenExchangeClient(logger)
    resp, err := client.Exchange(ctx, oidc.TokenExchangeRequest{
        TokenEndpoint:    "https://dex.cluster-b.example.com/token",
        SubjectToken:     userIDToken,
        SubjectTokenType: oidc.TokenTypeIDToken,
        ConnectorID:      "cluster-a-dex",
        Scope:            "openid profile email groups",
    })
    ```
  - **Related**: giantswarm/muster#275 - Investigate Dex Token Exchange (RFC 8693) for cross-cluster SSO

- **SSO Validation Metadata via TokenSource Field**
  - **Feature**: Added `TokenSource` field to `providers.UserInfo` to indicate how the user was authenticated
  - **Use Case**: Downstream MCP servers can now distinguish between normal OAuth flow tokens and SSO-forwarded tokens
  - **Problem Solved**: When SSO token forwarding is used, downstream servers need to know whether to look up a stored ID token from the token store or use the Bearer token directly for downstream authentication (e.g., Kubernetes API auth)
  - **New Types**:
    - `providers.TokenSource` type with constants `TokenSourceOAuth` and `TokenSourceSSO`
  - **New Methods on `UserInfo`**:
    - `IsSSO() bool` - Returns true if authenticated via SSO token forwarding
    - `IsOAuth() bool` - Returns true if authenticated via normal OAuth flow (default)
  - **Backward Compatible**: Empty `TokenSource` is treated as `TokenSourceOAuth` for backward compatibility with existing code
  - **Related**: Unblocks SSO token forwarding + downstream OAuth in mcp-kubernetes and other MCP servers

- **Security assessment reports**
  - Added comprehensive security assessment reports from three AI systems:
    - Claude Opus 4.5: Full codebase security review with OAuth 2.1 compliance analysis
    - GPT-5.2-Codex: Security assessment with high-severity finding on refresh token client binding
    - Gemini 3 Pro: Security assessment focusing on compliance, data protection, and infrastructure
  - Reports document OAuth 2.1 compliance, cryptographic implementations, SSRF protections, and security controls

- **TrustedAudiences Support for SSO Token Forwarding**
  - **Feature**: Added `TrustedAudiences` configuration option to accept tokens issued to trusted upstream OAuth clients
  - **Use Case**: Enables Single Sign-On (SSO) scenarios in MCP architectures where an aggregator (like muster) proxies requests to downstream MCP servers
  - **Problem Solved**: Previously, each downstream MCP server required separate authentication, even when all services use the same Identity Provider
  - **Configuration**: `TrustedAudiences []string` in `server.Config`
  - **Security Model**:
    - The server's own `ResourceIdentifier` is always implicitly trusted
    - Each trusted audience must be explicitly configured (no implicit trust)
    - Tokens are only accepted if they're from the same configured issuer
    - Audit event `EventCrossClientTokenAccepted` is logged when a token is accepted via cross-client trust
  - **Backward Compatibility**: Empty `TrustedAudiences` maintains current behavior (only own tokens accepted)
  - **Example**:
    ```go
    config := &server.Config{
        Issuer:             "https://auth.example.com",
        ResourceIdentifier: "https://mcp-kubernetes.example.com",
        // Accept tokens issued to the muster aggregator
        TrustedAudiences:   []string{"muster-client"},
    }
    ```
  - **New Audit Event**: `EventCrossClientTokenAccepted` for security monitoring of SSO token usage
  - **Issue**: [#171](https://github.com/giantswarm/mcp-oauth/issues/171)

- **JWT/JWKS Validation for SSO ID Token Forwarding**
  - **Bug Fix**: Fixed ID token forwarding failures when `TrustedAudiences` is configured
  - **Root Cause**: The `ValidateToken` middleware was calling the IdP's userinfo endpoint before checking for JWT tokens with trusted audiences. Many IdPs reject ID tokens at the userinfo endpoint (which expects access tokens).
  - **Solution**: When `TrustedAudiences` is configured, the middleware now:
    1. Detects if the Bearer token is a JWT
    2. Validates the JWT signature using the provider's JWKS endpoint
    3. Checks if the `aud` claim matches a trusted audience
    4. Extracts user info directly from JWT claims
    5. Falls back to userinfo validation only if JWT validation fails
  - **New Provider Interface**: Added `JWKSProvider` interface for providers that support JWKS-based JWT validation
  - **Provider Support**: Google and Dex providers now expose their JWKS URIs for JWT validation
  - **Security Features**:
    - SSRF protection for JWKS URI fetching (blocks private IPs, loopback, link-local addresses)
    - DNS rebinding protection: Validates resolved IPs at connection time, not just URL parsing time
    - Response body size limit (1MB) prevents memory exhaustion attacks
    - JWKS key count limit (100 keys) prevents DoS via excessive keys
    - JWKS documents cached for 1 hour (configurable)
    - Signature verification using RSA and ECDSA keys from JWKS
    - Algorithm restriction (RSA and ECDSA only) prevents algorithm confusion attacks (CVE-2015-9235)
    - Enhanced URL normalization for audience comparison (case-insensitive host, default port removal)
    - Clock skew tolerance (30 seconds) for time-based claims (exp, nbf, iat)
  - **New Audit Event**: `EventForwardedIDTokenAccepted` (`forwarded_id_token_accepted`): Logged when JWT validation succeeds
  - **New Validation Function**: `ValidateExternalURL()` for generic SSRF-protected URL validation
  - **Issue**: [#173](https://github.com/giantswarm/mcp-oauth/issues/173)

- **DNS Rebinding Protection for JWKS Fetching**
  - **Security Enhancement**: Added DNS rebinding attack protection to the SSRF-safe HTTP client
  - **How It Works**: Validates resolved IP addresses at connection time, not just during URL parsing
  - **Why It Matters**: Attackers can't use DNS rebinding to bypass SSRF protection and access internal services
  - **New Functions**:
    - `SSRFSafeDialContext()`: Creates a dial function that validates resolved IPs
    - `NewSSRFSafeHTTPClient()`: Creates an HTTP client with DNS rebinding protection
  - **Default Behavior**: JWKS client automatically uses SSRF-safe HTTP client when no custom client is provided

- **Enhanced URL Normalization for Audience Comparison**
  - **Security Enhancement**: Stricter URL normalization prevents audience matching bypasses
  - **Normalization Rules**:
    - Case-insensitive scheme and host (`HTTPS://EXAMPLE.COM` equals `https://example.com`)
    - Default port removal (`:443` for HTTPS, `:80` for HTTP)
    - Trailing slash removal
    - Path case preserved (paths remain case-sensitive)
  - **Why It Matters**: Prevents attackers from bypassing audience checks using case or port variations

- **ECDSA Key Support for JWT Validation**
  - **Feature**: Added support for ECDSA (EC) keys in addition to RSA for JWT signature verification
  - **Supported Curves**: P-256 (ES256), P-384 (ES384), P-521 (ES512)
  - **Why It Matters**: Many modern IdPs use ECDSA keys for better performance with equivalent security

- **Google Provider: ForceConsent Configuration for Reliable Refresh Tokens**
  - **Feature**: Added `ForceConsent` configuration option to the Google OAuth provider
  - **Root Cause**: Google only returns refresh tokens on the first user consent. Subsequent authorizations return no refresh token, causing token refresh failures.
  - **Solution**: The Google provider now adds `prompt=consent` to authorization URLs by default, ensuring refresh tokens are always returned
  - **Configuration**: `ForceConsent` field in `google.Config` (default: `true`)
  - **Backward Compatibility**: Existing code benefits automatically since `ForceConsent` defaults to `true`
  - **Opt-out**: Set `ForceConsent` to a pointer to `false` if you don't need refresh tokens or prefer fewer consent prompts
  - **Example**:
    ```go
    provider, err := google.NewProvider(&google.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-secret",
        RedirectURL:  "https://example.com/callback",
        // ForceConsent defaults to true for reliable refresh tokens
    })
    ```
  - **References**: [Google OAuth 2.0 Offline Access](https://developers.google.com/identity/protocols/oauth2/web-server#offline)
  - **Issue**: [#168](https://github.com/giantswarm/mcp-oauth/issues/168)

- **AllowPrivateIPJWKS Configuration Option for Private IdP Deployments**
  - **Feature**: Added configuration option to allow JWKS endpoints to resolve to private IP addresses during SSO token validation
  - **Use Case**: Enables SSO token forwarding (TrustedAudiences) with private Identity Provider deployments (e.g., internal Dex)
  - **Problem Solved**: Previously, JWKS fetching for JWT validation was blocked by SSRF protection when the IdP runs on private networks
  - **Configuration**: `AllowPrivateIPJWKS` in `server.Config` (default: `false` for security)
  - **Security**: When enabled, relaxes SSRF protection for JWKS fetching only to allow:
    - Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
    - Loopback addresses: 127.0.0.0/8, ::1
    - Link-local addresses: 169.254.0.0/16, fe80::/10
  - **HTTPS Enforcement**: HTTPS is still required even when AllowPrivateIPJWKS is enabled
  - **Warning**: Only enable for trusted internal network deployments where the IdP legitimately runs on private networks
  - **Logging**: When enabled, logs a startup warning at `Warn` level to ensure operator visibility
  - **New API**:
    - `JWKSClientOptions` struct for configurable JWKS client creation
    - `NewJWKSClientWithOptions()` function for creating JWKS clients with custom options
    - `NewPrivateIPAllowedHTTPClient()` for HTTP client without SSRF protection
  - **Example**:
    ```go
    config := &server.Config{
        Issuer:             "https://auth.internal.example.com",
        TrustedAudiences:   []string{"muster-client"},
        AllowPrivateIPJWKS: true, // Allow JWKS fetching from internal Dex
    }
    ```
  - **Issue**: [#175](https://github.com/giantswarm/mcp-oauth/issues/175)

- **AllowPrivateIPClientMetadata Configuration Option for Internal Network CIMD**
  - **Feature**: Added configuration option to allow CIMD (Client ID Metadata Document) metadata URLs that resolve to private IP addresses
  - **Use Case**: Enables MCP aggregators and servers to communicate over internal/private networks (home labs, air-gapped environments, enterprise intranets)
  - **Configuration**: `AllowPrivateIPClientMetadata` in `server.Config` (default: `false` for security)
  - **Security**: When enabled, relaxes SSRF protection to allow:
    - Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
    - Loopback addresses: 127.0.0.0/8, ::1
    - Link-local addresses: 169.254.0.0/16, fe80::/10
  - **Warning**: Only enable for trusted internal network deployments. PKCE and other OAuth security measures still apply.
  - **Logging**: When enabled, logs a startup warning at `Warn` level to ensure operator visibility, and logs each private IP fetch at `Info` level for audit trail.
  - **Example**:
    ```go
    config := &server.Config{
        Issuer: "https://auth.internal.example.com",
        EnableClientIDMetadataDocuments: true,
        AllowPrivateIPClientMetadata: true, // Allow fetching from internal network
    }
    ```
  - **Issue**: [#164](https://github.com/giantswarm/mcp-oauth/issues/164)

- **CIMD Metrics Callbacks for Observability**
  - **Feature**: Added instrumentation callbacks for Client ID Metadata Document (CIMD) operations
  - **New Metrics**:
    - `oauth.cimd.fetch.total`: Counter for CIMD metadata fetch attempts (labels: `result=success/error/blocked`)
    - `oauth.cimd.fetch.duration`: Histogram for CIMD metadata fetch duration in milliseconds
    - `oauth.cimd.cache.total`: Counter for CIMD cache operations (labels: `operation=hit/miss/negative_hit`)
  - **API Methods**:
    - `RecordCIMDFetch(ctx, result, durationMs)`: Record fetch attempts with outcome and duration
    - `RecordCIMDCache(ctx, operation)`: Record cache hit/miss/negative_hit events
  - **Use Case**: Enables consumers to monitor CIMD performance, track cache efficiency, and observe blocked requests (SSRF protection)
  - **Issue**: [#148](https://github.com/giantswarm/mcp-oauth/issues/148)

- **Client ID Metadata Documents (CIMD) Documentation and Example**
  - **Feature**: Comprehensive documentation and example for Client ID Metadata Documents support
  - **Documentation**: New `docs/cimd.md` with complete reference covering:
    - What CIMD is and when to use it
    - Configuration options (`EnableClientIDMetadataDocuments`, `ClientMetadataFetchTimeout`, `ClientMetadataCacheTTL`)
    - Client metadata document format and field reference
    - How the authorization flow works with CIMD
    - Security features (SSRF protection, negative caching, rate limiting)
    - Caching behavior and troubleshooting guide
  - **Example**: New `examples/cimd/` directory with:
    - Complete server implementation with CIMD enabled
    - Sample `client.json` metadata document
    - Detailed README with setup and usage instructions
  - **README Updates**: Added CIMD to main README features, documentation table, and examples list
  - **Issue**: [#145](https://github.com/giantswarm/mcp-oauth/issues/145)

- **Trusted Public Registration Schemes (Cursor/IDE Compatibility)**
  - **Feature**: Allow unauthenticated client registration for clients using trusted custom URI schemes (`cursor://`, `vscode://`, etc.)
  - **Use Case**: MCP clients like Cursor that don't support registration tokens can now register without authentication when using custom URI schemes
  - **Security**: Two-layer protection: PKCE (primary defense) + custom URI scheme OS-level registration
  - **Configuration**:
    - `TrustedPublicRegistrationSchemes`: List of schemes allowed for token-free registration (e.g., `["cursor", "vscode"]`)
    - `DisableStrictSchemeMatching`: Explicit opt-out for mixed scheme support (not recommended); strict matching is enabled by default
  - **Security Hardening**:
    - HTTP/HTTPS schemes are automatically blocked from trusted schemes (they can be hijacked by any attacker with a web server)
    - Dangerous schemes (`javascript:`, `data:`, `file:`, etc.) are automatically filtered out
    - Pre-computed trusted schemes map for O(1) lookup performance
    - Documentation clarifies that PKCE is the primary security control, with platform-specific scheme protection as defense-in-depth
  - **Audit Logging**: New event type `client_registered_via_trusted_scheme` for security monitoring
  - **Documentation**: Updated security guide with Cursor compatibility section and platform security considerations
  - **Issue**: [#141](https://github.com/giantswarm/mcp-oauth/issues/141)

### Changed

- **Refactored Error Types for Cleaner API**
  - **Change**: Renamed `OAuthError` to `Error` and `NewOAuthError` to `NewError` for a cleaner, more idiomatic Go API
  - **Backward Compatibility**: Type alias `OAuthError` and function alias `NewOAuthError` are provided for backward compatibility
  - **Migration**: Update your code to use `oauth.Error` and `oauth.NewError`. The aliases will be removed in a future major version.
  - **Example**:
    ```go
    // Before (deprecated)
    err := oauth.NewOAuthError("invalid_request", "Missing parameter", 400)
    var oauthErr *oauth.OAuthError

    // After (recommended)
    err := oauth.NewError("invalid_request", "Missing parameter", 400)
    var oauthErr *oauth.Error
    ```

- **Code Quality Improvements**
  - Reduced cyclomatic and cognitive complexity across the codebase
  - Extracted shared helper functions to reduce code duplication (DRY principle)
  - Added generic helpers for common patterns (`lookupWithTracing`, `getAndUnmarshal`, `ExchangeCodeWithPKCE`)
  - Introduced `metricsBuilder` pattern for cleaner metrics initialization
  - Moved shared constants to `storage/storage.go` for consistency

- **Internal Package Rename**
  - Renamed `internal/util` to `internal/helpers` for clarity (internal change, no public API impact)

### Deprecated

- **`OAuthError` type**: Use `Error` instead. Alias provided for backward compatibility.
- **`NewOAuthError` function**: Use `NewError` instead. Alias provided for backward compatibility.

### Fixed

- **Valkey storage: ProviderToken Extra field (id_token) now preserved during authorization code serialization (#158)**
  - **Problem**: When using Valkey storage, the `id_token` in the `ProviderToken.Extra` field was lost during authorization code serialization, causing downstream OIDC authentication to fail
  - **Root Cause**: `oauth2.Token` stores Extra fields (like `id_token`) in a private `raw` field that is NOT serialized by standard `json.Marshal`. The `authorizationCodeJSON` struct was directly embedding `*oauth2.Token`, which lost these fields
  - **Fix**: Changed `authorizationCodeJSON.ProviderToken` to use `*serializableToken` instead of `*oauth2.Token`, which explicitly captures and serializes the Extra fields
  - **Impact**: Authorization codes with provider tokens now correctly preserve id_token and other Extra fields through Valkey serialization
  - **Related**: Same pattern was already applied to direct token storage in commit `878730a` for issue #133

- **Google provider now filters out `offline_access` scope (#156)**
  - **Problem**: When clients requested the standard OIDC `offline_access` scope, the Google provider passed it directly to Google's authorization endpoint, causing `Error 400: invalid_scope`
  - **Root Cause**: Google doesn't support `offline_access` as a scope - it uses `access_type=offline` as a URL parameter instead (which was already being set correctly)
  - **Fix**: Filter out `offline_access` from scopes before passing to Google, since the equivalent functionality is already provided via `access_type=offline`
  - **Impact**: OIDC-compliant clients that request `offline_access` scope will now work correctly with the Google provider

- **JSON Injection Vulnerability in Example Code**
  - **Bug**: The `mcpHandler()` in basic and production examples used `fmt.Sprintf` to construct JSON responses with user-controlled data (`userInfo.Name`, `userInfo.Email`, `userInfo.ID`), allowing potential JSON injection if user data contained special characters like `"` or `\`
  - **Fix**: Replaced with proper struct types and `json.NewEncoder()` for safe serialization
  - **Affected Examples**: `examples/basic/main.go`, `examples/production/main.go`
  - **Security**: Added `X-Content-Type-Options: nosniff` header to prevent MIME type sniffing attacks

- **CIMD: Authorization flow now uses getOrFetchClient**
  - **Bug**: URL-based client IDs were not working in authorization flow because `StartAuthorizationFlow` and `ExchangeAuthorizationCode` used direct `clientStore.GetClient()` instead of `getOrFetchClient()` ([#143](https://github.com/giantswarm/mcp-oauth/issues/143))
  - **Root Cause**: When `EnableClientIDMetadataDocuments` was enabled, the authorization flow bypassed the CIMD-aware client lookup function
  - **Fix**: Changed `clientStore.GetClient()` to `getOrFetchClient()` in `flows.go` at lines 338 and 705
  - **Impact**: MCP clients using URL-based client IDs per MCP 2025-11-25 spec now work correctly in the full OAuth flow
  - **Testing**: Added unit tests for `getOrFetchClient` behavior with non-URL clients, CIMD disabled, cache hits, and negative cache hits

- **Token Encryption Preserves Extra Field**
  - **Bug**: Token encryption was losing the `Extra` field (`id_token`, `scope`) from `oauth2.Token`, breaking downstream OIDC authentication ([#133](https://github.com/giantswarm/mcp-oauth/issues/133))
  - **Root Cause**: `encryptToken()` and `decryptToken()` created new tokens without copying the private `raw` field
  - **Fix**: Extract known extra fields (`id_token`, `scope`, `expires_in`) before encryption and restore them using `WithExtra()` after encryption/decryption
  - **Affected Components**: `storage/memory/memory.go`, `storage/valkey/store.go`
  - **Testing**: Added regression tests for Extra field preservation with and without encryption enabled

- **Token Lookup by Email Fails When Dex Subject Claim Differs**
  - **Bug**: When using mcp-oauth with Dex as the OIDC provider, looking up tokens by `userInfo.Email` failed because tokens were only stored by email if it differed from `userInfo.ID` ([#154](https://github.com/giantswarm/mcp-oauth/issues/154))
  - **Root Cause**: The condition `userInfo.Email != userInfo.ID` prevented email storage when the comparison was not properly evaluated. With Dex, the subject claim is a base64-encoded identifier (e.g., `Cg1tYXJrdGVzdGVyQGdtYWlsLmNvbQoFbG9jYWw`), not the email
  - **Fix**: Always save tokens by email when email is available, regardless of whether it equals the ID. This is idempotent and ensures downstream consumers can reliably use email for lookups
  - **Affected Components**: `server/flows.go` - `saveUserInfoAndToken` function
  - **Testing**: Added test `TestServer_HandleProviderCallback_EmailLookup` that simulates Dex's base64-encoded subject claims

### Security

- **ID Token Encryption at Rest**
  - **Enhancement**: The `id_token` is now encrypted at rest when token encryption is enabled
  - **Rationale**: The `id_token` contains PII (user email, name, subject) that should be protected
  - **Implementation**: Added `SensitiveExtraFields` allowlist in `storage/token.go` with `EncryptExtraFields()` and `DecryptExtraFields()` helpers
  - **Scope/Expires_in**: Non-sensitive fields like `scope` and `expires_in` are preserved but not encrypted

### Added

- **Valkey Storage Provider**
  - **Feature**: New distributed storage backend using Valkey (Redis-compatible) in `storage/valkey/`
  - **Use Case**: Production deployments requiring distributed storage, persistence, and horizontal scaling
  - **Interfaces**: Implements all storage interfaces (`TokenStore`, `ClientStore`, `FlowStore`, `RefreshTokenFamilyStore`, `TokenRevocationStore`)
  - **Key Schema**: Configurable prefix (default `mcp:`) for multi-tenant deployments
  - **Atomic Operations**: Lua scripts ensure atomicity for security-critical operations
    - `AtomicCheckAndMarkAuthCodeUsed`: Prevents authorization code replay attacks
    - `AtomicGetAndDeleteRefreshToken`: Prevents refresh token reuse attacks
  - **TTL Management**: Automatic TTL-based expiration for all keys
  - **TLS Support**: Optional TLS configuration for encrypted connections
  - **Security Features**:
    - Constant-time bcrypt comparison for client secret validation
    - Token family tracking for OAuth 2.1 reuse detection
    - Configurable revoked family retention for security forensics (default: 90 days)
    - Optional token encryption at rest via `SetEncryptor()` using AES-256-GCM
    - Input size validation to prevent DoS attacks (max token: 512 bytes, max ID: 256 bytes)
    - Generic error messages prevent information leakage (no client IDs or counts in errors)
  - **IP Rate Limiting**: Built-in DoS protection via IP-based client registration limits
  - **Documentation**: Comprehensive package documentation with usage examples
  - **Testing**: Skip-based tests for environments without Valkey available, concurrency tests for atomic operations

- **GitHub OAuth Provider with Organization Access Control**
  - **Feature**: New dedicated GitHub OAuth provider in `providers/github/`
  - **Use Case**: Direct GitHub authentication without requiring Dex or other OIDC proxies
  - **Scopes**: Default scopes `user:email` and `read:user` for profile and email access
  - **Organization Restriction**: Optional `AllowedOrganizations` config to restrict login to specific organizations
    - Automatically adds `read:org` scope when organizations are configured
    - Case-insensitive organization name matching
    - Users not in allowed organizations receive clear error (`ErrOrganizationRequired`)
  - **Email Handling**: Robust email retrieval with fallback to `/user/emails` endpoint for private emails
  - **PKCE Support**: Full OAuth 2.1 PKCE support for enhanced security
  - **Health Check**: Uses GitHub's `/rate_limit` endpoint for lightweight health monitoring
  - **Token Behavior**: Gracefully handles GitHub's non-expiring tokens (`ErrRefreshNotSupported`)
  - **Token Revocation**: Graceful degradation (returns nil) since GitHub lacks server-side revocation
  - **Helper Methods**:
    - `GetUserOrganizations()` for listing user's organizations
    - `GetProviderToken()` for creating tokens for additional GitHub API calls
  - **Documentation**: Comprehensive `doc.go`, example application, and README with setup instructions
  - **Testing**: 87.2% test coverage with comprehensive unit tests
  - **Example**: New `examples/github/` demonstrating organization-based access control

## [0.2.0] - 2025-11-27

### Added

- **Multi-Tenant Authorization Server Discovery (MCP 2025-11-25)**
  - **Feature**: Automatic registration of multiple discovery endpoints for multi-tenant deployments
  - **Implementation**: New `RegisterAuthorizationServerMetadataRoutes()` method that detects path-based issuers
  - **Endpoints Registered**:
    - For single-tenant (no path): Standard OAuth and OIDC endpoints
    - For multi-tenant (path-based issuer like `https://auth.example.com/tenant1`):
      * OAuth path insertion: `/.well-known/oauth-authorization-server/tenant1`
      * OIDC path insertion: `/.well-known/openid-configuration/tenant1`
      * OIDC path appending: `/tenant1/.well-known/openid-configuration`
      * Standard endpoints (backward compatibility)
  - **Benefits**:
    - Supports complex multi-tenant architectures with path-based tenant isolation
    - Fully compliant with MCP 2025-11-25 discovery requirements
    - Automatic detection based on issuer configuration
    - Backward compatible with existing deployments
  - **Testing**: Comprehensive test coverage for single-tenant, multi-tenant, and nested path scenarios
  - **Examples**: All examples updated to use new registration method
  - **Use Case**: Enterprise deployments with multiple tenants using path-based issuer URLs

- **CIMD Negative Caching for Failed Metadata Fetches**
  - **Feature**: Cache failed Client ID Metadata Document (CIMD) fetch attempts to prevent rapid retries
  - **Security**: Mitigates cache poisoning attacks by preventing attackers from repeatedly hammering the server with requests for known-bad client IDs
  - **Configuration**: Default TTL of 5 minutes for negative entries, separate from positive cache entries
  - **Backoff**: Repeated failures extend the negative cache TTL up to 2x the default (progressive backoff)
  - **Recovery**: Successful fetches automatically clear negative cache entries, allowing recovery after fixes
  - **Metrics**: New cache metrics for negative cache hits, cached entries, and evictions

### Changed

- **Increased Minimum State Parameter Length** (OAuth 2.1 Security)
  - **Change**: Raised the absolute minimum `MinStateLength` floor from 16 to 32 characters
  - **Rationale**: 32 characters provides 192 bits of entropy in base64, exceeding OAuth 2.1's recommended 128+ bits
  - **Security**: Provides sufficient margin for high-security deployments and better CSRF protection
  - **Backward Compatible**: Existing configurations with MinStateLength >= 32 are unaffected

- **Defense-in-Depth Scope Sanitization in WWW-Authenticate Headers**
  - **Change**: Added escaping of backslash and quote characters in scope parameter
  - **Rationale**: While RFC 6749 restricts scope to a limited character set, defense-in-depth escaping prevents potential header injection attacks
  - **RFC Compliance**: Follows RFC 2616/7230 quoted-string rules for HTTP headers

- **ContextWithUserInfo Function for Testing**
  - **Feature**: Export `ContextWithUserInfo` function to create contexts with user info for testing
  - **Problem Solved**: Library consumers couldn't write unit tests for code depending on authenticated user context because `userInfoKey` was unexported
  - **Usage**: `ctx := oauth.ContextWithUserInfo(context.Background(), &providers.UserInfo{ID: "user-123", Email: "test@example.com"})`
  - **Follows Go Patterns**: Similar to `grpc.NewContextWithServerTransportStream` and other standard library context setters
  - **Security**: Includes explicit warning in documentation that this function is for testing only and should not be used to bypass authentication in production

- **Sub-Path Protected Resource Metadata Discovery** (MCP 2025-11-25, RFC 9728)
  - **Feature**: Enable different protected resources on the same domain to advertise different authorization requirements
  - **New Configuration**: `ResourceMetadataByPath` in `server.Config` allows per-path metadata configuration
  - **ProtectedResourceConfig Type**: New configuration type with fields:
    * `ScopesSupported` - Path-specific scopes
    * `AuthorizationServers` - Path-specific authorization server URLs
    * `BearerMethodsSupported` - Path-specific bearer token methods
    * `ResourceIdentifier` - Path-specific resource identifier (RFC 8707)
  - **Path Matching**: Uses longest-prefix matching to find the most specific configuration
  - **Automatic Route Registration**: Paths configured in `ResourceMetadataByPath` are automatically registered as discovery endpoints
  - **Backward Compatible**: Root endpoint and explicit `mcpPath` registration continue to work as before
  - **Example Usage**:
    ```go
    config := &server.Config{
        Issuer: "https://auth.example.com",
        ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
            "/mcp/files": {ScopesSupported: []string{"files:read", "files:write"}},
            "/mcp/admin": {ScopesSupported: []string{"admin:access"}},
        },
    }
    // Registers:
    // - /.well-known/oauth-protected-resource (default metadata)
    // - /.well-known/oauth-protected-resource/mcp/files (files-specific metadata)
    // - /.well-known/oauth-protected-resource/mcp/admin (admin-specific metadata)
    ```
  - **Configuration Validation**: Path format, scope format, authorization server URLs, and bearer methods are validated at startup
  - **Tests**: Comprehensive unit tests for sub-path discovery, path matching, and route registration

- **Success Interstitial Page for Custom URL Schemes** (RFC 8252)
  - **Feature**: Serve an HTML "success interstitial" page instead of direct 302 redirects for custom URL schemes (`cursor://`, `vscode://`, `slack://`, etc.)
  - **Problem Solved**: Browsers often fail silently on 302 redirects to custom URL schemes, leaving users on a blank page with a spinning indicator even though authentication succeeded
  - **Solution**: Per RFC 8252 Section 7.1, native apps should handle the case where browsers cannot redirect to custom schemes. The new interstitial page:
    * Shows "Authorization Successful!" message confirming authentication worked
    * Attempts JavaScript redirect after ~500ms delay
    * Provides manual "Open [App Name]" button as fallback
    * Shows "You can close this window" instruction
  - **App Recognition**: Recognizes common MCP client applications and displays friendly names:
    * Cursor, Visual Studio Code, VSCodium, Slack, Notion, Obsidian
    * Discord, Figma, Linear, Raycast, Warp, Zed, Windsurf, and more
    * Unknown schemes show capitalized scheme name
  - **UX Design**: Modern, clean styling with success checkmark animation
  - **Security**:
    * Uses `html/template` with proper escaping for XSS prevention
    * Hash-based Content-Security-Policy (CSP Level 2) for inline script allowlisting
    * Static inline script reads redirect URL from DOM to maintain stable SHA-256 hash
    * All standard security headers included (X-Frame-Options, X-Content-Type-Options, etc.)
  - **Backward Compatibility**: HTTP/HTTPS redirect URIs continue to use standard 302 redirects
  - **Tests**: Comprehensive unit tests for URL scheme detection, app name mapping, and interstitial rendering

- **Configurable Interstitial Page Branding**
  - **Feature**: Allow library users to customize the interstitial page with their own branding
  - **Configuration**: Three levels of customization via `server.InterstitialConfig`:
    * **Custom Handler**: Full control with `CustomHandler func(w http.ResponseWriter, r *http.Request)` - user is responsible for all security headers
    * **Custom Template**: Provide a custom HTML template via `CustomTemplate string` using Go's `html/template` syntax
    * **Branding Config**: Simple customization via `InterstitialBranding` struct for logo, colors, text, and CSS
  - **Branding Options** (`InterstitialBranding`):
    * `LogoURL` - Custom logo image URL (HTTPS required)
    * `LogoAlt` - Alt text for accessibility
    * `Title` - Custom page title
    * `Message` - Custom success message
    * `ButtonText` - Custom button text
    * `PrimaryColor` - CSS color for buttons/highlights
    * `BackgroundGradient` - CSS background value
    * `CustomCSS` - Additional CSS to inject
  - **Security Validation**:
    * Logo URLs validated to require HTTPS (unless `AllowInsecureHTTP` is set for development)
    * CSS values validated against injection attacks (expression(), javascript:, behavior:, etc.)
    * CustomCSS validated to prevent `</style>` tag injection
  - **Context Helpers**: For custom handlers, helper functions provide access to OAuth context:
    * `oauth.InterstitialRedirectURL(ctx)` - Get the redirect URL
    * `oauth.InterstitialAppName(ctx)` - Get the human-readable app name
  - **Tests**: Comprehensive tests for branding, custom template, custom handler, and security validation

- **Comprehensive MCP 2025-11-25 Documentation**
  - **Feature**: Complete documentation package for MCP 2025-11-25 specification compliance
  - **New Documentation**:
    - `docs/mcp-2025-11-25.md` - Comprehensive migration guide covering all new features:
      * Protected Resource Metadata Discovery (RFC 9728)
      * Enhanced WWW-Authenticate headers (RFC 6750)
      * Scope Selection Strategy
      * Resource Parameter (RFC 8707) for token audience binding
      * Client ID Metadata Documents
      * Insufficient Scope error handling
    - `docs/discovery.md` - Complete guide to OAuth discovery mechanisms:
      * Protected Resource Metadata endpoints
      * Authorization Server Metadata
      * WWW-Authenticate header discovery
      * Client ID Metadata Documents
      * Discovery flow examples and best practices
  - **Updated Documentation**:
    - `README.md`:
      * Added MCP Specification Compliance table showing support status
      * Added links to new documentation resources
      * Enhanced WWW-Authenticate section with references to detailed guides
      * Updated specification compliance references
    - `SECURITY_ARCHITECTURE.md`:
      * Added Resource Parameter Security section with token audience validation
      * Added Token Audience Validation section explaining OAuth 2.0 claims
      * Added WWW-Authenticate Information Disclosure security analysis
      * Updated References section with MCP 2025-11-25 and all relevant RFCs
      * Added links to new documentation resources
  - **Examples**:
    - `examples/mcp-2025-11-25/` - New comprehensive example demonstrating:
      * All MCP 2025-11-25 features configured
      * Endpoint-specific scope requirements
      * Method-specific scope requirements
      * Discovery endpoint setup
      * Complete testing instructions
      * Detailed README with testing scenarios
    - `examples/basic/main.go` - Enhanced with:
      * Detailed comments explaining discovery endpoints
      * MCP 2025-11-25 feature highlights
      * Discovery flow examples
  - **Migration Support**:
    - Backward compatibility notes (no breaking changes)
    - Step-by-step migration path from previous versions
    - Configuration examples for each new feature
    - Security considerations for new features
    - Testing and validation guidelines
  - **Compliance**: Full documentation coverage for MCP 2025-11-25 specification requirements
  - **Developer Experience**: Clear examples, migration guides, and best practices for adopting new features

- **Endpoint-Specific Scope Challenges in WWW-Authenticate Headers (MCP 2025-11-25)**
  - **Feature**: Implemented endpoint-specific scope guidance in WWW-Authenticate headers for 401 Unauthorized responses
  - **MCP Compliance**: Implements MCP 2025-11-25 scope selection strategy specification
  - **Use Case**: Helps clients discover exactly which scopes are required for specific endpoints, improving authorization UX
  - **Implementation**:
    - Added `getChallengeScopes()` helper that resolves scopes with priority: endpoint-specific → DefaultChallengeScopes → none
    - Added `writeUnauthorizedError()` method for 401 responses with endpoint-aware scope challenges
    - Updated `ValidateToken` middleware to use endpoint-specific scopes in WWW-Authenticate headers
    - Integrates seamlessly with existing `EndpointScopeRequirements` and `EndpointMethodScopeRequirements` configurations
  - **Scope Resolution Priority**:
    1. `EndpointMethodScopeRequirements` - method and path specific (e.g., POST /api/files/*)
    2. `EndpointScopeRequirements` - path specific (e.g., /api/files/*)
    3. `DefaultChallengeScopes` - configured fallback scopes
    4. No scope parameter if nothing configured
  - **Example**: When accessing `/api/files/test.txt` without auth, WWW-Authenticate header includes `scope="files:read files:write"` instead of generic default scopes
  - **Backward Compatibility**: Fully backward compatible - uses existing endpoint scope configuration, no breaking changes
  - **Testing**: Added comprehensive unit and integration tests (7 test scenarios, 3 test suites)
  - **Performance**: Minimal overhead - reuses existing scope resolution logic

- **Client ID Metadata Documents Support (draft-ietf-oauth-client-id-metadata-document, MCP 2025-11-25)**
  - **Feature**: Implemented URL-based client identifiers with automatic metadata fetching
  - **MCP Compliance**: SHOULD requirement for MCP 2025-11-25 specification
  - **Use Case**: Enables OAuth flows where servers and clients have no pre-existing relationship
  - **Implementation**:
    - URL detection: Automatically detects HTTPS URLs as client_id and fetches metadata
    - Metadata fetching: HTTP client with configurable timeout (default: 10s) and 1MB size limit
    - SSRF protection: Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x), loopback, and link-local addresses
    - Caching: In-memory LRU cache with TTL support (default: 5 minutes) and HTTP Cache-Control respect
    - Validation: Ensures client_id in document matches URL exactly (security requirement)
    - Integration: Transparent integration with existing authorization flow via `GetClient()`
  - **Configuration**:
    - `EnableClientIDMetadataDocuments` - Enable feature (default: false for backward compatibility)
    - `ClientMetadataFetchTimeout` - Timeout for metadata fetch (default: 10s)
    - `ClientMetadataCacheTTL` - Cache TTL (default: 5m)
  - **Discovery**: Authorization Server Metadata advertises support via `client_id_metadata_document_supported: true`
  - **Security**:
    - HTTPS-only enforcement for metadata URLs
    - Comprehensive SSRF protection against internal network access
    - Client_id validation prevents impersonation attacks
    - Localhost redirect URI warnings per spec recommendations
  - **Testing**: Comprehensive unit tests covering URL detection, SSRF protection, caching, and metadata validation
  - **Performance**: LRU cache with configurable size (default: 1000 entries) prevents memory exhaustion

- **Enhanced Protected Resource Metadata (RFC 9728, MCP 2025-11-25)**
  - **Feature**: Enhanced Protected Resource Metadata with `scopes_supported` field and sub-path discovery
  - **MCP Compliance**: High-priority enhancement for MCP 2025-11-25 specification
  - **Implementation**:
    - Added `scopes_supported` field to Protected Resource Metadata response when `SupportedScopes` is configured
    - Implemented sub-path metadata endpoint support (e.g., `/.well-known/oauth-protected-resource/mcp`)
    - Added `RegisterProtectedResourceMetadataRoutes()` helper function for easy route registration
    - Supports both root (`/.well-known/oauth-protected-resource`) and sub-path endpoints
  - **Discovery**: Clients can now discover available scopes and access metadata at service-specific sub-paths
  - **Helper Function**: Simplifies registration of both root and sub-path metadata endpoints with a single call
  - **Testing**: Added comprehensive unit tests for all scenarios (scopes inclusion, sub-path routing, path normalization)
  - **Documentation**: Updated README and examples to demonstrate new functionality

- **RFC 8707 Resource Parameter for Token Audience Binding (MCP 2025-11-25)**
  - **Feature**: Implemented RFC 8707 Resource Indicators to bind access tokens to their intended resource server
  - **MCP Compliance**: MUST requirement for MCP 2025-11-25 specification
  - **Security**: Prevents token theft and replay attacks across different resource servers
  - **Implementation**:
    - Authorization endpoint accepts `resource` parameter to specify target resource server
    - Token endpoint accepts `resource` parameter and validates consistency with authorization code
    - Audience validation ensures tokens are only accepted by their intended resource server
    - Resource binding stored with authorization codes and tokens
  - **Configuration**: New `ResourceIdentifier` field in `server.Config` (defaults to `Issuer` if not set)
  - **Backward Compatibility**: Resource parameter is optional to maintain compatibility with existing clients
  - **Storage Changes**:
    - Added `Resource` field to `storage.AuthorizationState`
    - Added `Resource` and `Audience` fields to `storage.AuthorizationCode`
  - **Validation**: Resource must be absolute HTTPS URI (or HTTP for localhost development)
  - **Audit Events**: New `EventResourceMismatch` for resource parameter validation failures
  - **Testing**: All existing tests updated, maintains 80%+ coverage

### Security

- **RFC 8707 Security Enhancements**
  - **Resource Length Validation**: Added maximum length limit (2048 characters) for resource parameter to prevent DoS attacks via extremely long URIs (RFC 3986 recommended limit)
  - **Constant-Time Audience Comparison**: Implemented constant-time comparison for token audience validation to prevent timing attacks (defense-in-depth best practice)
  - **Rate Limiting on Resource Mismatch**: Added rate limiting for repeated resource mismatch attempts to prevent reconnaissance attacks and log flooding
  - **Impact**: Enhanced defense-in-depth for RFC 8707 implementation, preventing potential DoS and timing-based attacks
  - **Testing**: Added comprehensive test coverage for length validation and rate limiting behavior

- **Scope string deep copy in Google provider to prevent race conditions**
  - **Problem**: Provider was using shallow copy when passing scopes to oauth2.Config, potentially allowing concurrent modifications to shared slice references
  - **Risk**: Low risk in current implementation (scopes only set at initialization), but future code changes could introduce race conditions
  - **Solution**: Implemented deep copy of scope slices to eliminate shared references
  - **Impact**: Prevents potential data races and unexpected scope modifications in concurrent scenarios
  - **Testing**: Added comprehensive test coverage for deep copy safety and concurrent modification scenarios

- **Scope string length validation to prevent DoS attacks**
  - **Problem**: No limit on scope parameter length could allow DoS attacks via extremely long scope strings
  - **Risk**: Potential resource exhaustion through processing and validating arbitrarily long scope strings
  - **Solution**:
    - Added `MaxScopeLength` configuration parameter (default: 1000 characters)
    - Scope length validated early in authorization flow before parsing/processing
    - Clear error messages when limit exceeded
  - **Impact**: Prevents potential DoS attacks while allowing legitimate use cases (1000 chars supports ~50+ typical scopes)
  - **Configuration**: `server.Config.MaxScopeLength` (default: 1000, automatically set if 0)
  - **Error**: Returns `invalid_scope` with clear message when limit exceeded
  - **Audit**: Scope length violations are logged via audit system
  - **Testing**: Added tests for boundary conditions (at limit, exceeds limit, empty scopes)

### Fixed

- **OAuth callback now properly passes client-requested scopes to Google provider (#82)**
  - **Problem**: Scopes from client authorization requests were not being passed to Google during provider authorization redirect
  - **Impact**: Google returned tokens without user info (no scopes = no permissions = no data), causing userID extraction to fail and token storage to fail with "userID cannot be empty" errors
  - **Root Cause**: The Provider interface's `AuthorizationURL` method didn't accept scopes parameter, so only provider's hardcoded scopes were used
  - **Solution**:
    - Modified `Provider.AuthorizationURL()` interface to accept `scopes []string` parameter
    - Updated Google provider to use client-requested scopes when provided, falling back to configured defaults when empty
    - Updated server flows to parse and pass client scopes to provider
  - **Breaking Change**: 🔴 **YES** - Provider interface method signature changed
    - **Before**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string) string`
    - **After**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string) string`
    - **Migration**: Add `scopes` parameter to any custom provider implementations
  - **Behavior**:
    - When client provides scopes in authorization request → those scopes are used
    - When client provides no scopes → provider's configured default scopes are used
    - Empty scopes array → provider defaults used
  - **Testing**: Added comprehensive tests for dynamic scope behavior

- **WWW-Authenticate metadata now defaults to enabled (secure by default)**
  - **Problem**: Field naming made it unclear whether metadata was enabled or disabled by default
  - **Impact**: Initial implementation had confusing semantics around defaults
  - **Solution**: Renamed to `DisableWWWAuthenticateMetadata` following the library's "secure by default" principle
  - **Field change**: `EnableWWWAuthenticateMetadata` → `DisableWWWAuthenticateMetadata` (inverted logic)
  - **Default behavior**:
    - `DisableWWWAuthenticateMetadata: false` (default) → Full metadata ENABLED (secure by default)
    - `DisableWWWAuthenticateMetadata: true` → Minimal headers for backward compatibility
  - **Breaking Change**: 🔴 **YES** - Field renamed for clarity
    - **Before**: `config.EnableWWWAuthenticateMetadata = false` to disable
    - **After**: `config.DisableWWWAuthenticateMetadata = true` to disable
    - **Migration**: Replace field name and invert boolean value
  - **Why this matters**:
    - Clear naming: "Disable" prefix indicates opt-out, not opt-in
    - Consistent with library philosophy: secure by default
    - MCP 2025-11-25 compliance out of the box
    - Modern OAuth clients ignore unknown header parameters (safe for most clients)
  - **Configuration changes**:
    - Renamed field for clarity
    - Added security warning log when feature is disabled
    - Removed confusing default-forcing logic (zero value = enabled)
  - **Testing**: All existing tests updated to use new field name

- **Dynamic Client Registration (DCR) now respects `token_endpoint_auth_method` parameter (#70)**
  - **Problem**: DCR always created confidential clients with secrets, even when native/CLI apps requested public clients
  - **Solution**: Implement OAuth 2.1 / RFC 7591 compliant DCR that respects the `token_endpoint_auth_method` field
  - **Key Changes**:
    - When `token_endpoint_auth_method: "none"` is requested, creates a public client (no secret)
    - When `token_endpoint_auth_method: "client_secret_basic"` or `"client_secret_post"`, creates a confidential client (with secret)
    - Auth method parameter overrides client_type when both are provided
    - Added validation to reject unsupported auth methods
  - **Security Enhancements**:
    - Public clients still require PKCE for all flows (OAuth 2.1 compliance)
    - **CRITICAL**: Added enforcement of `AllowPublicClientRegistration` policy for public client creation
    - Public client registration is now denied when `AllowPublicClientRegistration=false`, even with valid registration token
    - Reduced information leakage in auth method error messages (supported methods not revealed in error responses)
    - Comprehensive audit logging for public client registration attempts
  - **Configuration Clarification**:
    - `AllowPublicClientRegistration` now explicitly controls TWO aspects:
      1. DCR endpoint authentication (whether Bearer token is required)
      2. Public client creation (whether clients with `token_endpoint_auth_method="none"` can be registered)
    - Updated documentation to clearly explain secure vs. permissive configurations
  - **Use Case**: Enables native applications (like mcp-debug) to properly register as public clients
  - **Testing**: Added comprehensive unit and integration tests for all auth method combinations and policy enforcement
  - **Constants**: Added `TokenEndpointAuthMethod*` constants for type safety

### Added

- **MCP 2025-11-25: WWW-Authenticate header with resource_metadata for discovery (#73)**
  - Implemented MCP 2025-11-25 specification support for Protected Resource Metadata discovery
  - **What changed**: All 401 Unauthorized responses now include enhanced WWW-Authenticate headers
  - **Header format** (per RFC 6750 and RFC 9728):
    ```http
    WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource",
                             scope="files:read user:profile",
                             error="invalid_token",
                             error_description="Token has expired"
    ```
  - **Discovery mechanism**: Helps MCP clients automatically discover:
    - Authorization server location via `resource_metadata` URL
    - Required scopes via optional `scope` parameter
    - Error details for debugging and retry logic
  - **Configuration**:
    - `DefaultChallengeScopes`: Configure default scopes to include in WWW-Authenticate challenges
    - Example: `config.DefaultChallengeScopes = []string{"mcp:access", "files:read"}`
    - `DisableWWWAuthenticateMetadata`: Opt-out flag for backward compatibility (default: false = enabled)
  - **Backward compatibility**:
    - Feature enabled by default for MCP 2025-11-25 compliance (secure by default)
    - Can be disabled for legacy clients: `config.DisableWWWAuthenticateMetadata = true`
    - When disabled, returns minimal `WWW-Authenticate: Bearer` header
    - Standard HTTP behavior: clients ignore headers they don't understand
    - No breaking changes to existing client implementations
  - **Automatic behavior**:
    - All existing 401 responses automatically get proper WWW-Authenticate headers
    - No code changes needed in existing handlers
    - Scope parameter only included if configured (optional)
  - **Specification compliance**:
    - MCP 2025-11-25: One of two discovery mechanisms (WWW-Authenticate OR well-known paths) (✓)
    - RFC 6750 Section 3: Bearer token challenge format (✓)
    - RFC 9728: Protected Resource Metadata discovery (✓)
  - **Security improvements**:
    - Enhanced escaping in error descriptions: properly handles backslashes and quotes
    - Follows RFC 2616/7230 quoted-string rules for HTTP header values
    - Prevents header injection from malformed error messages
  - **Code quality improvements**:
    - Extracted repeated test strings to constants (DRY principle)
    - Added edge case tests for long scope lists and special characters
    - Improved test maintainability with test helper constants
  - **Testing**: Comprehensive unit tests for header formatting, integration, backward compatibility mode, and security edge cases (100% coverage)
  - **Configuration validation** (security hardening):
    - Validates `DefaultChallengeScopes` for invalid characters (quotes, commas, backslashes)
    - Warns when scope count exceeds 50 (HTTP header size limit protection)
    - Defense-in-depth: validation complements existing escaping
    - Comprehensive test coverage for validation edge cases
  - **Documentation**:
    - Added security considerations section to README
    - Documents information disclosure policy (intentional per OAuth specs)
    - Guidance on scope configuration best practices
    - Clear warnings about header size limits

- **OAuth 2.1 PKCE for provider leg - Enhanced security for confidential clients (#68)**
  - Implemented full OAuth 2.1 PKCE support on the OAuth server → Provider leg
  - **Why this matters**: OAuth 2.1 recommends PKCE for ALL client types (public AND confidential) to protect against Authorization Code Injection attacks
  - **Two-layer PKCE architecture**:
    1. MCP client → OAuth server: Uses client-provided PKCE (already working)
    2. OAuth server → Google: Now uses server-generated PKCE (NEW)
  - **Security benefits**:
    - Defense-in-depth against Authorization Code Injection
    - Cryptographic binding between authorization and token exchange
    - Protection even if state parameter is compromised
    - OAuth 2.1 compliance for confidential client security
  - **Implementation details**:
    - Added `ProviderCodeVerifier` field to `AuthorizationState`
    - Server generates independent PKCE pair for provider communication
    - Google provider now accepts and validates PKCE parameters
    - Both client_secret AND PKCE provide layered security
  - **Testing**: Updated provider and integration tests to verify PKCE flow
  - **Documentation**: Added `SECURITY_ARCHITECTURE.md` explaining the security model

- **Comprehensive security architecture documentation**
  - New `SECURITY_ARCHITECTURE.md` document explaining:
    - Two-layer authentication architecture (MCP client ↔ OAuth server ↔ Provider)
    - PKCE implementation at both layers with security rationale
    - Dual-layer state protection strategy
    - Attack mitigation strategies (code injection, CSRF, timing attacks, etc.)
    - Production deployment security checklist
    - Monitoring and auditing best practices
  - Detailed threat model analysis
  - References to OAuth 2.1 and RFC 7636 specifications

### Fixed

- **Google provider OAuth flow now fully OAuth 2.1 compliant (#68)**
  - Fixed: "Missing code verifier" errors when using Google OAuth
  - Root cause: Provider was forwarding MCP client's PKCE to Google without corresponding verifier
  - Solution: Implemented proper two-layer PKCE where server generates its own PKCE for provider leg
  - Impact: Fixes complete OAuth flow failure while enhancing security beyond original implementation
  - Migration: No breaking changes - PKCE is generated and handled automatically

### Security

- **Typed storage errors for security-sensitive error handling**
  - Added sentinel errors (`ErrTokenNotFound`, `ErrTokenExpired`, `ErrClientNotFound`, `ErrAuthorizationCodeNotFound`, `ErrAuthorizationCodeUsed`, `ErrAuthorizationStateNotFound`) to distinguish transient errors from security events
  - Added helper functions `IsNotFoundError()`, `IsExpiredError()`, `IsCodeReuseError()` for consistent error type checking
  - Enables proper detection of token reuse attacks without false positives from transient storage failures

- **CORS wildcard origin now requires explicit opt-in**
  - New `AllowWildcardOrigin` field must be set to `true` to use `"*"` in `AllowedOrigins`
  - Prevents accidental CSRF exposure in production deployments
  - Configuration will panic with clear instructions if wildcard is used without opt-in

- **Constant-time comparison for registration access token**
  - Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks on the registration endpoint
  - Attackers cannot guess the token character by character through response time analysis

- **MinStateLength floor enforcement**
  - Absolute minimum of 16 characters enforced regardless of configuration
  - Ensures adequate CSRF protection entropy even if misconfigured
  - Logs warning when configured value is below the floor

- **Enhanced SECURITY.md documentation**
  - Added production logging configuration guidance (disable DEBUG in production)
  - Added security-sensitive log entries reference table
  - Extended production deployment checklist with logging, CORS, and state length checks

### Changed

- **OpenTelemetry instrumentation infrastructure for comprehensive observability (#37)**
  - Added new `instrumentation` package providing metrics, traces, and logging integration
  - Features:
    - Metrics: Counters, histograms, and gauges for all OAuth operations
    - Traces: Distributed tracing spans for request flows across components
    - Structured logging integration with trace context
    - Zero overhead when disabled (uses no-op providers)
    - Thread-safe concurrent access
    - Graceful shutdown handling
  - Configuration:
    - Added `InstrumentationConfig` to server configuration
    - Opt-in via `Enabled` flag (default: false)
    - Configurable service name and version
  - Metrics provided:
    - HTTP layer: requests, duration
    - OAuth flows: authorization, callback, code exchange, token refresh/revocation, client registration
    - Security: rate limits, PKCE validation, code/token reuse detection
    - Storage: operation counts, duration, size
    - Provider: API calls, duration, errors
    - Audit events, encryption operations
  - Integration:
    - Server automatically initializes instrumentation when enabled
    - Shutdown integrates with server graceful shutdown
    - Ready for layer-by-layer adoption in future PRs
  - Testing:
    - 83% test coverage on instrumentation package
    - Concurrent access tests
    - No-op provider verification
    - Metric recording correctness
    - Span lifecycle management
  - **Security & Privacy:**
    - Comprehensive security warnings against logging sensitive credentials
    - GDPR/privacy compliance documentation
    - Clear guidance on data collection and retention policies
    - Reserved attribute constants to prevent credential leakage
    - Security-reviewed implementation with no sensitive data logging
  - **Impact**: No breaking changes - instrumentation is opt-in and disabled by default
  - **Future work**: Layer-by-layer instrumentation adoption (HTTP, storage, provider, security)
  - **Documentation**: Comprehensive package documentation with security best practices

- **CORS (Cross-Origin Resource Sharing) support for browser-based clients (#28)**
  - Added `CORSConfig` to server configuration with `AllowedOrigins`, `AllowCredentials`, and `MaxAge` settings
  - Implemented `setCORSHeaders()` method to apply CORS headers to all HTTP responses
  - Added `isAllowedOrigin()` helper for origin validation with exact matching
  - Implemented `ServePreflightRequest()` handler for OPTIONS preflight requests
  - CORS headers automatically applied to all OAuth endpoints:
    - Authorization server metadata, protected resource metadata
    - Authorization, callback, token endpoints
    - Token revocation, client registration, token introspection
  - Features:
    - Opt-in by default (disabled when `AllowedOrigins` is empty) for backward compatibility
    - Support for multiple allowed origins with exact matching (case-sensitive)
    - Wildcard `*` support with security warning for development
    - Configurable credentials support for OAuth flows
    - Configurable preflight cache duration
  - Security considerations:
    - Only echoes back allowed origins (no arbitrary reflection)
    - Logs security warning when wildcard `*` is used
    - Respects CORS specification for credentials and preflight requests
  - Comprehensive test coverage:
    - CORS disabled by default
    - Allowed/disallowed origin validation
    - Wildcard origin support
    - Preflight request handling
    - Credentials configuration
    - Custom max age
  - **Impact**: No breaking changes - CORS is opt-in and disabled by default
  - **Documentation**: Added CORS configuration guide to README with security best practices
  - **Example**: Updated production example with commented CORS configuration

- **Proactive token refresh during validation to prevent expiry failures (#27)**
  - Added `TokenRefreshThreshold` configuration (default: 300 seconds = 5 minutes)
  - `ValidateToken()` now checks if provider token will expire within threshold
  - Automatically refreshes token with provider if refresh token is available
  - Graceful fallback: continues with validation if refresh fails (no user-facing error)
  - Benefits:
    - Improved UX: prevents "token expired" errors when refresh is possible
    - Reduces failed validation attempts and provider API calls
    - Configurable threshold for different deployment scenarios
  - Comprehensive test coverage:
    - Proactive refresh when token near expiry (multiple time windows)
    - Graceful fallback when refresh fails
    - Custom threshold configuration (1 min, 5 min, 10 min, 15 min)
    - No refresh when threshold not reached or refresh token unavailable
  - Audit logging for refresh events (`token_proactively_refreshed`, `proactive_refresh_failed`)
  - **Impact**: No breaking changes - backward compatible, opt-in via configuration
  - **Performance**: Reduces provider API errors and improves token validation reliability

### Changed

- **Refactored proactive refresh implementation for better maintainability**
  - Extracted nested refresh logic into dedicated helper functions (`shouldProactivelyRefresh`, `attemptProactiveRefresh`)
  - Improved test isolation by moving mock setup into per-test closures
  - Added descriptive test constants for better code clarity
  - **Impact**: Internal refactoring only - no functional changes or breaking changes
  - **Benefit**: Reduced cyclomatic complexity, improved testability and code readability

### Fixed

- **Added registration_endpoint to OAuth Authorization Server Metadata (#66)**
  - Fixed missing `registration_endpoint` field in `/.well-known/oauth-authorization-server` response
  - OAuth clients can now automatically discover Dynamic Client Registration endpoint via RFC 8414 metadata
  - The `/oauth/register` endpoint was working but not advertised in metadata
  - **Conditional Advertising**: Field is only included when client registration is actually available
    - Included when `RegistrationAccessToken` is set OR `AllowPublicClientRegistration=true`
    - Excluded when neither is configured (defense-in-depth)
  - **Impact**: Enables automatic client discovery for RFC 8414-compliant OAuth clients
  - **Standards**: Complies with RFC 8414 Section 3.1 requirement for `registration_endpoint` field
  - **Security**: Added comprehensive documentation explaining metadata security model
  - **Testing**: Enhanced metadata tests to verify conditional inclusion/exclusion behavior

### Security

- **Implemented LRU eviction in rate limiter to prevent memory exhaustion (#23)**
  - Added configurable `MaxEntries` limit (default: 10,000 unique identifiers)
  - Implemented LRU (Least Recently Used) eviction strategy using `container/list`
  - When limit reached, automatically evicts least recently used entries
  - Added `NewRateLimiterWithConfig()` for custom max entries configuration
  - Added `GetStats()` method for monitoring:
    - `CurrentEntries`: Number of tracked identifiers
    - `MaxEntries`: Configured limit (0 = unlimited)
    - `TotalEvictions`: Number of LRU evictions performed
    - `TotalCleanups`: Number of cleanup operations completed
    - `MemoryPressure`: Percentage of max capacity used (0-100)
  - Enhanced cleanup to maintain consistency between map and LRU list
  - Added comprehensive test suite covering:
    - Max entries enforcement
    - LRU eviction order correctness
    - Concurrent access with eviction
    - Memory bounds under high load (500+ unique identifiers)
    - Unlimited mode (maxEntries = 0) for backward compatibility
    - Stats reporting accuracy
  - Added benchmarks for large-scale usage (10k+ entries)
  - Created security package documentation (doc.go) with:
    - Memory management behavior explanation
    - Monitoring and alerting guidelines
    - Security considerations and best practices
    - Example usage patterns
  - **Impact**: No breaking changes - backward compatible with safe defaults
  - **Security**: Prevents memory exhaustion from distributed attacks while maintaining rate limiting effectiveness
- **Added client-specific scope validation to prevent scope escalation attacks (#26)**
  - Implemented `validateClientScopes()` to validate requested scopes against client's allowed scopes
  - Validation occurs at TWO points for defense-in-depth:
    1. Authorization flow start - early rejection of unauthorized scope requests
    2. Token exchange - final validation before issuing tokens (prevents bypasses)
  - Clients with empty/nil `Scopes` field allow all scopes (backward compatibility)
  - Clients with non-empty `Scopes` field are restricted to their allowed scopes only
  - **Security hardening**: Fully generic error messages prevent scope enumeration attacks
    - Error messages do NOT reveal specific unauthorized scope names
    - Prevents attackers from fingerprinting allowed scopes
    - Consistent with RFC 6749 and OAuth 2.0 Security Best Practices
  - Comprehensive audit logging for security monitoring:
    - `scope_escalation_attempt` events (high severity) for unauthorized scope requests
    - `scope_validation_failed` events for tracking validation failures
    - Detailed event metadata for incident response and forensics
  - Added security monitoring documentation in SECURITY.md:
    - Alert thresholds and recommended response procedures
    - Example queries for log aggregation systems (Prometheus, ELK)
    - Guidance on extracting metrics from audit logs
    - Custom metrics collector implementation examples
  - Added comprehensive test suite covering:
    - Single and multiple scope validation
    - Scope escalation attempts
    - Unauthorized scope detection
    - Backward compatibility with unrestricted clients
    - Integration tests for authorization flow and token exchange
    - Security scenario testing (read-only client escalation, admin attempts)
  - **Impact**: No breaking changes - enhanced OAuth 2.0 security
  - **Security**: Prevents compromised clients from obtaining tokens with unauthorized scopes
- **Added local token expiry validation before provider check (#24)**
  - `ValidateToken` now checks token expiry locally before calling provider
  - Prevents expired tokens from being accepted if provider's clock is skewed
  - Respects `ClockSkewGracePeriod` configuration (default 5 seconds)
  - Defense in depth: checks expiry locally before external API call
  - Falls back to provider validation if token not found locally
  - Added comprehensive test suite for expiry validation and clock skew scenarios
  - **Impact**: No breaking changes - enhanced security validation
- **Implemented explicit entropy validation for token generation (#21)**
  - Replaced `oauth2.GenerateVerifier()` with `crypto/rand` for better control
  - Generates 32 bytes (256 bits) of cryptographically secure entropy
  - Base64url encoding produces 43-character tokens (RFC 4648)
  - Panics on RNG failure to prevent weak token generation
  - Affects all security-critical tokens (auth codes, access/refresh tokens, state values, client credentials)
  - Added comprehensive test suite and benchmarks
  - **Impact**: No breaking changes - same format, improved security guarantee
- **Fixed timing attack vulnerability in state parameter validation (#19)**
  - Added minimum length validation (32 characters) for state parameters
  - State validation now enforces sufficient entropy for CSRF protection
  - Constant-time comparison already in place for state value validation
  - Added comprehensive tests for timing attack resistance
  - Updated all tests to use secure state parameters
  - Refactored validation logic to follow DRY principle and architectural patterns
  - State validation now centralized in server layer with handler doing input validation
  - Added compile-time test to ensure constant synchronization between packages
  - **Impact**: Short state parameters (< 32 chars) are now rejected
  - **Migration**: Ensure client applications generate state parameters with at least 32 characters
- **[BREAKING]** Added runtime HTTPS enforcement for OAuth server (#18, #49)
  - New `AllowInsecureHTTP` config flag (default: `false`)
  - Production deployments now require HTTPS by default
  - HTTP allowed only on localhost (127.0.0.0/8, ::1, 0.0.0.0) for development
  - Non-localhost HTTP deployments blocked unless explicitly allowed
  - Clear error messages guide developers to secure configuration
  - OAuth 2.1 compliance: HTTPS required for all production endpoints
  - **Migration**:
    - For localhost development: Add `AllowInsecureHTTP: true` to suppress warnings
    - For production HTTP (not recommended): Add `AllowInsecureHTTP: true` and review security risks
    - **Recommended**: Switch to HTTPS for all environments
- **Enforced mandatory PKCE for public clients to prevent authorization code theft (#22)**
  - Public clients (mobile apps, SPAs) now MUST use PKCE per OAuth 2.1 specification by default
  - Authorization code exchange fails for public clients without PKCE (secure by default)
  - Confidential clients can still optionally use PKCE (backward compatible)
  - Prevents authorization code interception attacks on public clients
  - Added comprehensive security event logging for PKCE enforcement failures
  - Added extensive test coverage for public and confidential client scenarios
  - **New Config Option**: `AllowPublicClientsWithoutPKCE` (default: `false`)
    - Set to `true` to allow legacy public clients without PKCE support
    - **WARNING**: Enabling this creates authorization code theft vulnerability
    - Only use for backward compatibility with unmaintained legacy clients
    - Logs warning events when public clients authenticate without PKCE
  - **Impact**: Public clients without PKCE will receive `invalid_grant` error by default
  - **Migration**: Ensure all public clients (mobile apps, SPAs) implement PKCE with S256 method
  - **Legacy Compatibility**: Set `AllowPublicClientsWithoutPKCE: true` if you cannot update legacy clients
  - **Security Rationale**: Public clients cannot securely store credentials, making PKCE essential for binding authorization codes to specific client instances

### Added
- Initial open-source release
- Comprehensive README with usage examples
- Apache 2.0 LICENSE
- CONTRIBUTING.md with development guidelines
- SECURITY.md with security policy
- Example applications in `examples/` directory
- GitHub workflows for CI/CD
- Issue and PR templates

## [1.0.0] - 2025-11-23

### Added
- OAuth 2.1 Authorization Server implementation (proxying to Google)
- OAuth 2.1 Resource Server implementation (token validation)
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- Token Revocation (RFC 7009)
- PKCE support with S256 method enforcement
- Token encryption at rest with AES-256-GCM
- Refresh token rotation with reuse detection
- Comprehensive audit logging with sensitive data hashing
- Rate limiting (per-IP and per-user)
- Client type validation (public vs confidential)
- Google OAuth integration for Gmail, Drive, Calendar, etc.
- Cryptographically secure token generation
- HTTP middleware for token validation
- Custom HTTP client support
- Structured logging with slog
- Extensive test coverage
- Godoc documentation

### Security
- Enforces HTTPS in production (localhost exception for development)
- Disables plain PKCE method (S256 only)
- Hashes all sensitive data before logging (SHA-256)
- Validates redirect URIs with scheme restrictions
- Implements bcrypt for client secret hashing
- Adds clock skew grace period (5 seconds)
- Rate limiting to prevent DoS and brute force attacks
- Token expiration with automatic cleanup

## Release History

### Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Supported Versions

| Version | Release Date | End of Life | Status |
|---------|--------------|-------------|--------|
| 1.0.x   | 2025-11-23   | TBD         | Active |

### Upgrade Guide

#### From Pre-1.0 to 1.0

This is the first stable release.

If upgrading from internal/unreleased versions:

1. Update import path to `github.com/giantswarm/mcp-oauth`
2. Review security configuration (defaults are now secure by default)
3. Enable token encryption for production deployments
4. Review rate limiting configuration
5. Update to new structured Config type
6. Check audit log integration

### Migration Notes

#### Breaking Changes in 1.0

N/A - First release

### Future Roadmap

Planned features for future releases:

- [x] Support for additional OAuth providers (GitHub - completed in v0.2.8, Microsoft - planned)
- [ ] Token introspection endpoint (RFC 7662)
- [ ] Device authorization grant (RFC 8628)
- [ ] JWT access tokens (RFC 9068)
- [ ] Persistent storage adapters (Redis, PostgreSQL, etc.)
- [ ] Metrics and observability improvements
- [ ] OpenTelemetry integration
- [ ] mTLS client authentication
- [ ] DPoP (RFC 9449) support
- [ ] FAPI 2.0 compliance

### Deprecation Policy

We maintain backwards compatibility within major versions. Deprecated features:

1. **Announcement**: Marked as deprecated in release notes and godoc
2. **Grace Period**: Supported for at least 2 minor versions
3. **Removal**: Only in next major version

Currently deprecated features: None

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.
