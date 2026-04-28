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
//   - OAUTH_ALLOW_INSECURE_HTTP               (default false) — permit http:// issuer
//     (loopback issuers — http://localhost, http://127.0.0.1, http://[::1] —
//     are exempt from this gate per RFC 8252 §7.3, so dev loops don't have to
//     enable the global insecure flag)
//   - OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION  (default false)
//   - OAUTH_REGISTRATION_ACCESS_TOKEN         — registration bearer; see _FILE note below
//   - OAUTH_ENCRYPTION_KEY                    — base64 32-byte AES-GCM key
//   - OAUTH_SESSION_ID_HMAC_KEY               — base64 32-byte HMAC key
//     (see server.Config.SessionIDHMACKey for the operator caveat)
//   - OAUTH_ACCESS_TOKEN_TTL                  — Go duration (e.g. "1h")
//   - OAUTH_REFRESH_TOKEN_TTL                 — Go duration
//   - OAUTH_MAX_CLIENTS_PER_IP                — positive integer
//   - OAUTH_TRUST_PROXY                       (default false)
//   - OAUTH_TRUSTED_AUDIENCES                 — comma-separated audience list
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
//   - OAUTH_SESSION_ID_HMAC_KEY_FILE
//
// OAUTH_TRUSTED_AUDIENCES deliberately has NO _FILE variant — audience
// identifiers are not secrets. The asymmetry is intentional; the list lives in
// deployment configuration (Helm values / ConfigMap) rather than in a Secret.
//
// # OAUTH_TRUSTED_AUDIENCES limitation
//
// The value is split on literal commas. RFC 8707 audiences are URIs and URIs
// should not contain literal commas, so this is safe in practice. Callers with
// audiences containing commas for some other reason must populate
// oauth.Config.TrustedAudiences programmatically instead of relying on this
// loader.
//
// # FromEnv vs FromEnvWithPrefix
//
// [FromEnv] reads the names above. [FromEnvWithPrefix] reads the same names
// with a caller-supplied prefix (for consumers that scope env vars to their
// product, e.g. "MUSTER_OAUTH_"). The prefix is applied verbatim — include the
// trailing underscore if you want one.
package oauthconfig
