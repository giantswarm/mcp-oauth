package oauthconfig

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

// FromEnv reads the standard OAUTH_* variables and returns a populated
// *server.Config. Defaults are NOT applied here — server.New runs applyDefaults
// and remains the single source of truth for default values. FromEnv only
// populates what the caller provided.
//
// Returns an error for:
//   - missing required variables (OAUTH_ISSUER)
//   - malformed values (bad base64, bad duration, bad bool)
//   - secret _FILE paths that cannot be read
//   - insecure-HTTP issuer without the explicit opt-in
//
// See the package doc for the full variable list and the _FILE convention.
func FromEnv() (*server.Config, error) {
	return FromEnvWithPrefix("OAUTH_")
}

// FromEnvWithPrefix is [FromEnv] with a caller-supplied prefix. Useful for
// consumers that scope their env vars to their product name, e.g.
// FromEnvWithPrefix("MUSTER_OAUTH_"). The prefix is applied verbatim; include
// the trailing underscore if you want one.
func FromEnvWithPrefix(prefix string) (*server.Config, error) {
	cfg := &server.Config{}

	issuer, err := requireString(prefix + "ISSUER")
	if err != nil {
		return nil, err
	}
	cfg.Issuer = issuer

	allowInsecure, err := optionalBool(prefix+"ALLOW_INSECURE_HTTP", false)
	if err != nil {
		return nil, err
	}
	if err := validateIssuerScheme(issuer, allowInsecure, prefix); err != nil {
		return nil, err
	}
	cfg.AllowInsecureHTTP = allowInsecure

	cfg.AllowPublicClientRegistration, err = optionalBool(prefix+"ALLOW_PUBLIC_CLIENT_REGISTRATION", false)
	if err != nil {
		return nil, err
	}

	cfg.TrustProxy, err = optionalBool(prefix+"TRUST_PROXY", false)
	if err != nil {
		return nil, err
	}

	if err := loadDurationSecondsIfSet(prefix+"ACCESS_TOKEN_TTL", &cfg.AccessTokenTTL); err != nil {
		return nil, err
	}
	if err := loadDurationSecondsIfSet(prefix+"REFRESH_TOKEN_TTL", &cfg.RefreshTokenTTL); err != nil {
		return nil, err
	}
	if err := loadPositiveIntIfSet(prefix+"MAX_CLIENTS_PER_IP", &cfg.MaxClientsPerIP); err != nil {
		return nil, err
	}

	cfg.RegistrationAccessToken, err = optionalSecret(prefix + "REGISTRATION_ACCESS_TOKEN")
	if err != nil {
		return nil, err
	}

	// The encryption key is NOT read here because *server.Config does not
	// carry one — token-at-rest encryption is wired via the
	// server.WithEncryptor option at construction. See [NewEncryptorFromEnv]
	// for the corresponding loader.

	if err := loadSessionIDHMACKey(prefix, cfg); err != nil {
		return nil, err
	}

	if err := loadTrustedAllowlistsFromEnv(prefix, cfg); err != nil {
		return nil, err
	}

	cfg.AllowLocalhostRedirectURIs, err = optionalBool(prefix+"ALLOW_LOCALHOST_REDIRECT_URIS", false)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadTrustedAllowlistsFromEnv loads the comma-separated allowlist env vars
// (TRUSTED_AUDIENCES, TRUSTED_REDIRECT_SCHEMES, TRUSTED_REDIRECT_URIS) into cfg.
func loadTrustedAllowlistsFromEnv(prefix string, cfg *server.Config) error {
	loadCSVIfSet(prefix+"TRUSTED_AUDIENCES", &cfg.TrustedAudiences)
	if err := dex.ValidateAudiences(cfg.TrustedAudiences); err != nil {
		return fmt.Errorf("%sTRUSTED_AUDIENCES: %w", prefix, err)
	}
	loadCSVIfSet(prefix+"TRUSTED_REDIRECT_SCHEMES", &cfg.TrustedPublicRegistrationSchemes)
	loadCSVIfSet(prefix+"TRUSTED_REDIRECT_URIS", &cfg.TrustedPublicRegistrationRedirectURIs)
	return nil
}

// loadCSVIfSet writes splitAndTrim(value, ",") into dst when the named env var is set.
func loadCSVIfSet(name string, dst *[]string) {
	if raw := os.Getenv(name); raw != "" {
		*dst = splitAndTrim(raw, ",")
	}
}

// validateIssuerScheme rejects a plain-HTTP issuer unless the operator has
// explicitly opted in OR the issuer points at a loopback host. URL schemes
// are case-insensitive per RFC 3986 §3.1, so HTTP://example.com must not
// slip past a gate that catches http://example.com.
//
// The loopback exception (RFC 8252 native-app territory) skips the
// ALLOW_INSECURE_HTTP requirement for "http://localhost", "http://127.0.0.1",
// and "http://[::1]" so dev loops don't have to flip the global insecure flag
// — which would weaken every other http:// check at the same time.
func validateIssuerScheme(issuer string, allowInsecure bool, prefix string) error {
	if allowInsecure {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%sISSUER is not a valid URL: %w", prefix, err)
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%sISSUER uses http:// but %sALLOW_INSECURE_HTTP is not set; refusing to run an OAuth server over plain HTTP without an explicit opt-in", prefix, prefix)
}

// isLoopbackHost reports whether host is one of the loopback identifiers
// used to bypass the http-issuer gate: "localhost", "127.0.0.1", or "::1".
// Pure string match — no DNS resolution. Comparison is case-insensitive on
// the textual identifier ("Localhost" matches) per RFC 3986 §3.2.2.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func loadDurationSecondsIfSet(name string, dst *int64) error {
	v, err := optionalDurationSeconds(name)
	if err != nil {
		return err
	}
	if v != 0 {
		*dst = v
	}
	return nil
}

func loadPositiveIntIfSet(name string, dst *int) error {
	v, err := optionalPositiveInt(name)
	if err != nil {
		return err
	}
	if v != 0 {
		*dst = v
	}
	return nil
}

func loadSessionIDHMACKey(prefix string, cfg *server.Config) error {
	hmacB64, err := optionalSecret(prefix + "SESSION_ID_HMAC_KEY")
	if err != nil {
		return err
	}
	if hmacB64 == "" {
		return nil
	}
	key, err := security.KeyFromBase64(hmacB64)
	if err != nil {
		return fmt.Errorf("%sSESSION_ID_HMAC_KEY: %w", prefix, err)
	}
	cfg.SessionIDHMACKey = key
	return nil
}

// NewEncryptorFromEnv reads OAUTH_ENCRYPTION_KEY (or OAUTH_ENCRYPTION_KEY_FILE)
// as a 32-byte AES-GCM key and returns a *security.Encryptor ready to pass to
// the server.WithEncryptor option. Returns (nil, nil) when no key is
// configured — callers can decide whether to require encryption.
//
// The key may be encoded as either base64 (canonical, produced by
// `openssl rand -base64 32`) or hex (`openssl rand -hex 32`). Base64 is tried
// first; on any failure (decode error or wrong length) the value is retried as
// hex. base64 is the recommended form.
//
// Separate from [FromEnv] because token-at-rest encryption is wired via the
// server.WithEncryptor option at construction, not through *server.Config.
func NewEncryptorFromEnv() (*security.Encryptor, error) {
	return NewEncryptorFromEnvWithPrefix("OAUTH_")
}

// NewEncryptorFromEnvWithPrefix is [NewEncryptorFromEnv] with a caller-supplied
// prefix. See [FromEnvWithPrefix] for the convention.
func NewEncryptorFromEnvWithPrefix(prefix string) (*security.Encryptor, error) {
	raw, err := optionalSecret(prefix + "ENCRYPTION_KEY")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	key, err := decodeSymmetricKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%sENCRYPTION_KEY: %w", prefix, err)
	}
	return security.NewEncryptor(key)
}

// decodeSymmetricKey decodes a 32-byte symmetric key from either base64 (the
// canonical form produced by `openssl rand -base64 32`) or hex
// (`openssl rand -hex 32`). Base64 is attempted first; on any failure — bad
// charset OR a decoded length other than 32 — the value is retried as hex.
//
// The fallback exists because the previous loader accepted only base64, and
// dropping hex support broke operators who had generated keys with
// `openssl rand -hex 32`. The two encodings have disjoint shapes when the
// underlying key really is 32 bytes (base64 → 44 chars with `=` padding;
// hex → 64 chars [0-9a-f]), so the order is unambiguous in practice.
func decodeSymmetricKey(s string) ([]byte, error) {
	if key, err := security.KeyFromBase64(s); err == nil {
		return key, nil
	}
	key, err := security.KeyFromHex(s)
	if err != nil {
		return nil, fmt.Errorf("expected base64 or hex 32-byte key: %w", err)
	}
	return key, nil
}

// requireString returns os.Getenv(name) or an error if empty.
func requireString(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return v, nil
}

// optionalBool parses truthy/falsy env values. Accepts the strconv.ParseBool
// set (1/t/T/TRUE/true/True, 0/f/F/FALSE/false/False). Missing → fallback.
func optionalBool(name string, fallback bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: expected a boolean (true/false, 1/0), got %q", name, v)
	}
	return b, nil
}

// optionalDurationSeconds parses a Go duration (e.g. "1h30m") and returns the
// equivalent whole seconds. Returns 0 when the variable is unset.
func optionalDurationSeconds(name string) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: expected a Go duration (e.g. 1h, 30m), got %q: %w", name, v, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: duration must be non-negative, got %s", name, d)
	}
	return int64(d.Seconds()), nil
}

// optionalPositiveInt parses a non-negative integer. Returns 0 when unset.
func optionalPositiveInt(name string) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: expected a non-negative integer, got %q", name, v)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: must be non-negative, got %d", name, n)
	}
	return n, nil
}

// optionalSecret reads a secret that may come from either the plain env var or
// from a sibling "<NAME>_FILE" path (k8s mounted-secret convention). When both
// are set, the _FILE variant wins. A single trailing newline is trimmed from
// file contents (projected-volume files commonly carry one).
func optionalSecret(name string) (string, error) {
	if raw := os.Getenv(name + "_FILE"); raw != "" {
		path := filepath.Clean(raw)
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSuffix(string(b), "\n"), nil
	}
	return os.Getenv(name), nil
}

// splitAndTrim splits s on sep, trims whitespace from each entry, and drops
// empty entries. Used for comma-separated list env vars.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
