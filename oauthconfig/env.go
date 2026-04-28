package oauthconfig

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	// carry one — token-at-rest encryption is attached via server.SetEncryptor
	// after the server is constructed. See [NewEncryptorFromEnv] for the
	// corresponding loader.

	if err := loadSessionIDHMACKey(prefix, cfg); err != nil {
		return nil, err
	}

	if raw := os.Getenv(prefix + "TRUSTED_AUDIENCES"); raw != "" {
		cfg.TrustedAudiences = splitAndTrim(raw, ",")
	}

	return cfg, nil
}

// validateIssuerScheme rejects a plain-HTTP issuer unless the operator has
// explicitly opted in. URL schemes are case-insensitive per RFC 3986 §3.1, so
// HTTP://example.com must not slip past a gate that catches http://example.com.
func validateIssuerScheme(issuer string, allowInsecure bool, prefix string) error {
	if allowInsecure {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%sISSUER is not a valid URL: %w", prefix, err)
	}
	if strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("%sISSUER uses http:// but %sALLOW_INSECURE_HTTP is not set; refusing to run an OAuth server over plain HTTP without an explicit opt-in", prefix, prefix)
	}
	return nil
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
// as a base64-encoded 32-byte AES-GCM key and returns a *security.Encryptor
// ready to pass to server.SetEncryptor. Returns (nil, nil) when no key is
// configured — callers can decide whether to require encryption.
//
// Separate from [FromEnv] because token-at-rest encryption is wired via
// server.SetEncryptor after server construction, not through *server.Config.
func NewEncryptorFromEnv() (*security.Encryptor, error) {
	return NewEncryptorFromEnvWithPrefix("OAUTH_")
}

// NewEncryptorFromEnvWithPrefix is [NewEncryptorFromEnv] with a caller-supplied
// prefix. See [FromEnvWithPrefix] for the convention.
func NewEncryptorFromEnvWithPrefix(prefix string) (*security.Encryptor, error) {
	encB64, err := optionalSecret(prefix + "ENCRYPTION_KEY")
	if err != nil {
		return nil, err
	}
	if encB64 == "" {
		return nil, nil
	}
	key, err := security.KeyFromBase64(encB64)
	if err != nil {
		return nil, fmt.Errorf("%sENCRYPTION_KEY: %w", prefix, err)
	}
	return security.NewEncryptor(key)
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
