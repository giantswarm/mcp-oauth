package oauthconfig

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/oauthconfig/internal/valkeytls"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// StorageFromEnv selects a storage backend from the OAUTH_STORAGE_BACKEND
// environment variable and returns a ready [storage.Combined] plus a close
// function the caller MUST defer. "memory" (default) and "valkey" are
// supported.
//
// The returned close function is a no-op for memory and calls Store.Close()
// for valkey. It is always safe to call and always returns nil (close errors
// are swallowed and logged by the backend).
//
// enc and inst are wired into the store at construction. Encryption is
// optional for memory and required for Valkey. Nil inst disables OTel.
//
// Valkey-specific variables (read only when OAUTH_STORAGE_BACKEND=valkey):
//
//   - OAUTH_VALKEY_ADDR                   (required when OAUTH_STORAGE_BACKEND=valkey)
//   - OAUTH_VALKEY_PASSWORD[_FILE]           (optional)
//   - OAUTH_VALKEY_DB                        (optional; non-negative integer)
//   - OAUTH_VALKEY_KEY_PREFIX                (optional; defaults to valkey.DefaultKeyPrefix)
//   - OAUTH_VALKEY_TLS                       (optional; "true" enables TLS)
//   - OAUTH_VALKEY_TLS_INSECURE_SKIP_VERIFY  (optional; dev only)
//   - OAUTH_VALKEY_REFRESH_TOKEN_TTL         (optional Go duration)
//   - OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE       (optional bytes; default 600 KiB,
//     range [64 KiB, 8 MiB])
//   - OAUTH_VALKEY_STARTUP_TIMEOUT           (optional Go duration; how long
//     start-up waits for Valkey, default valkey.DefaultStartupTimeout)
//
// Pass the returned [storage.Combined] to [server.NewWithCombined].
func StorageFromEnv(enc *security.Encryptor, inst *instrumentation.Instrumentation, logger *slog.Logger) (storage.Combined, func() error, error) {
	return StorageFromEnvWithPrefix("OAUTH_", enc, inst, logger)
}

// StorageFromEnvWithPrefix is [StorageFromEnv] with a caller-supplied prefix
// applied to STORAGE_BACKEND and VALKEY_*. The prefix is applied verbatim;
// include a trailing underscore if you want one. Useful for consumers that
// scope their env vars to their product name, e.g.
// StorageFromEnvWithPrefix("MUSTER_OAUTH_", enc, inst, logger) reads
// MUSTER_OAUTH_STORAGE_BACKEND and MUSTER_OAUTH_VALKEY_*.
func StorageFromEnvWithPrefix(prefix string, enc *security.Encryptor, inst *instrumentation.Instrumentation, logger *slog.Logger) (storage.Combined, func() error, error) {
	configuration, err := storageConfigFromEnv(prefix)
	if err != nil {
		return nil, nil, err
	}
	store, closeStore, err := configuredStorage(configuration, enc, inst, logger)
	if err != nil {
		return nil, nil, err
	}
	return store, func() error { closeStore(); return nil }, nil
}

func storageConfigFromEnv(prefix string) (*valkey.Config, error) {
	backend := os.Getenv(prefix + "STORAGE_BACKEND")
	if backend == "" || backend == storage.BackendMemory {
		return nil, nil
	}
	if backend != storage.BackendValkey {
		return nil, fmt.Errorf("%sSTORAGE_BACKEND: unknown backend %q (want %q or %q)", prefix, backend, storage.BackendMemory, storage.BackendValkey)
	}
	addr := os.Getenv(prefix + "VALKEY_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("%sVALKEY_ADDR is required when %sSTORAGE_BACKEND=valkey", prefix, prefix)
	}

	password, err := optionalSecret(prefix + "VALKEY_PASSWORD")
	if err != nil {
		return nil, err
	}

	db, err := optionalPositiveInt(prefix + "VALKEY_DB")
	if err != nil {
		return nil, err
	}

	tlsEnabled, err := optionalBool(prefix+"VALKEY_TLS", false)
	if err != nil {
		return nil, err
	}
	tlsInsecure, err := optionalBool(prefix+"VALKEY_TLS_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return nil, err
	}

	refreshTTL, err := optionalDuration(prefix + "VALKEY_REFRESH_TOKEN_TTL")
	if err != nil {
		return nil, err
	}

	maxTokenDataSize, err := optionalPositiveInt(prefix + "VALKEY_MAX_TOKEN_DATA_SIZE")
	if err != nil {
		return nil, err
	}

	startupTimeout, err := optionalDuration(prefix + "VALKEY_STARTUP_TIMEOUT")
	if err != nil {
		return nil, err
	}

	return &valkey.Config{
		Address:          addr,
		Password:         password,
		DB:               db,
		KeyPrefix:        os.Getenv(prefix + "VALKEY_KEY_PREFIX"),
		TLS:              valkeytls.New(valkeytls.Options{Enabled: tlsEnabled, InsecureSkipVerify: tlsInsecure}),
		RefreshTokenTTL:  refreshTTL,
		MaxTokenDataSize: maxTokenDataSize,
		StartupTimeout:   startupTimeout,
	}, nil
}

// optionalDuration parses a Go duration (e.g. "24h") directly — used for
// Valkey's RefreshTokenTTL, which the Valkey store takes as a time.Duration.
// Distinct from optionalDurationSeconds, which converts to int64 seconds for
// *server.Config fields that use that shape.
func optionalDuration(name string) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: expected a Go duration (e.g. 24h), got %q: %w", name, v, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: duration must be non-negative, got %s", name, d)
	}
	return d, nil
}

// Compile-time assertion: the concrete backends we return from StorageFromEnv
// really satisfy storage.Combined. Keeps the contract local to this file so
// a breakage is surfaced here rather than at the New* call sites.
var (
	_ storage.Combined = (*valkey.Store)(nil)
)
