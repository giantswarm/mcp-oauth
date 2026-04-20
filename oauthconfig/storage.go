package oauthconfig

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/giantswarm/mcp-oauth/oauthconfig/internal/valkeytls"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// StorageFromEnv selects a storage backend from the STORAGE_BACKEND
// environment variable and returns a ready [storage.Combined] plus a close
// function the caller MUST defer. "memory" (default) and "valkey" are
// supported.
//
// The returned close function is a no-op for memory and calls Store.Close()
// for valkey. It is always safe to call and always returns nil (close errors
// are swallowed and logged by the backend).
//
// Valkey-specific variables (read only when STORAGE_BACKEND=valkey):
//
//   - VALKEY_ADDRESS                   (required when STORAGE_BACKEND=valkey)
//   - VALKEY_PASSWORD[_FILE]           (optional)
//   - VALKEY_DB                        (optional; non-negative integer)
//   - VALKEY_KEY_PREFIX                (optional; defaults to valkey.DefaultKeyPrefix)
//   - VALKEY_TLS                       (optional; "true" enables TLS)
//   - VALKEY_TLS_INSECURE_SKIP_VERIFY  (optional; dev only)
//   - VALKEY_REFRESH_TOKEN_TTL         (optional Go duration)
//
// Pass the returned [storage.Combined] to [server.NewWithCombined].
func StorageFromEnv(logger *slog.Logger) (storage.Combined, func() error, error) {
	return StorageFromEnvWithPrefix("", logger)
}

// StorageFromEnvWithPrefix is [StorageFromEnv] with a caller-supplied prefix
// applied to STORAGE_BACKEND and VALKEY_*. The prefix is applied verbatim;
// include a trailing underscore if you want one. Useful for consumers that
// scope their env vars to their product name, e.g.
// StorageFromEnvWithPrefix("MUSTER_", logger).
func StorageFromEnvWithPrefix(prefix string, logger *slog.Logger) (storage.Combined, func() error, error) {
	backend := os.Getenv(prefix + "STORAGE_BACKEND")
	if backend == "" {
		backend = "memory"
	}

	switch backend {
	case "memory":
		store := memory.New()
		return store, func() error { store.Stop(); return nil }, nil
	case "valkey":
		return newValkeyFromEnv(prefix, logger)
	default:
		return nil, nil, fmt.Errorf("%sSTORAGE_BACKEND: unknown backend %q (want \"memory\" or \"valkey\")", prefix, backend)
	}
}

// newValkeyFromEnv constructs a valkey.Store from the VALKEY_* environment
// variables. Returns a close func that invokes Store.Close and always returns
// nil (Valkey close errors are logged by the backend; surfacing them would
// complicate caller shutdown flows).
func newValkeyFromEnv(prefix string, logger *slog.Logger) (storage.Combined, func() error, error) {
	addr := os.Getenv(prefix + "VALKEY_ADDRESS")
	if addr == "" {
		return nil, nil, fmt.Errorf("%sVALKEY_ADDRESS is required when %sSTORAGE_BACKEND=valkey", prefix, prefix)
	}

	password, err := optionalSecret(prefix + "VALKEY_PASSWORD")
	if err != nil {
		return nil, nil, err
	}

	db, err := optionalPositiveInt(prefix + "VALKEY_DB")
	if err != nil {
		return nil, nil, err
	}

	tlsEnabled, err := optionalBool(prefix+"VALKEY_TLS", false)
	if err != nil {
		return nil, nil, err
	}
	tlsInsecure, err := optionalBool(prefix+"VALKEY_TLS_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return nil, nil, err
	}

	refreshTTL, err := optionalDuration(prefix + "VALKEY_REFRESH_TOKEN_TTL")
	if err != nil {
		return nil, nil, err
	}

	cfg := valkey.Config{
		Address:         addr,
		Password:        password,
		DB:              db,
		KeyPrefix:       os.Getenv(prefix + "VALKEY_KEY_PREFIX"),
		TLS:             valkeytls.New(valkeytls.Options{Enabled: tlsEnabled, InsecureSkipVerify: tlsInsecure}),
		Logger:          logger,
		RefreshTokenTTL: refreshTTL,
	}
	store, err := valkey.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("valkey.New: %w", err)
	}
	return store, func() error { store.Close(); return nil }, nil
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
	_ storage.Combined = (*memory.Store)(nil)
	_ storage.Combined = (*valkey.Store)(nil)
)
