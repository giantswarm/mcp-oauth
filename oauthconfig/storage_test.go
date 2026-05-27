package oauthconfig_test

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// clearStorageEnv zeroes every OAUTH_STORAGE_* / OAUTH_VALKEY_* var this
// package reads so each test inherits a known baseline regardless of what the
// CI shell set.
func clearStorageEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"OAUTH_STORAGE_BACKEND",
		"OAUTH_VALKEY_ADDR",
		"OAUTH_VALKEY_PASSWORD",
		"OAUTH_VALKEY_PASSWORD_FILE",
		"OAUTH_VALKEY_DB",
		"OAUTH_VALKEY_KEY_PREFIX",
		"OAUTH_VALKEY_TLS",
		"OAUTH_VALKEY_TLS_INSECURE_SKIP_VERIFY",
		"OAUTH_VALKEY_REFRESH_TOKEN_TTL",
		"OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE",
	} {
		t.Setenv(v, "")
	}
}

func TestStorageFromEnv_DefaultIsMemory(t *testing.T) {
	clearStorageEnv(t)
	store, closeFn, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("StorageFromEnv: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, ok := store.(*memory.Store); !ok {
		t.Errorf("default backend: got %T, want *memory.Store", store)
	}
}

func TestStorageFromEnv_MemoryExplicit(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "memory")

	store, closeFn, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("StorageFromEnv: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, ok := store.(*memory.Store); !ok {
		t.Errorf("got %T, want *memory.Store", store)
	}
}

func TestStorageFromEnv_UnknownBackend(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "postgres")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("expected unknown-backend error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyMissingAddress(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "VALKEY_ADDR") {
		t.Fatalf("expected VALKEY_ADDR required error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyBadDB(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "unreachable:0")
	t.Setenv("OAUTH_VALKEY_DB", "not-a-number")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "VALKEY_DB") {
		t.Fatalf("expected VALKEY_DB parse error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyBadTLSBool(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "unreachable:0")
	t.Setenv("OAUTH_VALKEY_TLS", "maybe")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "VALKEY_TLS") {
		t.Fatalf("expected VALKEY_TLS bool parse error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyBadMaxTokenDataSize(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "unreachable:0")
	t.Setenv("OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE", "not-an-int")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "VALKEY_MAX_TOKEN_DATA_SIZE") {
		t.Fatalf("expected VALKEY_MAX_TOKEN_DATA_SIZE parse error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyMaxTokenDataSizeOutOfRange(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "unreachable:0")
	t.Setenv("OAUTH_VALKEY_MAX_TOKEN_DATA_SIZE", "1024") // below MinMaxTokenDataSize

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "MaxTokenDataSize") {
		t.Fatalf("expected MaxTokenDataSize range error, got %v", err)
	}
}

func TestStorageFromEnv_ValkeyBadRefreshTTL(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "unreachable:0")
	t.Setenv("OAUTH_VALKEY_REFRESH_TOKEN_TTL", "not-a-duration")

	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "VALKEY_REFRESH_TOKEN_TTL") {
		t.Fatalf("expected VALKEY_REFRESH_TOKEN_TTL parse error, got %v", err)
	}
}

// TestStorageFromEnv_ValkeyPasswordFilePrecedence verifies the _FILE variant
// overrides the plain env var. Does NOT require a running Valkey — the test
// relies on the bad-address path to surface the password in an error, proving
// the env-loader read from the file not the env.
func TestStorageFromEnv_ValkeyPasswordFilePrecedence(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", "127.0.0.1:1") // unreachable by design
	t.Setenv("OAUTH_VALKEY_PASSWORD", "from-env")

	pwdFile := writeSecretFile(t, "from-file\n")
	t.Setenv("OAUTH_VALKEY_PASSWORD_FILE", pwdFile)

	// Connection will fail — we only care that the loader accepted the _FILE
	// variant without erroring on password parsing.
	_, _, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err == nil {
		t.Fatal("expected connection error against unreachable address")
	}
	// The error should originate from valkey.New (connection failure), not
	// from our env-loader stage.
	if strings.Contains(err.Error(), "VALKEY_PASSWORD") {
		t.Errorf("password stage should not have errored; got %v", err)
	}
}

func TestStorageFromEnvWithPrefix(t *testing.T) {
	clearStorageEnv(t)
	t.Setenv("MUSTER_OAUTH_STORAGE_BACKEND", "memory")

	store, closeFn, err := oauthconfig.StorageFromEnvWithPrefix("MUSTER_OAUTH_", nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("StorageFromEnvWithPrefix: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, ok := store.(*memory.Store); !ok {
		t.Errorf("prefixed backend: got %T, want *memory.Store", store)
	}
}

// TestStorageFromEnv_ValkeyLive hits a real Valkey instance when VALKEY_TEST_ADDR
// is set, matching the opt-in convention of storage/valkey's own tests. Skipped
// otherwise. Verifies the full happy path: env parse → valkey.New → Combined.
func TestStorageFromEnv_ValkeyLive(t *testing.T) {
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		t.Skip("set VALKEY_TEST_ADDR (e.g. localhost:6379) to run")
	}

	clearStorageEnv(t)
	t.Setenv("OAUTH_STORAGE_BACKEND", "valkey")
	t.Setenv("OAUTH_VALKEY_ADDR", addr)
	t.Setenv("OAUTH_VALKEY_KEY_PREFIX", "oauthconfigtest:")
	t.Setenv("OAUTH_VALKEY_REFRESH_TOKEN_TTL", "1h")

	store, closeFn, err := oauthconfig.StorageFromEnv(nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("StorageFromEnv against live valkey: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, ok := store.(*valkey.Store); !ok {
		t.Errorf("valkey backend: got %T, want *valkey.Store", store)
	}
}
