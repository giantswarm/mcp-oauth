package oauthconfig_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/server"
)

// TestTurnkeyWiring proves the full oauthconfig loader surface composes into
// a working server: FromEnv + NewEncryptorFromEnv + StorageFromEnv +
// ProviderFromEnv → server.NewWithCombined. This is the complete end-to-end
// path a typical consumer writes, and each piece is unit-tested in isolation
// elsewhere — this test locks down the composition.
//
// Intentionally uses:
//   - GitHub provider (synchronous construction, no network)
//   - memory storage (default; no external dependency)
//   - encryption key set via env
//
// Dex would need a live OIDC discovery server; Google and GitHub don't hit
// the network during construction, so GitHub is the safe choice here.
func TestTurnkeyWiring(t *testing.T) {
	// Start from a clean env so stray CI vars can't skew the result.
	clearRequired(t)
	clearStorageEnv(t)
	clearProviderEnv(t)

	// Base server config.
	t.Setenv("OAUTH_ISSUER", "https://auth.turnkey.test")
	t.Setenv("OAUTH_ACCESS_TOKEN_TTL", "1h")
	t.Setenv("OAUTH_ENCRYPTION_KEY", validKeyB64)
	t.Setenv("OAUTH_SESSION_ID_HMAC_KEY", validKeyB64)

	// Storage: memory (explicit, to prove the env var is honored through the
	// composition, not just "default fall-through").
	t.Setenv("STORAGE_BACKEND", "memory")

	// Provider: GitHub. Synchronous construction, no network.
	t.Setenv("OAUTH_PROVIDER", "github")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh-client")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "gh-secret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://app.turnkey.test/callback")

	// ---- The composition the library's README will promise. ----
	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}

	encryptor, err := oauthconfig.NewEncryptorFromEnv()
	if err != nil {
		t.Fatalf("NewEncryptorFromEnv: %v", err)
	}
	if encryptor == nil {
		t.Fatal("NewEncryptorFromEnv returned nil despite ENCRYPTION_KEY set")
	}

	store, closeFn, err := oauthconfig.StorageFromEnv(slog.Default())
	if err != nil {
		t.Fatalf("StorageFromEnv: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })

	provider, err := oauthconfig.ProviderFromEnv()
	if err != nil {
		t.Fatalf("ProviderFromEnv: %v", err)
	}

	srv, err := server.NewWithCombined(provider, store, cfg, slog.Default())
	if err != nil {
		t.Fatalf("server.NewWithCombined: %v", err)
	}

	// Attaching the encryptor is the documented post-construction step; prove
	// it wires through without a panic, since the whole point of
	// NewEncryptorFromEnv is to be composable with SetEncryptor.
	srv.SetEncryptor(encryptor)

	// Minimal behavioral spot-check: the constructed server should accept a
	// healthy provider check. Not asking for a round-trip OAuth flow — that
	// is covered by the package's own integration tests — just that the
	// composed pieces produce a functional *Server whose wired provider
	// answers its contract.
	if err := provider.HealthCheck(context.Background()); err != nil {
		// GitHub HealthCheck hits api.github.com. Skipping is honest — we
		// don't want a CI flake when GitHub is down. The point of this test
		// is the composition step, not the provider's health.
		t.Logf("provider HealthCheck returned %v (non-fatal; test is about composition)", err)
	}

	// Final sanity: each loader returned the shape the constructor expects.
	if srv == nil {
		t.Fatal("*Server should not be nil after successful NewWithCombined")
	}
	if cfg.Issuer != "https://auth.turnkey.test" {
		t.Errorf("Issuer = %q, want https://auth.turnkey.test", cfg.Issuer)
	}
	if len(cfg.SessionIDHMACKey) != 32 {
		t.Errorf("SessionIDHMACKey length = %d, want 32 (base64-decoded from validKeyB64)", len(cfg.SessionIDHMACKey))
	}
	if provider.Name() != "github" {
		t.Errorf("provider.Name() = %q, want github", provider.Name())
	}
}

// clearRequired is a superset of the helpers in env_test.go / storage_test.go
// / provider_test.go that zeros everything the turnkey path reads. Keeping a
// local copy (rather than exporting the package-internal clear helpers) keeps
// the test surface minimal.
func clearRequired(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"OAUTH_ISSUER",
		"OAUTH_ALLOW_INSECURE_HTTP",
		"OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION",
		"OAUTH_TRUST_PROXY",
		"OAUTH_ACCESS_TOKEN_TTL",
		"OAUTH_REFRESH_TOKEN_TTL",
		"OAUTH_MAX_CLIENTS_PER_IP",
		"OAUTH_REGISTRATION_ACCESS_TOKEN",
		"OAUTH_REGISTRATION_ACCESS_TOKEN_FILE",
		"OAUTH_ENCRYPTION_KEY",
		"OAUTH_ENCRYPTION_KEY_FILE",
		"OAUTH_SESSION_ID_HMAC_KEY",
		"OAUTH_SESSION_ID_HMAC_KEY_FILE",
		"OAUTH_TRUSTED_AUDIENCES",
	} {
		t.Setenv(v, "")
	}
}
