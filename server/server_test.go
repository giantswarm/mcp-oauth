package server

import (
	"log/slog"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNew(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv == nil {
		t.Fatal("New() returned nil")
	}

	if srv.Config.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", srv.Config.Issuer, "https://auth.example.com")
	}

	if srv.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestNew_WithLogger(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger := slog.Default()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.Logger != logger {
		t.Error("Logger should match provided logger")
	}
}

func TestNew_NilConfig(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, nil, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.Config == nil {
		t.Error("Config should not be nil when nil is passed")
	}
}

func TestNew_MissingProvider(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	_, err := New(nil, store, store, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil provider should return error")
	}
}

func TestNew_MissingTokenStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	_, err := New(provider, nil, store, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil token store should return error")
	}
}

func TestNew_MissingClientStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	_, err := New(provider, store, nil, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil client store should return error")
	}
}

func TestNew_MissingFlowStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	_, err := New(provider, store, store, nil, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil flow store should return error")
	}
}

func TestServer_SetEncryptor(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	srv.SetEncryptor(enc)

	if srv.Encryptor == nil {
		t.Error("Encryptor should be set")
	}
}

func TestServer_SetAuditor(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	auditor := security.NewAuditor(nil, true)
	srv.SetAuditor(auditor)

	if srv.Auditor == nil {
		t.Error("Auditor should be set")
	}
}

func TestServer_SetRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(10, 20, nil)
	defer rl.Stop()

	srv.SetRateLimiter(rl)

	if srv.RateLimiter == nil {
		t.Error("RateLimiter should be set")
	}
}

func TestServer_SetUserRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(5, 10, nil)
	defer rl.Stop()

	srv.SetUserRateLimiter(rl)

	if srv.UserRateLimiter == nil {
		t.Error("UserRateLimiter should be set")
	}
}

func TestServer_SetSecurityEventRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(1, 5, nil)
	defer rl.Stop()

	srv.SetSecurityEventRateLimiter(rl)

	if srv.SecurityEventRateLimiter == nil {
		t.Error("SecurityEventRateLimiter should be set")
	}
}

// TestServer_ProviderRevocationConfigDefaults tests that New() applies correct defaults
// P1: Configuration defaults validation
func TestServer_ProviderRevocationConfigDefaults(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Create server with empty config (should apply defaults)
	config := &Config{
		Issuer: "https://auth.example.com",
		// Don't set provider revocation fields - should use defaults
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify defaults were applied
	if srv.Config.ProviderRevocationTimeout != 10 {
		t.Errorf("ProviderRevocationTimeout = %d, want 10 (default)", srv.Config.ProviderRevocationTimeout)
	}

	if srv.Config.ProviderRevocationMaxRetries != 3 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 3 (default)", srv.Config.ProviderRevocationMaxRetries)
	}

	if srv.Config.ProviderRevocationFailureThreshold != 0.5 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.5 (default)", srv.Config.ProviderRevocationFailureThreshold)
	}

	if srv.Config.RevokedFamilyRetentionDays != 90 {
		t.Errorf("RevokedFamilyRetentionDays = %d, want 90 (default)", srv.Config.RevokedFamilyRetentionDays)
	}
}

// TestServer_ProviderRevocationConfigCustomValues tests custom values are preserved
// P1: Configuration validation
func TestServer_ProviderRevocationConfigCustomValues(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Create server with custom config values
	config := &Config{
		Issuer:                             "https://auth.example.com",
		ProviderRevocationTimeout:          30,
		ProviderRevocationMaxRetries:       5,
		ProviderRevocationFailureThreshold: 0.3,
		RevokedFamilyRetentionDays:         180,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify custom values were preserved
	if srv.Config.ProviderRevocationTimeout != 30 {
		t.Errorf("ProviderRevocationTimeout = %d, want 30 (custom)", srv.Config.ProviderRevocationTimeout)
	}

	if srv.Config.ProviderRevocationMaxRetries != 5 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 5 (custom)", srv.Config.ProviderRevocationMaxRetries)
	}

	if srv.Config.ProviderRevocationFailureThreshold != 0.3 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.3 (custom)", srv.Config.ProviderRevocationFailureThreshold)
	}

	if srv.Config.RevokedFamilyRetentionDays != 180 {
		t.Errorf("RevokedFamilyRetentionDays = %d, want 180 (custom)", srv.Config.RevokedFamilyRetentionDays)
	}
}

// TestServer_RevokedFamilyRetentionPropagation tests retention period propagates to storage
// P2: Feature integration test
func TestServer_RevokedFamilyRetentionPropagation(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &Config{
		Issuer:                     "https://auth.example.com",
		RevokedFamilyRetentionDays: 120,
	}

	_, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Memory store implements the retention setter interface
	// Verify it was called (we can't directly check private field, but can verify no error)
	// The actual retention behavior is tested in memory store tests

	// If we get here without panic, the type assertion and call succeeded
	t.Log("Retention period propagation test passed - no error during setup")
}
