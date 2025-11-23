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

	srv, err := New(provider, store, store, store, &Config{Issuer: "test"}, nil)
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

	srv, err := New(provider, store, store, store, &Config{Issuer: "test"}, nil)
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

	srv, err := New(provider, store, store, store, &Config{Issuer: "test"}, nil)
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

	srv, err := New(provider, store, store, store, &Config{Issuer: "test"}, nil)
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
