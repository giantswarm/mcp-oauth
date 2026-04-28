package server

import (
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestNewWithCombined_SamePointerInAllSlots verifies that the additive
// constructor wires the same storage.Combined value into the server's
// tokenStore, clientStore, and flowStore fields. In-package test so the
// unexported fields are reachable — external consumers can't observe the
// identity directly, but the contract they rely on is that a single backend
// is used end-to-end.
func TestNewWithCombined_SamePointerInAllSlots(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	srv, err := NewWithCombined(mock.NewProvider(), store, &Config{Issuer: "https://auth.example"}, nil)
	if err != nil {
		t.Fatalf("NewWithCombined: %v", err)
	}

	if srv.tokenStore != store {
		t.Errorf("tokenStore = %p, want %p", srv.tokenStore, store)
	}
	if srv.clientStore != store {
		t.Errorf("clientStore = %p, want %p", srv.clientStore, store)
	}
	if srv.flowStore != store {
		t.Errorf("flowStore = %p, want %p", srv.flowStore, store)
	}
}

// TestNewWithCombined_NilStoreRejected confirms the validator still rejects a
// nil store through the delegated path — otherwise NewWithCombined would be a
// silent bypass of the existing validateServerDependencies guard.
func TestNewWithCombined_NilStoreRejected(t *testing.T) {
	_, err := NewWithCombined(mock.NewProvider(), nil, &Config{Issuer: "https://auth.example"}, nil)
	if err == nil {
		t.Fatal("expected error when passing nil storage.Combined")
	}
}
