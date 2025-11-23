package oauth

import (
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNewServer(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := NewServer(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if srv == nil {
		t.Fatal("NewServer() returned nil")
	}
}
