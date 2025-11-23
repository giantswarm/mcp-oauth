package oauth

import (
	"log/slog"
	"testing"
)

func TestClientStore_RegisterClient(t *testing.T) {
	store := NewClientStore(slog.Default())

	req := &ClientRegistrationRequest{
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		ClientName:    "Test Client",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}

	resp, err := store.RegisterClient(req, "192.0.2.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	if resp.ClientID == "" {
		t.Error("ClientID should not be empty")
	}

	if resp.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}

	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "http://localhost:8080/callback" {
		t.Errorf("RedirectURIs = %v, want %v", resp.RedirectURIs, req.RedirectURIs)
	}

	if resp.ClientName != "Test Client" {
		t.Errorf("ClientName = %s, want %s", resp.ClientName, "Test Client")
	}
}

func TestClientStore_GetClient(t *testing.T) {
	store := NewClientStore(slog.Default())

	// Register a client first
	req := &ClientRegistrationRequest{
		RedirectURIs: []string{"http://localhost:8080/callback"},
		ClientName:   "Test Client",
	}

	resp, err := store.RegisterClient(req, "192.0.2.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Retrieve the client
	client, err := store.GetClient(resp.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}

	if client.ClientID != resp.ClientID {
		t.Errorf("ClientID = %s, want %s", client.ClientID, resp.ClientID)
	}

	if client.ClientName != "Test Client" {
		t.Errorf("ClientName = %s, want %s", client.ClientName, "Test Client")
	}
}

func TestClientStore_GetClient_NotFound(t *testing.T) {
	store := NewClientStore(slog.Default())

	_, err := store.GetClient("nonexistent")
	if err == nil {
		t.Error("GetClient() should return error for nonexistent client")
	}
}

func TestClientStore_ValidateClientSecret(t *testing.T) {
	store := NewClientStore(slog.Default())

	// Register a client
	req := &ClientRegistrationRequest{
		RedirectURIs: []string{"http://localhost:8080/callback"},
	}

	resp, err := store.RegisterClient(req, "192.0.2.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Validate with correct secret
	err = store.ValidateClientSecret(resp.ClientID, resp.ClientSecret)
	if err != nil {
		t.Errorf("ValidateClientSecret() with correct secret error = %v", err)
	}

	// Validate with wrong secret
	err = store.ValidateClientSecret(resp.ClientID, "wrong-secret")
	if err == nil {
		t.Error("ValidateClientSecret() should return error for wrong secret")
	}
}

func TestClientStore_ValidateRedirectURI(t *testing.T) {
	store := NewClientStore(slog.Default())

	// Register a client
	req := &ClientRegistrationRequest{
		RedirectURIs: []string{
			"http://localhost:8080/callback",
			"http://localhost:8081/callback",
		},
	}

	resp, err := store.RegisterClient(req, "192.0.2.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name        string
		redirectURI string
		wantErr     bool
	}{
		{
			name:        "valid redirect URI 1",
			redirectURI: "http://localhost:8080/callback",
			wantErr:     false,
		},
		{
			name:        "valid redirect URI 2",
			redirectURI: "http://localhost:8081/callback",
			wantErr:     false,
		},
		{
			name:        "invalid redirect URI",
			redirectURI: "http://evil.com/callback",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.ValidateRedirectURI(resp.ClientID, tt.redirectURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientStore_RegisterClient_Defaults(t *testing.T) {
	store := NewClientStore(slog.Default())

	// Register with minimal request
	req := &ClientRegistrationRequest{
		RedirectURIs: []string{"http://localhost:8080/callback"},
	}

	resp, err := store.RegisterClient(req, "192.0.2.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Check defaults
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod = %s, want client_secret_basic", resp.TokenEndpointAuthMethod)
	}

	if len(resp.GrantTypes) != 2 || resp.GrantTypes[0] != "authorization_code" || resp.GrantTypes[1] != "refresh_token" {
		t.Errorf("GrantTypes = %v, want [authorization_code refresh_token]", resp.GrantTypes)
	}

	if len(resp.ResponseTypes) != 1 || resp.ResponseTypes[0] != "code" {
		t.Errorf("ResponseTypes = %v, want [code]", resp.ResponseTypes)
	}

	if resp.ClientSecretExpiresAt != 0 {
		t.Errorf("ClientSecretExpiresAt = %d, want 0 (never expires)", resp.ClientSecretExpiresAt)
	}
}
