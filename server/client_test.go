package server

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestServer_RegisterClient(t *testing.T) {
	ctx := context.Background()
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

	tests := []struct {
		name         string
		clientName   string
		clientType   string
		redirectURIs []string
		scopes       []string
		clientIP     string
		maxPerIP     int
		wantErr      bool
	}{
		{
			name:         "register confidential client",
			clientName:   "Test Client",
			clientType:   ClientTypeConfidential,
			redirectURIs: []string{"https://example.com/callback"},
			scopes:       []string{"openid", "email"},
			clientIP:     "192.168.1.100",
			maxPerIP:     10,
			wantErr:      false,
		},
		{
			name:         "register public client",
			clientName:   "Public Client",
			clientType:   ClientTypePublic,
			redirectURIs: []string{"myapp://callback"},
			scopes:       []string{"openid"},
			clientIP:     "192.168.1.101",
			maxPerIP:     10,
			wantErr:      false,
		},
		{
			name:         "register with default type (confidential)",
			clientName:   "Default Type Client",
			clientType:   "",
			redirectURIs: []string{"https://example.com/callback"},
			scopes:       []string{"openid"},
			clientIP:     "192.168.1.102",
			maxPerIP:     10,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, secret, err := srv.RegisterClient(ctx,
				tt.clientName,
				tt.clientType,
				"", // tokenEndpointAuthMethod
				tt.redirectURIs,
				tt.scopes,
				tt.clientIP,
				tt.maxPerIP,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify client was created
			if client == nil {
				t.Fatal("RegisterClient() returned nil client")
			}

			if client.ClientID == "" {
				t.Error("RegisterClient() client ID is empty")
			}

			if client.ClientName != tt.clientName {
				t.Errorf("ClientName = %q, want %q", client.ClientName, tt.clientName)
			}

			// Verify client type
			expectedType := tt.clientType
			if expectedType == "" {
				expectedType = ClientTypeConfidential
			}
			if client.ClientType != expectedType {
				t.Errorf("ClientType = %q, want %q", client.ClientType, expectedType)
			}

			// Verify secret handling
			if expectedType == ClientTypeConfidential {
				if secret == "" {
					t.Error("RegisterClient() confidential client should have secret")
				}
				if client.ClientSecretHash == "" {
					t.Error("RegisterClient() confidential client should have secret hash")
				}

				// Verify secret hash is valid
				err = bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(secret))
				if err != nil {
					t.Errorf("Secret hash verification failed: %v", err)
				}

				if client.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("TokenEndpointAuthMethod = %q, want %q", client.TokenEndpointAuthMethod, "client_secret_basic")
				}
			} else {
				if secret != "" {
					t.Error("RegisterClient() public client should not have secret")
				}
				if client.ClientSecretHash != "" {
					t.Error("RegisterClient() public client should not have secret hash")
				}

				if client.TokenEndpointAuthMethod != "none" {
					t.Errorf("TokenEndpointAuthMethod = %q, want %q", client.TokenEndpointAuthMethod, "none")
				}
			}

			// Verify redirect URIs
			if len(client.RedirectURIs) != len(tt.redirectURIs) {
				t.Errorf("len(RedirectURIs) = %d, want %d", len(client.RedirectURIs), len(tt.redirectURIs))
			}

			// Verify scopes
			if len(client.Scopes) != len(tt.scopes) {
				t.Errorf("len(Scopes) = %d, want %d", len(client.Scopes), len(tt.scopes))
			}

			// Verify grant types
			if len(client.GrantTypes) != 2 {
				t.Errorf("len(GrantTypes) = %d, want 2", len(client.GrantTypes))
			}

			// Verify response types
			if len(client.ResponseTypes) != 1 || client.ResponseTypes[0] != "code" {
				t.Errorf("ResponseTypes = %v, want [code]", client.ResponseTypes)
			}
		})
	}
}

func TestServer_RegisterClient_IPLimit(t *testing.T) {
	ctx := context.Background()
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

	clientIP := "192.168.1.200"
	maxPerIP := 2

	// Register first client
	_, _, err = srv.RegisterClient(ctx,
		"Client 1",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback1"},
		[]string{"openid"},
		clientIP,
		maxPerIP,
	)
	if err != nil {
		t.Fatalf("First RegisterClient() error = %v", err)
	}

	// Register second client
	_, _, err = srv.RegisterClient(ctx,
		"Client 2",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback2"},
		[]string{"openid"},
		clientIP,
		maxPerIP,
	)
	if err != nil {
		t.Fatalf("Second RegisterClient() error = %v", err)
	}

	// Third registration should fail (exceeds limit)
	_, _, err = srv.RegisterClient(ctx,
		"Client 3",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback3"},
		[]string{"openid"},
		clientIP,
		maxPerIP,
	)
	if err == nil {
		t.Error("RegisterClient() should fail when IP limit exceeded")
	}
}

func TestServer_ValidateClientCredentials(t *testing.T) {
	ctx := context.Background()
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

	// Register a client
	client, secret, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantErr      bool
	}{
		{
			name:         "valid credentials",
			clientID:     client.ClientID,
			clientSecret: secret,
			wantErr:      false,
		},
		{
			name:         "invalid client ID",
			clientID:     "nonexistent-client",
			clientSecret: secret,
			wantErr:      true,
		},
		{
			name:         "invalid secret",
			clientID:     client.ClientID,
			clientSecret: "wrong-secret",
			wantErr:      true,
		},
		{
			name:         "empty secret",
			clientID:     client.ClientID,
			clientSecret: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.ValidateClientCredentials(ctx, tt.clientID, tt.clientSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClientCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_GetClient(t *testing.T) {
	ctx := context.Background()
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

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name     string
		clientID string
		wantErr  bool
	}{
		{
			name:     "existing client",
			clientID: client.ClientID,
			wantErr:  false,
		},
		{
			name:     "nonexistent client",
			clientID: "nonexistent-client-id",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := srv.GetClient(ctx, tt.clientID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got == nil {
					t.Error("GetClient() returned nil client")
				} else if got.ClientID != tt.clientID {
					t.Errorf("GetClient() ClientID = %q, want %q", got.ClientID, tt.clientID)
				}
			}
		})
	}
}

func TestClientTypeConstants(t *testing.T) {
	if ClientTypeConfidential != "confidential" {
		t.Errorf("ClientTypeConfidential = %q, want %q", ClientTypeConfidential, "confidential")
	}

	if ClientTypePublic != "public" {
		t.Errorf("ClientTypePublic = %q, want %q", ClientTypePublic, "public")
	}
}

func TestServer_RegisterClient_TokenEndpointAuthMethod(t *testing.T) {
	ctx := context.Background()
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

	tests := []struct {
		name                    string
		clientName              string
		clientType              string
		tokenEndpointAuthMethod string
		wantClientType          string
		wantAuthMethod          string
		wantSecret              bool
	}{
		{
			name:                    "token_endpoint_auth_method=none creates public client",
			clientName:              "Native App",
			clientType:              "",
			tokenEndpointAuthMethod: "none",
			wantClientType:          ClientTypePublic,
			wantAuthMethod:          "none",
			wantSecret:              false,
		},
		{
			name:                    "token_endpoint_auth_method=client_secret_basic creates confidential client",
			clientName:              "Web App",
			clientType:              "",
			tokenEndpointAuthMethod: "client_secret_basic",
			wantClientType:          ClientTypeConfidential,
			wantAuthMethod:          "client_secret_basic",
			wantSecret:              true,
		},
		{
			name:                    "token_endpoint_auth_method=client_secret_post creates confidential client",
			clientName:              "Server App",
			clientType:              "",
			tokenEndpointAuthMethod: "client_secret_post",
			wantClientType:          ClientTypeConfidential,
			wantAuthMethod:          "client_secret_post",
			wantSecret:              true,
		},
		{
			name:                    "empty auth method + public type uses none",
			clientName:              "Mobile App",
			clientType:              ClientTypePublic,
			tokenEndpointAuthMethod: "",
			wantClientType:          ClientTypePublic,
			wantAuthMethod:          "none",
			wantSecret:              false,
		},
		{
			name:                    "empty auth method + confidential type uses client_secret_basic",
			clientName:              "Backend Service",
			clientType:              ClientTypeConfidential,
			tokenEndpointAuthMethod: "",
			wantClientType:          ClientTypeConfidential,
			wantAuthMethod:          "client_secret_basic",
			wantSecret:              true,
		},
		{
			name:                    "auth method overrides client type (none overrides confidential)",
			clientName:              "CLI Tool",
			clientType:              ClientTypeConfidential,
			tokenEndpointAuthMethod: "none",
			wantClientType:          ClientTypePublic,
			wantAuthMethod:          "none",
			wantSecret:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, secret, err := srv.RegisterClient(ctx,
				tt.clientName,
				tt.clientType,
				tt.tokenEndpointAuthMethod,
				[]string{"https://example.com/callback"},
				[]string{"openid"},
				"192.168.1."+tt.name[:3], // Use unique IP for each test
				10,
			)

			if err != nil {
				t.Fatalf("RegisterClient() error = %v", err)
			}

			if client.ClientType != tt.wantClientType {
				t.Errorf("ClientType = %q, want %q", client.ClientType, tt.wantClientType)
			}

			if client.TokenEndpointAuthMethod != tt.wantAuthMethod {
				t.Errorf("TokenEndpointAuthMethod = %q, want %q", client.TokenEndpointAuthMethod, tt.wantAuthMethod)
			}

			if tt.wantSecret {
				if secret == "" {
					t.Error("RegisterClient() should return secret for confidential client")
				}
				if client.ClientSecretHash == "" {
					t.Error("Client should have secret hash for confidential client")
				}
			} else {
				if secret != "" {
					t.Error("RegisterClient() should not return secret for public client")
				}
				if client.ClientSecretHash != "" {
					t.Error("Client should not have secret hash for public client")
				}
			}
		})
	}
}
