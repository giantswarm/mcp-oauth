package server

import (
	"context"
	"strings"
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

func TestServer_CanRegisterWithTrustedScheme(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	tests := []struct {
		name                        string
		trustedSchemes              []string
		disableStrictSchemeMatching bool // Use this to test permissive mode (defaults to strict)
		redirectURIs                []string
		wantAllowed                 bool
		wantScheme                  string
		wantErr                     bool
		wantErrContains             string
	}{
		// Basic functionality tests
		{
			name:           "no trusted schemes configured - require token",
			trustedSchemes: nil,
			redirectURIs:   []string{"cursor://oauth/callback"},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},
		{
			name:           "empty trusted schemes - require token",
			trustedSchemes: []string{},
			redirectURIs:   []string{"cursor://oauth/callback"},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},
		{
			name:           "no redirect URIs - require token",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},
		{
			name:           "nil redirect URIs - require token",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   nil,
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},

		// Trusted scheme matching tests
		{
			name:           "single cursor scheme allowed",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"cursor://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},
		{
			name:           "single vscode scheme allowed",
			trustedSchemes: []string{"vscode"},
			redirectURIs:   []string{"vscode://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "vscode",
			wantErr:        false,
		},
		{
			name:           "multiple trusted schemes - cursor matches",
			trustedSchemes: []string{"cursor", "vscode", "vscode-insiders"},
			redirectURIs:   []string{"cursor://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},
		{
			name:           "multiple trusted schemes - vscode-insiders matches",
			trustedSchemes: []string{"cursor", "vscode", "vscode-insiders"},
			redirectURIs:   []string{"vscode-insiders://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "vscode-insiders",
			wantErr:        false,
		},

		// Case insensitivity tests
		{
			name:           "scheme matching is case insensitive",
			trustedSchemes: []string{"Cursor"},
			redirectURIs:   []string{"cursor://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},
		{
			name:           "uppercase redirect URI scheme matches",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"CURSOR://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},

		// Multiple redirect URIs - strict matching (default)
		{
			name:           "strict: all URIs use trusted schemes - allowed",
			trustedSchemes: []string{"cursor", "vscode"},
			redirectURIs:   []string{"cursor://oauth/callback", "vscode://oauth/callback"},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},
		{
			name:           "strict: mixed schemes - not allowed",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"cursor://oauth/callback", "https://example.com/callback"},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},
		{
			name:           "strict: all URIs untrusted - not allowed",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"https://example.com/callback"},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},

		// Multiple redirect URIs - permissive matching (requires DisableStrictSchemeMatching)
		{
			name:                        "permissive: mixed schemes - allowed (has trusted)",
			trustedSchemes:              []string{"cursor"},
			disableStrictSchemeMatching: true,
			redirectURIs:                []string{"cursor://oauth/callback", "https://example.com/callback"},
			wantAllowed:                 true,
			wantScheme:                  "cursor",
			wantErr:                     false,
		},
		{
			name:                        "permissive: all untrusted - not allowed",
			trustedSchemes:              []string{"cursor"},
			disableStrictSchemeMatching: true,
			redirectURIs:                []string{"https://example.com/callback"},
			wantAllowed:                 false,
			wantScheme:                  "",
			wantErr:                     false,
		},
		{
			name:                        "permissive: trusted at end of list",
			trustedSchemes:              []string{"cursor"},
			disableStrictSchemeMatching: true,
			redirectURIs:                []string{"https://example.com/callback", "cursor://oauth/callback"},
			wantAllowed:                 true,
			wantScheme:                  "cursor",
			wantErr:                     false,
		},

		// Error cases
		{
			name:            "invalid redirect URI format",
			trustedSchemes:  []string{"cursor"},
			redirectURIs:    []string{"://invalid"},
			wantAllowed:     false,
			wantScheme:      "",
			wantErr:         true,
			wantErrContains: "invalid redirect URI",
		},
		{
			name:            "redirect URI missing scheme",
			trustedSchemes:  []string{"cursor"},
			redirectURIs:    []string{"/path/only"},
			wantAllowed:     false,
			wantScheme:      "",
			wantErr:         true,
			wantErrContains: "missing scheme",
		},

		// Edge cases - extremely long URIs (security: ensure no buffer issues)
		{
			name:           "extremely long redirect URI path - trusted scheme",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"cursor://oauth/callback/" + strings.Repeat("a", 10000)},
			wantAllowed:    true,
			wantScheme:     "cursor",
			wantErr:        false,
		},
		{
			name:           "extremely long redirect URI path - untrusted scheme",
			trustedSchemes: []string{"cursor"},
			redirectURIs:   []string{"https://example.com/callback/" + strings.Repeat("b", 10000)},
			wantAllowed:    false,
			wantScheme:     "",
			wantErr:        false,
		},
		{
			name:           "many redirect URIs - all trusted",
			trustedSchemes: []string{"cursor", "vscode"},
			redirectURIs: func() []string {
				uris := make([]string, 100)
				for i := range uris {
					if i%2 == 0 {
						uris[i] = "cursor://oauth/callback/" + strings.Repeat("x", i)
					} else {
						uris[i] = "vscode://oauth/callback/" + strings.Repeat("y", i)
					}
				}
				return uris
			}(),
			wantAllowed: true,
			wantScheme:  "cursor",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Issuer:                           "https://auth.example.com",
				TrustedPublicRegistrationSchemes: tt.trustedSchemes,
				DisableStrictSchemeMatching:      tt.disableStrictSchemeMatching,
			}

			srv, err := New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			allowed, scheme, err := srv.CanRegisterWithTrustedScheme(tt.redirectURIs)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("CanRegisterWithTrustedScheme() expected error, got nil")
					return
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanRegisterWithTrustedScheme() unexpected error = %v", err)
			}

			// Check allowed
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}

			// Check scheme
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
			}
		})
	}
}
