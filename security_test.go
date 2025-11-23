package oauth

import (
	"testing"
)

func TestValidateClientTypeAuthMethod(t *testing.T) {
	tests := []struct {
		name       string
		clientType string
		authMethod string
		wantError  bool
	}{
		// Public client tests
		{
			name:       "public client with none auth - valid",
			clientType: "public",
			authMethod: "none",
			wantError:  false,
		},
		{
			name:       "public client with client_secret_basic - invalid",
			clientType: "public",
			authMethod: "client_secret_basic",
			wantError:  true,
		},
		{
			name:       "public client with client_secret_post - invalid",
			clientType: "public",
			authMethod: "client_secret_post",
			wantError:  true,
		},

		// Confidential client tests
		{
			name:       "confidential client with client_secret_basic - valid",
			clientType: "confidential",
			authMethod: "client_secret_basic",
			wantError:  false,
		},
		{
			name:       "confidential client with client_secret_post - valid",
			clientType: "confidential",
			authMethod: "client_secret_post",
			wantError:  false,
		},
		{
			name:       "confidential client with none auth - invalid (SECURITY VIOLATION)",
			clientType: "confidential",
			authMethod: "none",
			wantError:  true,
		},

		// Invalid client type
		{
			name:       "invalid client type",
			clientType: "invalid_type",
			authMethod: "client_secret_basic",
			wantError:  true,
		},
		{
			name:       "empty client type",
			clientType: "",
			authMethod: "client_secret_basic",
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientTypeAuthMethod(tt.clientType, tt.authMethod)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateClientTypeAuthMethod() error = nil, want error for %s/%s",
						tt.clientType, tt.authMethod)
				}
			} else {
				if err != nil {
					t.Errorf("validateClientTypeAuthMethod() error = %v, want nil for %s/%s",
						err, tt.clientType, tt.authMethod)
				}
			}
		})
	}
}

func TestClientStore_PublicClientRegistration(t *testing.T) {
	store := NewClientStore(nil)

	// Register a public client
	req := &ClientRegistrationRequest{
		ClientName:              "Test Public Client",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"myapp://callback"},
	}

	resp, err := store.RegisterClient(req, "192.168.1.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Public client should not have a client secret
	if resp.ClientSecret != "" {
		t.Error("Public client should not have client_secret")
	}

	if resp.ClientType != "public" {
		t.Errorf("ClientType = %s, want 'public'", resp.ClientType)
	}

	// Verify stored client
	client, err := store.GetClient(resp.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}

	if client.ClientType != "public" {
		t.Errorf("Stored client type = %s, want 'public'", client.ClientType)
	}

	if client.ClientSecretHash != "" {
		t.Error("Public client should not have secret hash stored")
	}
}

func TestClientStore_ConfidentialClientRegistration(t *testing.T) {
	store := NewClientStore(nil)

	// Register a confidential client
	req := &ClientRegistrationRequest{
		ClientName:              "Test Confidential Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://example.com/callback"},
	}

	resp, err := store.RegisterClient(req, "192.168.1.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Confidential client MUST have a client secret
	if resp.ClientSecret == "" {
		t.Error("Confidential client should have client_secret")
	}

	if resp.ClientType != "confidential" {
		t.Errorf("ClientType = %s, want 'confidential'", resp.ClientType)
	}

	// Verify stored client
	client, err := store.GetClient(resp.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}

	if client.ClientType != "confidential" {
		t.Errorf("Stored client type = %s, want 'confidential'", client.ClientType)
	}

	if client.ClientSecretHash == "" {
		t.Error("Confidential client should have secret hash stored")
	}
}

func TestClientStore_InvalidClientTypeAuthMethodCombination(t *testing.T) {
	store := NewClientStore(nil)

	// Try to register public client with client_secret_basic (invalid)
	req := &ClientRegistrationRequest{
		ClientName:              "Invalid Public Client",
		ClientType:              "public",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"myapp://callback"},
	}

	_, err := store.RegisterClient(req, "192.168.1.1")
	if err == nil {
		t.Error("RegisterClient() should fail for public client with client_secret_basic")
	}

	// Try to register confidential client with "none" auth (SECURITY VIOLATION)
	req2 := &ClientRegistrationRequest{
		ClientName:              "Invalid Confidential Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://example.com/callback"},
	}

	_, err = store.RegisterClient(req2, "192.168.1.1")
	if err == nil {
		t.Error("RegisterClient() should fail for confidential client with 'none' auth (CRITICAL SECURITY VIOLATION)")
	}
}

func TestClientStore_DefaultClientType(t *testing.T) {
	store := NewClientStore(nil)

	// Register without specifying client type
	req := &ClientRegistrationRequest{
		ClientName:              "Default Type Client",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://example.com/callback"},
	}

	resp, err := store.RegisterClient(req, "192.168.1.1")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Should default to confidential
	if resp.ClientType != "confidential" {
		t.Errorf("Default client type = %s, want 'confidential'", resp.ClientType)
	}

	// Should have client secret for confidential client
	if resp.ClientSecret == "" {
		t.Error("Confidential client (default) should have client_secret")
	}
}

func TestSupportedCodeChallengeMethods_NoPKCEPlain(t *testing.T) {
	// Security Test: Ensure "plain" PKCE method is NOT supported
	for _, method := range SupportedCodeChallengeMethods {
		if method == "plain" {
			t.Error("SECURITY VIOLATION: 'plain' PKCE method is supported but should be disabled")
		}
	}

	// Verify S256 is supported
	hasS256 := false
	for _, method := range SupportedCodeChallengeMethods {
		if method == "S256" {
			hasS256 = true
			break
		}
	}

	if !hasS256 {
		t.Error("S256 PKCE method should be supported")
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"email", "user@example.com"},
		{"token", "secret_token_123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashForDisplay(tt.input)

			if tt.input == "" {
				if hash != "<empty>" {
					t.Errorf("HashForDisplay('') = %q, want '<empty>'", hash)
				}
				return
			}

			// Hash should be consistent
			hash2 := HashForDisplay(tt.input)
			if hash != hash2 {
				t.Error("HashForDisplay is not consistent for same input")
			}

			// Hash should be 16 chars
			if len(hash) != 16 {
				t.Errorf("hash length = %d, want 16", len(hash))
			}

			// Hash should not contain original
			if hash == tt.input {
				t.Error("HashForDisplay returned input unchanged (not hashed)")
			}

			// Hash should be hex-encoded
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("hash contains non-hex character: %c", c)
				}
			}
		})
	}
}

func TestSecurityDefaults(t *testing.T) {
	// Test that security defaults are safe
	t.Run("default token TTLs", func(t *testing.T) {
		if DefaultAccessTokenTTL > 24*60*60*1000000000 { // 24 hours in nanoseconds
			t.Error("Default access token TTL too long (security risk)")
		}

		if DefaultRefreshTokenTTL < 7*24*60*60*1000000000 { // 7 days
			t.Error("Default refresh token TTL too short (usability issue)")
		}

		if DefaultRefreshTokenTTL > 180*24*60*60*1000000000 { // 180 days
			t.Error("Default refresh token TTL too long (security risk)")
		}
	})

	t.Run("default auth methods", func(t *testing.T) {
		// Verify default is secure (client_secret_basic)
		if DefaultTokenEndpointAuthMethod != "client_secret_basic" {
			t.Errorf("Default auth method = %s, want client_secret_basic",
				DefaultTokenEndpointAuthMethod)
		}

		// Verify "none" is in supported list (needed for public clients)
		hasNone := false
		for _, method := range SupportedTokenAuthMethods {
			if method == "none" {
				hasNone = true
				break
			}
		}
		if !hasNone {
			t.Error("'none' auth method should be in supported list (for public clients)")
		}
	})
}
