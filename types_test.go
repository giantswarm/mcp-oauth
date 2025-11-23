package oauth

import (
	"encoding/json"
	"testing"
)

func TestProtectedResourceMetadata_JSON(t *testing.T) {
	tests := []struct {
		name string
		meta ProtectedResourceMetadata
	}{
		{
			name: "complete metadata",
			meta: ProtectedResourceMetadata{
				Resource:             "https://api.example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
				BearerMethodsSupported: []string{
					"header",
					"body",
					"query",
				},
				ResourceSigningAlgValuesSupported: []string{
					"RS256",
					"ES256",
				},
				ScopesSupported: []string{
					"read",
					"write",
				},
			},
		},
		{
			name: "minimal metadata",
			meta: ProtectedResourceMetadata{
				Resource:             "https://api.example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.meta)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			// Unmarshal back
			var got ProtectedResourceMetadata
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			// Compare
			if got.Resource != tt.meta.Resource {
				t.Errorf("Resource = %q, want %q", got.Resource, tt.meta.Resource)
			}
		})
	}
}

func TestErrorResponse_JSON(t *testing.T) {
	tests := []struct {
		name string
		err  ErrorResponse
	}{
		{
			name: "complete error",
			err: ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "The request is missing a required parameter",
				ErrorURI:         "https://example.com/docs/errors#invalid_request",
			},
		},
		{
			name: "minimal error",
			err: ErrorResponse{
				Error: "server_error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.err)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			// Unmarshal back
			var got ErrorResponse
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			// Compare
			if got.Error != tt.err.Error {
				t.Errorf("Error = %q, want %q", got.Error, tt.err.Error)
			}
			if got.ErrorDescription != tt.err.ErrorDescription {
				t.Errorf("ErrorDescription = %q, want %q", got.ErrorDescription, tt.err.ErrorDescription)
			}
			if got.ErrorURI != tt.err.ErrorURI {
				t.Errorf("ErrorURI = %q, want %q", got.ErrorURI, tt.err.ErrorURI)
			}
		})
	}
}

func TestAuthorizationServerMetadata_JSON(t *testing.T) {
	meta := AuthorizationServerMetadata{
		Issuer:                            "https://auth.example.com",
		AuthorizationEndpoint:             "https://auth.example.com/authorize",
		TokenEndpoint:                     "https://auth.example.com/token",
		RegistrationEndpoint:              "https://auth.example.com/register",
		ScopesSupported:                   []string{"openid", "email", "profile"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}

	// Marshal to JSON
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var got AuthorizationServerMetadata
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Compare critical fields
	if got.Issuer != meta.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, meta.Issuer)
	}
	if got.AuthorizationEndpoint != meta.AuthorizationEndpoint {
		t.Errorf("AuthorizationEndpoint = %q, want %q", got.AuthorizationEndpoint, meta.AuthorizationEndpoint)
	}
	if got.TokenEndpoint != meta.TokenEndpoint {
		t.Errorf("TokenEndpoint = %q, want %q", got.TokenEndpoint, meta.TokenEndpoint)
	}
}

func TestClientRegistrationRequest_JSON(t *testing.T) {
	req := ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Example Client",
		ClientURI:               "https://example.com",
		Scope:                   "openid email profile",
		ClientType:              "confidential",
	}

	// Marshal to JSON
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var got ClientRegistrationRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Compare
	if got.ClientName != req.ClientName {
		t.Errorf("ClientName = %q, want %q", got.ClientName, req.ClientName)
	}
	if got.ClientType != req.ClientType {
		t.Errorf("ClientType = %q, want %q", got.ClientType, req.ClientType)
	}
}

func TestClientRegistrationResponse_JSON(t *testing.T) {
	resp := ClientRegistrationResponse{
		ClientID:                "test-client-id",
		ClientSecret:            "test-client-secret",
		ClientIDIssuedAt:        1234567890,
		ClientSecretExpiresAt:   0,
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Example Client",
		Scope:                   "openid email profile",
		ClientType:              "confidential",
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var got ClientRegistrationResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Compare
	if got.ClientID != resp.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, resp.ClientID)
	}
	if got.ClientSecret != resp.ClientSecret {
		t.Errorf("ClientSecret = %q, want %q", got.ClientSecret, resp.ClientSecret)
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
		Scope:        "openid email profile",
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var got TokenResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Compare
	if got.AccessToken != resp.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, resp.AccessToken)
	}
	if got.TokenType != resp.TokenType {
		t.Errorf("TokenType = %q, want %q", got.TokenType, resp.TokenType)
	}
	if got.ExpiresIn != resp.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", got.ExpiresIn, resp.ExpiresIn)
	}
	if got.RefreshToken != resp.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, resp.RefreshToken)
	}
	if got.Scope != resp.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, resp.Scope)
	}
}
