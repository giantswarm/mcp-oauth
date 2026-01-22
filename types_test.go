package oauth

import (
	"encoding/json"
	"errors"
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

func TestCallbackResult_IsError(t *testing.T) {
	tests := []struct {
		name     string
		result   CallbackResult
		expected bool
	}{
		{
			name: "successful callback - not an error",
			result: CallbackResult{
				Code:  "abc123",
				State: "state456",
			},
			expected: false,
		},
		{
			name: "error callback - access_denied",
			result: CallbackResult{
				Error:            "access_denied",
				ErrorDescription: "User denied the request",
				State:            "state456",
			},
			expected: true,
		},
		{
			name: "error callback - login_required",
			result: CallbackResult{
				Error: "login_required",
				State: "state456",
			},
			expected: true,
		},
		{
			name:     "empty result",
			result:   CallbackResult{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsError(); got != tt.expected {
				t.Errorf("CallbackResult.IsError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCallbackResult_Err(t *testing.T) {
	tests := []struct {
		name           string
		result         CallbackResult
		wantNil        bool
		wantSilentAuth bool
		wantMessage    string
	}{
		{
			name: "successful callback returns nil",
			result: CallbackResult{
				Code:  "abc123",
				State: "state456",
			},
			wantNil: true,
		},
		{
			name: "login_required returns SilentAuthError",
			result: CallbackResult{
				Error:            "login_required",
				ErrorDescription: "User must authenticate",
				State:            "state456",
			},
			wantSilentAuth: true,
			wantMessage:    "silent authentication failed: login_required - User must authenticate",
		},
		{
			name: "consent_required returns SilentAuthError",
			result: CallbackResult{
				Error: "consent_required",
				State: "state456",
			},
			wantSilentAuth: true,
			wantMessage:    "silent authentication failed: consent_required",
		},
		{
			name: "interaction_required returns SilentAuthError",
			result: CallbackResult{
				Error:            "interaction_required",
				ErrorDescription: "UI required",
				State:            "state456",
			},
			wantSilentAuth: true,
			wantMessage:    "silent authentication failed: interaction_required - UI required",
		},
		{
			name: "access_denied returns generic error",
			result: CallbackResult{
				Error:            "access_denied",
				ErrorDescription: "User denied the request",
				State:            "state456",
			},
			wantSilentAuth: false,
			wantMessage:    "oauth error: access_denied - User denied the request",
		},
		{
			name: "empty error returns nil",
			result: CallbackResult{
				State: "state456",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Err()

			if tt.wantNil {
				if err != nil {
					t.Errorf("CallbackResult.Err() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatal("CallbackResult.Err() = nil, want error")
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("CallbackResult.Err().Error() = %q, want %q", err.Error(), tt.wantMessage)
			}

			if tt.wantSilentAuth {
				var silentErr *SilentAuthError
				if !errors.As(err, &silentErr) {
					t.Errorf("CallbackResult.Err() should return *SilentAuthError")
				}
				if !IsSilentAuthError(err) {
					t.Errorf("IsSilentAuthError() should return true")
				}
			}
		})
	}
}

func TestParseCallbackQuery(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		state            string
		errorCode        string
		errorDescription string
		errorURI         string
	}{
		{
			name:  "successful callback",
			code:  "auth_code_123",
			state: "state_456",
		},
		{
			name:             "error callback with all fields",
			state:            "state_456",
			errorCode:        "login_required",
			errorDescription: "User must authenticate",
			errorURI:         "https://docs.example.com/errors",
		},
		{
			name:      "error callback without description",
			state:     "state_456",
			errorCode: "access_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCallbackQuery(tt.code, tt.state, tt.errorCode, tt.errorDescription, tt.errorURI)

			if result.Code != tt.code {
				t.Errorf("Code = %q, want %q", result.Code, tt.code)
			}
			if result.State != tt.state {
				t.Errorf("State = %q, want %q", result.State, tt.state)
			}
			if result.Error != tt.errorCode {
				t.Errorf("Error = %q, want %q", result.Error, tt.errorCode)
			}
			if result.ErrorDescription != tt.errorDescription {
				t.Errorf("ErrorDescription = %q, want %q", result.ErrorDescription, tt.errorDescription)
			}
			if result.ErrorURI != tt.errorURI {
				t.Errorf("ErrorURI = %q, want %q", result.ErrorURI, tt.errorURI)
			}
		})
	}
}

func TestCallbackResult_SilentAuthWorkflow(t *testing.T) {
	// This test demonstrates the typical silent auth workflow:
	// 1. Client sends authorization request with prompt=none
	// 2. IdP returns error because user session doesn't exist
	// 3. Client detects silent auth failure and falls back to interactive login

	// Simulate IdP returning login_required error
	result := ParseCallbackQuery(
		"",           // No code because auth failed
		"csrf_state", // State preserved
		"login_required",
		"The user is not logged in",
		"",
	)

	// Check if it's an error
	if !result.IsError() {
		t.Fatal("Expected callback to be an error")
	}

	// Get the typed error
	err := result.Err()
	if err == nil {
		t.Fatal("Expected non-nil error")
	}

	// Detect that it's a silent auth error
	if !IsSilentAuthError(err) {
		t.Error("Expected IsSilentAuthError to return true")
	}

	// Extract the SilentAuthError details
	var silentErr *SilentAuthError
	if !errors.As(err, &silentErr) {
		t.Fatal("Expected error to be *SilentAuthError")
	}

	if silentErr.Code != "login_required" {
		t.Errorf("SilentAuthError.Code = %q, want %q", silentErr.Code, "login_required")
	}
	if silentErr.Description != "The user is not logged in" {
		t.Errorf("SilentAuthError.Description = %q, want %q", silentErr.Description, "The user is not logged in")
	}
}
