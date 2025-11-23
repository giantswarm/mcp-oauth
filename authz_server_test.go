package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServeAuthorizationServerMetadata(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ServeAuthorizationServerMetadata() status = %d, want %d", w.Code, http.StatusOK)
	}

	var metadata AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode metadata: %v", err)
	}

	// Verify metadata
	if metadata.Issuer != "https://mcp.example.com" {
		t.Errorf("Issuer = %s, want https://mcp.example.com", metadata.Issuer)
	}

	if metadata.AuthorizationEndpoint != "https://mcp.example.com/oauth/authorize" {
		t.Errorf("AuthorizationEndpoint = %s, want https://mcp.example.com/oauth/authorize", metadata.AuthorizationEndpoint)
	}

	if metadata.TokenEndpoint != "https://mcp.example.com/oauth/token" {
		t.Errorf("TokenEndpoint = %s, want https://mcp.example.com/oauth/token", metadata.TokenEndpoint)
	}

	if metadata.RegistrationEndpoint != "https://mcp.example.com/oauth/register" {
		t.Errorf("RegistrationEndpoint = %s, want https://mcp.example.com/oauth/register", metadata.RegistrationEndpoint)
	}

	// Verify response types
	if len(metadata.ResponseTypesSupported) != 1 || metadata.ResponseTypesSupported[0] != "code" {
		t.Errorf("ResponseTypesSupported = %v, want [code]", metadata.ResponseTypesSupported)
	}

	// Verify grant types
	expectedGrantTypes := []string{"authorization_code", "refresh_token"}
	if len(metadata.GrantTypesSupported) != len(expectedGrantTypes) {
		t.Errorf("GrantTypesSupported length = %d, want %d", len(metadata.GrantTypesSupported), len(expectedGrantTypes))
	}

	// Verify PKCE methods - only S256 supported (plain is insecure per OAuth 2.1)
	expectedPKCE := []string{"S256"}
	if len(metadata.CodeChallengeMethodsSupported) != len(expectedPKCE) {
		t.Errorf("CodeChallengeMethodsSupported = %v, want %v", metadata.CodeChallengeMethodsSupported, expectedPKCE)
	}
	if len(metadata.CodeChallengeMethodsSupported) > 0 && metadata.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("CodeChallengeMethodsSupported[0] = %s, want S256", metadata.CodeChallengeMethodsSupported[0])
	}
}

func TestHandler_ServeAuthorizationServerMetadata_MethodNotAllowed(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ServeAuthorizationServerMetadata() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_ServeDynamicClientRegistration(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		Security: SecurityConfig{
			AllowPublicClientRegistration: true, // For testing only
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	regReq := &ClientRegistrationRequest{
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		ClientName:    "Test MCP Client",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}

	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeDynamicClientRegistration(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("ServeDynamicClientRegistration() status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp ClientRegistrationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response
	if resp.ClientID == "" {
		t.Error("ClientID should not be empty")
	}

	if resp.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}

	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "http://localhost:8080/callback" {
		t.Errorf("RedirectURIs = %v, want [http://localhost:8080/callback]", resp.RedirectURIs)
	}

	if resp.ClientName != "Test MCP Client" {
		t.Errorf("ClientName = %s, want Test MCP Client", resp.ClientName)
	}

	if resp.ClientIDIssuedAt == 0 {
		t.Error("ClientIDIssuedAt should be set")
	}

	if resp.ClientSecretExpiresAt != 0 {
		t.Errorf("ClientSecretExpiresAt = %d, want 0 (never expires)", resp.ClientSecretExpiresAt)
	}
}

func TestHandler_ServeDynamicClientRegistration_NoRedirectURIs(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		Security: SecurityConfig{
			AllowPublicClientRegistration: true, // For testing only
		},
	})

	regReq := &ClientRegistrationRequest{
		ClientName: "Test Client",
	}

	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeDynamicClientRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ServeDynamicClientRegistration() status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errorResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResp.Error != "invalid_redirect_uri" {
		t.Errorf("Error = %s, want invalid_redirect_uri", errorResp.Error)
	}
}

func TestHandler_ServeDynamicClientRegistration_InvalidRedirectURI(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		Security: SecurityConfig{
			AllowPublicClientRegistration: true, // For testing only
		},
	})

	tests := []struct {
		name        string
		redirectURI string
		wantStatus  int
	}{
		{
			name:        "relative path (no scheme)",
			redirectURI: "/callback",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "http without host",
			redirectURI: "http:///callback",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "custom scheme (valid)",
			redirectURI: "myapp://callback",
			wantStatus:  http.StatusCreated, // Custom schemes are valid in OAuth 2.1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regReq := &ClientRegistrationRequest{
				RedirectURIs: []string{tt.redirectURI},
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeDynamicClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ServeDynamicClientRegistration() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_ServeDynamicClientRegistration_MethodNotAllowed(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	w := httptest.NewRecorder()

	handler.ServeDynamicClientRegistration(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ServeDynamicClientRegistration() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_ServeAuthorization_MissingParameters(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		GoogleAuth: GoogleAuthConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	})

	tests := []struct {
		name        string
		queryParams map[string]string
		wantError   string
	}{
		{
			name:        "missing client_id",
			queryParams: map[string]string{},
			wantError:   "invalid_request",
		},
		{
			name: "missing redirect_uri",
			queryParams: map[string]string{
				"client_id": "test-client",
			},
			wantError: "invalid_request",
		},
		// Note: state is RECOMMENDED but not required (OAuth 2.1)
		// Test removed - missing state should NOT return an error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := "/oauth/authorize?"
			for k, v := range tt.queryParams {
				reqURL += k + "=" + v + "&"
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			w := httptest.NewRecorder()

			handler.ServeAuthorization(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("ServeAuthorization() status = %d, want %d", w.Code, http.StatusBadRequest)
			}

			var errorResp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			if errorResp.Error != tt.wantError {
				t.Errorf("Error = %s, want %s", errorResp.Error, tt.wantError)
			}
		})
	}
}

func TestHandler_ServeAuthorization_InvalidClient(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		GoogleAuth: GoogleAuthConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=nonexistent&redirect_uri=http://localhost:8080/callback&state=test-state", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ServeAuthorization() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var errorResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResp.Error != "invalid_client" {
		t.Errorf("Error = %s, want invalid_client", errorResp.Error)
	}
}

func TestHandler_ServeToken_UnsupportedGrantType(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ServeToken() status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errorResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResp.Error != "unsupported_grant_type" {
		t.Errorf("Error = %s, want unsupported_grant_type", errorResp.Error)
	}
}

func TestHandler_ServeToken_MethodNotAllowed(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ServeToken() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_UpdatedProtectedResourceMetadata(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeProtectedResourceMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ServeProtectedResourceMetadata() status = %d, want %d", w.Code, http.StatusOK)
	}

	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode metadata: %v", err)
	}

	// Verify authorization servers point to the server (not Google)
	if len(metadata.AuthorizationServers) != 1 {
		t.Errorf("AuthorizationServers length = %d, want 1", len(metadata.AuthorizationServers))
	}

	if metadata.AuthorizationServers[0] != "https://mcp.example.com" {
		t.Errorf("AuthorizationServers[0] = %s, want https://mcp.example.com (should point to the server, not Google)", metadata.AuthorizationServers[0])
	}
}

func TestHandler_ValidateScopes(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/drive",
		},
	})

	tests := []struct {
		name        string
		scope       string
		wantError   bool
		errContains string
	}{
		{
			name:      "empty scope",
			scope:     "",
			wantError: false,
		},
		{
			name:      "supported Google scope",
			scope:     "https://www.googleapis.com/auth/gmail.readonly",
			wantError: false,
		},
		{
			name:      "multiple supported Google scopes",
			scope:     "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive",
			wantError: false,
		},
		{
			name:        "unsupported Google scope",
			scope:       "https://www.googleapis.com/auth/youtube",
			wantError:   true,
			errContains: "unsupported Google API scope",
		},
		{
			name:      "MCP scopes are ignored (not rejected)",
			scope:     "mcp:tools mcp:resources",
			wantError: false,
		},
		{
			name:      "mix of MCP scopes and supported Google scopes",
			scope:     "mcp:tools https://www.googleapis.com/auth/gmail.readonly mcp:resources",
			wantError: false,
		},
		{
			name:        "mix of MCP scopes and unsupported Google scopes",
			scope:       "mcp:tools https://www.googleapis.com/auth/youtube",
			wantError:   true,
			errContains: "unsupported Google API scope",
		},
		{
			name:      "openid scope is ignored",
			scope:     "openid profile email",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateScopes(tt.scope)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateScopes() error = nil, want error containing %q", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateScopes() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateScopes() error = %v, want nil", err)
				}
			}
		})
	}
}
