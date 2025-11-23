package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Resource: "https://mcp.example.com",
			},
			wantErr: false,
		},
		{
			name:   "missing resource",
			config: &Config{
				// Resource is required
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewHandler(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHandler() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && handler == nil {
				t.Error("NewHandler() returned nil handler")
			}
		})
	}
}

func TestHandler_ServeProtectedResourceMetadata(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/drive",
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

	// Verify resource
	if metadata.Resource != "https://mcp.example.com" {
		t.Errorf("metadata.Resource = %s, want https://mcp.example.com", metadata.Resource)
	}

	// Verify authorization servers (should point to the server, not Google, in OAuth proxy mode)
	if len(metadata.AuthorizationServers) != 1 {
		t.Errorf("metadata.AuthorizationServers length = %d, want 1", len(metadata.AuthorizationServers))
	}
	if metadata.AuthorizationServers[0] != "https://mcp.example.com" {
		t.Errorf("metadata.AuthorizationServers[0] = %s, want https://mcp.example.com (OAuth proxy mode)", metadata.AuthorizationServers[0])
	}

	// Verify bearer methods
	if len(metadata.BearerMethodsSupported) != 1 {
		t.Errorf("metadata.BearerMethodsSupported length = %d, want 1", len(metadata.BearerMethodsSupported))
	}
	if metadata.BearerMethodsSupported[0] != "header" {
		t.Errorf("metadata.BearerMethodsSupported[0] = %s, want header", metadata.BearerMethodsSupported[0])
	}

	// Verify scopes
	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("metadata.ScopesSupported length = %d, want 2", len(metadata.ScopesSupported))
	}
}

func TestHandler_ServeProtectedResourceMetadata_MethodNotAllowed(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeProtectedResourceMetadata(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ServeProtectedResourceMetadata() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_GetStore(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	store := handler.GetStore()
	if store == nil {
		t.Error("GetStore() returned nil store")
	}
}

func TestHandler_GetConfig(t *testing.T) {
	config := &Config{
		Resource: "https://mcp.example.com",
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	retrievedConfig := handler.GetConfig()
	if retrievedConfig == nil {
		t.Fatal("GetConfig() returned nil config")
	}

	if retrievedConfig.Resource != config.Resource {
		t.Errorf("GetConfig() Resource = %s, want %s", retrievedConfig.Resource, config.Resource)
	}

	if len(retrievedConfig.SupportedScopes) != len(config.SupportedScopes) {
		t.Errorf("GetConfig() SupportedScopes length = %d, want %d", len(retrievedConfig.SupportedScopes), len(config.SupportedScopes))
	}
}

func TestHandler_WriteError(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	w := httptest.NewRecorder()
	handler.writeError(w, "invalid_request", "The request is invalid", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("writeError() status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("writeError() Content-Type = %s, want application/json", contentType)
	}

	var errorResponse ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResponse.Error != "invalid_request" {
		t.Errorf("writeError() Error = %s, want invalid_request", errorResponse.Error)
	}

	if errorResponse.ErrorDescription != "The request is invalid" {
		t.Errorf("writeError() ErrorDescription = %s, want 'The request is invalid'", errorResponse.ErrorDescription)
	}
}
