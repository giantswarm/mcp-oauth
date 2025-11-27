package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestRegisterAuthorizationServerMetadataRoutes_SingleTenant verifies that
// single-tenant deployments (no path in issuer) register standard endpoints
func TestRegisterAuthorizationServerMetadataRoutes_SingleTenant(t *testing.T) {
	// Single-tenant issuer (no path component)
	config := &ServerConfig{
		Issuer: "https://auth.example.com",
	}

	provider := mock.NewMockProvider()
	store := memory.New()
	defer store.Stop()

	server, err := NewServer(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := NewHandler(server, nil)
	mux := http.NewServeMux()

	// Register routes
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	// Test standard OAuth endpoint
	t.Run("oauth_standard_endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var metadata map[string]any
		if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if metadata["issuer"] != "https://auth.example.com" {
			t.Errorf("issuer = %v, want https://auth.example.com", metadata["issuer"])
		}
	})

	// Test standard OIDC endpoint
	t.Run("oidc_standard_endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// TestRegisterAuthorizationServerMetadataRoutes_MultiTenant verifies that
// multi-tenant deployments (path in issuer) register path insertion endpoints
func TestRegisterAuthorizationServerMetadataRoutes_MultiTenant(t *testing.T) {
	// Multi-tenant issuer with path component
	config := &ServerConfig{
		Issuer: "https://auth.example.com/tenant1",
	}

	provider := mock.NewMockProvider()
	store := memory.New()
	defer store.Stop()

	server, err := NewServer(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := NewHandler(server, nil)
	mux := http.NewServeMux()

	// Register routes
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{
			name:     "oauth_path_insertion",
			path:     "/.well-known/oauth-authorization-server/tenant1",
			wantCode: http.StatusOK,
		},
		{
			name:     "oidc_path_insertion",
			path:     "/.well-known/openid-configuration/tenant1",
			wantCode: http.StatusOK,
		},
		{
			name:     "oidc_path_appending",
			path:     "/tenant1/.well-known/openid-configuration",
			wantCode: http.StatusOK,
		},
		{
			name:     "oauth_standard_backward_compat",
			path:     "/.well-known/oauth-authorization-server",
			wantCode: http.StatusOK,
		},
		{
			name:     "oidc_standard_backward_compat",
			path:     "/.well-known/openid-configuration",
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d for path %s", w.Code, tt.wantCode, tt.path)
			}

			if w.Code == http.StatusOK {
				var metadata map[string]any
				if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				// Verify issuer matches configured value
				if metadata["issuer"] != "https://auth.example.com/tenant1" {
					t.Errorf("issuer = %v, want https://auth.example.com/tenant1", metadata["issuer"])
				}

				// Verify required fields are present
				requiredFields := []string{
					"authorization_endpoint",
					"token_endpoint",
					"response_types_supported",
					"grant_types_supported",
					"code_challenge_methods_supported",
				}

				for _, field := range requiredFields {
					if _, ok := metadata[field]; !ok {
						t.Errorf("missing required field: %s", field)
					}
				}
			}
		})
	}
}

// TestRegisterAuthorizationServerMetadataRoutes_NestedPath verifies that
// deeply nested paths work correctly (e.g., /org/tenant/env)
func TestRegisterAuthorizationServerMetadataRoutes_NestedPath(t *testing.T) {
	// Multi-level tenant path
	config := &ServerConfig{
		Issuer: "https://auth.example.com/org1/tenant1/prod",
	}

	provider := mock.NewMockProvider()
	store := memory.New()
	defer store.Stop()

	server, err := NewServer(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := NewHandler(server, nil)
	mux := http.NewServeMux()

	// Register routes
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "oauth_path_insertion_nested",
			path: "/.well-known/oauth-authorization-server/org1/tenant1/prod",
		},
		{
			name: "oidc_path_insertion_nested",
			path: "/.well-known/openid-configuration/org1/tenant1/prod",
		},
		{
			name: "oidc_path_appending_nested",
			path: "/org1/tenant1/prod/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d for path %s", w.Code, http.StatusOK, tt.path)
			}

			if w.Code == http.StatusOK {
				var metadata map[string]any
				if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				expectedIssuer := "https://auth.example.com/org1/tenant1/prod"
				if metadata["issuer"] != expectedIssuer {
					t.Errorf("issuer = %v, want %s", metadata["issuer"], expectedIssuer)
				}
			}
		})
	}
}

// TestExtractIssuerPath verifies the path extraction logic
func TestExtractIssuerPath(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		wantPath string
	}{
		{
			name:     "no_path",
			issuer:   "https://auth.example.com",
			wantPath: "",
		},
		{
			name:     "root_path",
			issuer:   "https://auth.example.com/",
			wantPath: "",
		},
		{
			name:     "single_segment",
			issuer:   "https://auth.example.com/tenant1",
			wantPath: "/tenant1",
		},
		{
			name:     "multiple_segments",
			issuer:   "https://auth.example.com/org/tenant",
			wantPath: "/org/tenant",
		},
		{
			name:     "trailing_slash",
			issuer:   "https://auth.example.com/tenant1/",
			wantPath: "/tenant1",
		},
		{
			name:     "empty_issuer",
			issuer:   "",
			wantPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerConfig{
				Issuer: tt.issuer,
			}

			provider := mock.NewMockProvider()
			store := memory.New()
			defer store.Stop()

			server, err := NewServer(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(server, nil)
			gotPath := handler.extractIssuerPath()

			if gotPath != tt.wantPath {
				t.Errorf("extractIssuerPath() = %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}
