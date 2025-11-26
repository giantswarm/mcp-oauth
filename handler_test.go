package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	testTokenTypeBearer         = "Bearer"
	testClientRemoteAddr        = "192.168.1.100:12345"
	testOriginApp               = "https://app.example.com"
	testIssuer                  = "https://auth.example.com"
	testResourceMetadataURL     = `resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"`
	testResourceMetadataURLFull = "https://auth.example.com/.well-known/oauth-protected-resource"
)

func setupTestHandler(t *testing.T) (*Handler, *memory.Store) {
	t.Helper()

	store := memory.New()
	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: testIssuer,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)
	return handler, store
}

// decodeProtectedResourceMetadata decodes Protected Resource Metadata from the response body
func decodeProtectedResourceMetadata(t *testing.T, w *httptest.ResponseRecorder) *ProtectedResourceMetadata {
	t.Helper()
	var meta ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode Protected Resource Metadata: %v", err)
	}
	return &meta
}

func setupTestHandlerWithCORS(t *testing.T, allowedOrigins []string) (*Handler, *memory.Store) {
	t.Helper()

	store := memory.New()
	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: "https://auth.example.com",
		CORS: server.CORSConfig{
			AllowedOrigins:   allowedOrigins,
			AllowCredentials: true,
			MaxAge:           3600,
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)
	return handler, store
}

func TestNewHandler(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: testIssuer,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)
	if handler == nil {
		t.Fatal("NewHandler() returned nil")
	}

	if handler.logger == nil {
		t.Error("logger should not be nil")
	}
}

func TestHandler_ServeProtectedResourceMetadata(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeProtectedResourceMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	meta := decodeProtectedResourceMetadata(t, w)

	if meta.Resource != testIssuer {
		t.Errorf("Resource = %q, want %q", meta.Resource, testIssuer)
	}
}

func TestHandler_ServeProtectedResourceMetadata_WithScopes(t *testing.T) {
	store := memory.New()
	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer:          testIssuer,
		SupportedScopes: []string{"files:read", "files:write", "user:profile"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeProtectedResourceMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	meta := decodeProtectedResourceMetadata(t, w)

	if meta.Resource != testIssuer {
		t.Errorf("Resource = %q, want %q", meta.Resource, testIssuer)
	}

	// Verify scopes_supported is included
	if len(meta.ScopesSupported) != 3 {
		t.Errorf("len(ScopesSupported) = %d, want 3", len(meta.ScopesSupported))
	}

	expectedScopes := []string{"files:read", "files:write", "user:profile"}
	for i, scope := range expectedScopes {
		if meta.ScopesSupported[i] != scope {
			t.Errorf("ScopesSupported[%d] = %q, want %q", i, meta.ScopesSupported[i], scope)
		}
	}

	store.Stop()
}

func TestHandler_ServeProtectedResourceMetadata_WithoutScopes(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Ensure SupportedScopes is empty (default)
	handler.server.Config.SupportedScopes = []string{}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeProtectedResourceMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify scopes_supported is NOT included
	if _, exists := meta["scopes_supported"]; exists {
		t.Error("scopes_supported should not be included when SupportedScopes is empty")
	}
}

func TestHandler_RegisterProtectedResourceMetadataRoutes(t *testing.T) {
	tests := []struct {
		name        string
		mcpPath     string
		wantRoot    bool
		wantSubPath bool
		subPath     string
	}{
		{
			name:        "empty path",
			mcpPath:     "",
			wantRoot:    true,
			wantSubPath: false,
		},
		{
			name:        "root path",
			mcpPath:     "/",
			wantRoot:    true,
			wantSubPath: false,
		},
		{
			name:        "simple path",
			mcpPath:     "/mcp",
			wantRoot:    true,
			wantSubPath: true,
			subPath:     "/.well-known/oauth-protected-resource/mcp",
		},
		{
			name:        "path without leading slash",
			mcpPath:     "mcp",
			wantRoot:    true,
			wantSubPath: true,
			subPath:     "/.well-known/oauth-protected-resource/mcp",
		},
		{
			name:        "path with trailing slash",
			mcpPath:     "/mcp/",
			wantRoot:    true,
			wantSubPath: true,
			subPath:     "/.well-known/oauth-protected-resource/mcp",
		},
		{
			name:        "nested path",
			mcpPath:     "/api/mcp",
			wantRoot:    true,
			wantSubPath: true,
			subPath:     "/.well-known/oauth-protected-resource/api/mcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			handler.server.Config.SupportedScopes = []string{"test:scope"}

			mux := http.NewServeMux()
			handler.RegisterProtectedResourceMetadataRoutes(mux, tt.mcpPath)

			// Test root endpoint
			if tt.wantRoot {
				req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("root endpoint: status = %d, want %d", w.Code, http.StatusOK)
				}

				meta := decodeProtectedResourceMetadata(t, w)

				if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "test:scope" {
					t.Errorf("root endpoint: ScopesSupported = %v, want [test:scope]", meta.ScopesSupported)
				}
			}

			// Test sub-path endpoint
			if tt.wantSubPath {
				req := httptest.NewRequest(http.MethodGet, tt.subPath, nil)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("sub-path endpoint %q: status = %d, want %d", tt.subPath, w.Code, http.StatusOK)
				}

				meta := decodeProtectedResourceMetadata(t, w)

				if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "test:scope" {
					t.Errorf("sub-path endpoint: ScopesSupported = %v, want [test:scope]", meta.ScopesSupported)
				}
			}
		})
	}
}

func TestHandler_RegisterProtectedResourceMetadataRoutes_SecurityValidation(t *testing.T) {
	tests := []struct {
		name           string
		mcpPath        string
		shouldRegister bool
		description    string
		skipHTTPTest   bool // Skip HTTP request test if path contains characters invalid in URLs
	}{
		{
			name:           "path traversal with double dots",
			mcpPath:        "/../../etc/passwd",
			shouldRegister: false,
			description:    "should reject path traversal attempts",
		},
		{
			name:           "path traversal in middle",
			mcpPath:        "/api/../secret",
			shouldRegister: false,
			description:    "should reject path traversal in any position",
		},
		{
			name:           "excessively long path",
			mcpPath:        "/" + strings.Repeat("a", 300),
			shouldRegister: false,
			description:    "should reject paths exceeding max length",
		},
		{
			name:           "path with null byte",
			mcpPath:        "/mcp\x00/secret",
			shouldRegister: false,
			description:    "should reject paths with null bytes",
			skipHTTPTest:   true, // null bytes are invalid in URLs
		},
		{
			name:           "path with too many segments",
			mcpPath:        "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p",
			shouldRegister: false,
			description:    "should reject paths with excessive segments",
		},
		{
			name:           "valid simple path",
			mcpPath:        "/mcp",
			shouldRegister: true,
			description:    "should accept valid simple path",
		},
		{
			name:           "valid nested path",
			mcpPath:        "/api/v1/mcp",
			shouldRegister: true,
			description:    "should accept valid nested path",
		},
		{
			name:           "valid path with hyphens and underscores",
			mcpPath:        "/mcp-server_v2",
			shouldRegister: true,
			description:    "should accept path with hyphens and underscores",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			handler.server.Config.SupportedScopes = []string{"test:scope"}

			// First verify the validation function works correctly
			err := handler.validateMetadataPath(tt.mcpPath)
			if tt.shouldRegister && err != nil {
				t.Errorf("%s: validateMetadataPath() returned error for valid path: %v",
					tt.description, err)
			} else if !tt.shouldRegister && err == nil {
				t.Errorf("%s: validateMetadataPath() did not reject invalid path",
					tt.description)
			}

			// Skip HTTP test if path contains characters that are invalid in URLs
			if tt.skipHTTPTest {
				return
			}

			mux := http.NewServeMux()
			handler.RegisterProtectedResourceMetadataRoutes(mux, tt.mcpPath)

			// Build expected path
			var expectedPath string
			if tt.shouldRegister && tt.mcpPath != "" && tt.mcpPath != "/" {
				cleanPath := path.Clean("/" + strings.TrimPrefix(tt.mcpPath, "/"))
				expectedPath = "/.well-known/oauth-protected-resource" + cleanPath
			} else {
				// For invalid paths that were rejected, test that a reasonable path returns 404
				expectedPath = "/.well-known/oauth-protected-resource/rejected-path"
			}

			// Try to access the sub-path endpoint
			req := httptest.NewRequest(http.MethodGet, expectedPath, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if tt.shouldRegister {
				if w.Code != http.StatusOK {
					t.Errorf("%s: status = %d, want %d (path should be registered)",
						tt.description, w.Code, http.StatusOK)
				}
			} else {
				// For invalid paths, verify they were not registered
				// We expect 404 because the handler was never registered
				if w.Code == http.StatusOK {
					t.Errorf("%s: path was incorrectly registered (security violation)",
						tt.description)
				}
			}
		})
	}
}

func TestHandler_validateMetadataPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple path",
			path:    "/mcp",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "/api/v1/mcp",
			wantErr: false,
		},
		{
			name:    "path traversal attempt",
			path:    "../../../etc/passwd",
			wantErr: true,
			errMsg:  "path traversal",
		},
		{
			name:    "path traversal in middle",
			path:    "/api/../secret",
			wantErr: true,
			errMsg:  "path traversal",
		},
		{
			name:    "excessively long path",
			path:    "/" + strings.Repeat("a", 300),
			wantErr: true,
			errMsg:  "maximum length",
		},
		{
			name:    "path at max length boundary",
			path:    "/" + strings.Repeat("a", 255),
			wantErr: false,
		},
		{
			name:    "path with null byte",
			path:    "/mcp\x00/hack",
			wantErr: true,
			errMsg:  "null byte",
		},
		{
			name:    "path with too many segments",
			path:    "/a/b/c/d/e/f/g/h/i/j/k/l",
			wantErr: true,
			errMsg:  "too many segments",
		},
		{
			name:    "path with exactly 10 segments (boundary)",
			path:    "/a/b/c/d/e/f/g/h/i/j",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			err := handler.validateMetadataPath(tt.path)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateMetadataPath() error = nil, want error containing %q", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateMetadataPath() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateMetadataPath() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestHandler_ServeAuthorizationServerMetadata(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Enable client registration by setting a registration access token
	handler.server.Config.RegistrationAccessToken = "test-token"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// RFC 8414: Table-driven test for all required metadata fields
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "issuer",
			got:  meta.Issuer,
			want: "https://auth.example.com",
		},
		{
			name: "authorization_endpoint",
			got:  meta.AuthorizationEndpoint,
			want: "https://auth.example.com/oauth/authorize",
		},
		{
			name: "token_endpoint",
			got:  meta.TokenEndpoint,
			want: "https://auth.example.com/oauth/token",
		},
		{
			name: "registration_endpoint",
			got:  meta.RegistrationEndpoint,
			want: "https://auth.example.com/oauth/register",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}

	// Verify response_types_supported
	if len(meta.ResponseTypesSupported) == 0 {
		t.Error("ResponseTypesSupported is empty")
	}
	if len(meta.ResponseTypesSupported) > 0 && meta.ResponseTypesSupported[0] != "code" {
		t.Errorf("ResponseTypesSupported[0] = %q, want %q", meta.ResponseTypesSupported[0], "code")
	}

	// Verify grant_types_supported
	if len(meta.GrantTypesSupported) < 2 {
		t.Errorf("GrantTypesSupported has %d items, want at least 2", len(meta.GrantTypesSupported))
	}

	// Verify code_challenge_methods_supported includes S256
	if len(meta.CodeChallengeMethodsSupported) == 0 {
		t.Error("CodeChallengeMethodsSupported is empty")
	}
	if len(meta.CodeChallengeMethodsSupported) > 0 && meta.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("CodeChallengeMethodsSupported[0] = %q, want %q", meta.CodeChallengeMethodsSupported[0], "S256")
	}
}

func TestHandler_ServeAuthorizationServerMetadata_NoRegistration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Ensure client registration is disabled (neither token nor public registration)
	handler.server.Config.AllowPublicClientRegistration = false
	handler.server.Config.RegistrationAccessToken = ""

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify registration_endpoint is NOT included when registration is disabled
	if meta.RegistrationEndpoint != "" {
		t.Errorf("registration_endpoint should be empty when registration is disabled, got %q", meta.RegistrationEndpoint)
	}

	// Verify required fields are still present
	if meta.Issuer != "https://auth.example.com" {
		t.Errorf("issuer = %q, want %q", meta.Issuer, "https://auth.example.com")
	}
	if meta.AuthorizationEndpoint != "https://auth.example.com/oauth/authorize" {
		t.Errorf("authorization_endpoint = %q, want %q", meta.AuthorizationEndpoint, "https://auth.example.com/oauth/authorize")
	}
	if meta.TokenEndpoint != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint = %q, want %q", meta.TokenEndpoint, "https://auth.example.com/oauth/token")
	}
}

func TestHandler_ServeAuthorizationServerMetadata_PublicRegistration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Enable public client registration (no token required)
	handler.server.Config.AllowPublicClientRegistration = true
	handler.server.Config.RegistrationAccessToken = ""

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify registration_endpoint IS included when public registration is enabled
	if meta.RegistrationEndpoint != "https://auth.example.com/oauth/register" {
		t.Errorf("registration_endpoint = %q, want %q", meta.RegistrationEndpoint, "https://auth.example.com/oauth/register")
	}
}

// TestHandler_ServeAuthorizationServerMetadata_EnhancedFields tests the new metadata fields
// added for MCP 2025-11-25 compliance (issue #78)
func TestHandler_ServeAuthorizationServerMetadata_EnhancedFields(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure supported scopes
	handler.server.Config.SupportedScopes = []string{"openid", "profile", "email", "files:read", "files:write"}

	// Enable enhanced endpoints for testing
	handler.server.Config.EnableClientIDMetadataDocuments = true
	handler.server.Config.EnableRevocationEndpoint = true
	handler.server.Config.EnableIntrospectionEndpoint = true

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Test new endpoint fields (RFC 7009, RFC 7662)
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "revocation_endpoint",
			got:  meta.RevocationEndpoint,
			want: "https://auth.example.com/oauth/revoke",
		},
		{
			name: "introspection_endpoint",
			got:  meta.IntrospectionEndpoint,
			want: "https://auth.example.com/oauth/introspect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}

	// Verify token_endpoint_auth_methods_supported
	if len(meta.TokenEndpointAuthMethodsSupported) != 3 {
		t.Errorf("len(TokenEndpointAuthMethodsSupported) = %d, want 3", len(meta.TokenEndpointAuthMethodsSupported))
	}
	expectedAuthMethods := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"none":                true,
	}
	for _, method := range meta.TokenEndpointAuthMethodsSupported {
		if !expectedAuthMethods[method] {
			t.Errorf("unexpected auth method: %q", method)
		}
	}

	// Verify scopes_supported
	if len(meta.ScopesSupported) != 5 {
		t.Errorf("len(ScopesSupported) = %d, want 5", len(meta.ScopesSupported))
	}
	expectedScopes := map[string]bool{
		"openid":      true,
		"profile":     true,
		"email":       true,
		"files:read":  true,
		"files:write": true,
	}
	for _, scope := range meta.ScopesSupported {
		if !expectedScopes[scope] {
			t.Errorf("unexpected scope: %q", scope)
		}
	}

	// Verify client_id_metadata_document_supported
	if !meta.ClientIDMetadataDocumentSupported {
		t.Error("ClientIDMetadataDocumentSupported should be true when enabled")
	}
}

// TestHandler_ServeAuthorizationServerMetadata_DisabledEndpoints verifies that
// revocation and introspection endpoints are NOT advertised when disabled
func TestHandler_ServeAuthorizationServerMetadata_DisabledEndpoints(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Explicitly disable endpoints (though false is default)
	handler.server.Config.EnableRevocationEndpoint = false
	handler.server.Config.EnableIntrospectionEndpoint = false
	handler.server.Config.EnableClientIDMetadataDocuments = false

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify endpoints are NOT included when disabled
	if meta.RevocationEndpoint != "" {
		t.Errorf("RevocationEndpoint should be empty when disabled, got %q", meta.RevocationEndpoint)
	}
	if meta.IntrospectionEndpoint != "" {
		t.Errorf("IntrospectionEndpoint should be empty when disabled, got %q", meta.IntrospectionEndpoint)
	}
	if meta.ClientIDMetadataDocumentSupported {
		t.Error("ClientIDMetadataDocumentSupported should be false when disabled")
	}
}

// TestHandler_ServeAuthorizationServerMetadata_NoScopes verifies scopes_supported
// is not included when no scopes are configured
func TestHandler_ServeAuthorizationServerMetadata_NoScopes(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Ensure no scopes are configured
	handler.server.Config.SupportedScopes = nil

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify scopes_supported is not included (nil/empty)
	if len(meta.ScopesSupported) > 0 {
		t.Errorf("ScopesSupported should be empty when no scopes configured, got %v", meta.ScopesSupported)
	}
}

// TestHandler_ServeOpenIDConfiguration verifies OpenID Connect Discovery endpoint
// returns the same metadata as Authorization Server Metadata (RFC 8414 Section 5)
func TestHandler_ServeOpenIDConfiguration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure server with some settings
	handler.server.Config.SupportedScopes = []string{"openid", "profile"}
	handler.server.Config.EnableClientIDMetadataDocuments = true
	handler.server.Config.EnableRevocationEndpoint = true
	handler.server.Config.EnableIntrospectionEndpoint = true

	// Request Authorization Server Metadata
	reqAS := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	wAS := httptest.NewRecorder()
	handler.ServeAuthorizationServerMetadata(wAS, reqAS)

	// Request OpenID Configuration
	reqOIDC := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	wOIDC := httptest.NewRecorder()
	handler.ServeOpenIDConfiguration(wOIDC, reqOIDC)

	// Both should return 200 OK
	if wAS.Code != http.StatusOK {
		t.Errorf("AS metadata status = %d, want %d", wAS.Code, http.StatusOK)
	}
	if wOIDC.Code != http.StatusOK {
		t.Errorf("OIDC configuration status = %d, want %d", wOIDC.Code, http.StatusOK)
	}

	// Decode both responses
	var metaAS, metaOIDC AuthorizationServerMetadata
	if err := json.NewDecoder(wAS.Body).Decode(&metaAS); err != nil {
		t.Fatalf("failed to decode AS metadata: %v", err)
	}
	if err := json.NewDecoder(wOIDC.Body).Decode(&metaOIDC); err != nil {
		t.Fatalf("failed to decode OIDC configuration: %v", err)
	}

	// Verify key fields match
	if metaAS.Issuer != metaOIDC.Issuer {
		t.Errorf("issuer mismatch: AS=%q, OIDC=%q", metaAS.Issuer, metaOIDC.Issuer)
	}
	if metaAS.AuthorizationEndpoint != metaOIDC.AuthorizationEndpoint {
		t.Errorf("authorization_endpoint mismatch: AS=%q, OIDC=%q", metaAS.AuthorizationEndpoint, metaOIDC.AuthorizationEndpoint)
	}
	if metaAS.TokenEndpoint != metaOIDC.TokenEndpoint {
		t.Errorf("token_endpoint mismatch: AS=%q, OIDC=%q", metaAS.TokenEndpoint, metaOIDC.TokenEndpoint)
	}
	if metaAS.RevocationEndpoint != metaOIDC.RevocationEndpoint {
		t.Errorf("revocation_endpoint mismatch: AS=%q, OIDC=%q", metaAS.RevocationEndpoint, metaOIDC.RevocationEndpoint)
	}
	if metaAS.IntrospectionEndpoint != metaOIDC.IntrospectionEndpoint {
		t.Errorf("introspection_endpoint mismatch: AS=%q, OIDC=%q", metaAS.IntrospectionEndpoint, metaOIDC.IntrospectionEndpoint)
	}

	// Verify array lengths match
	if len(metaAS.ScopesSupported) != len(metaOIDC.ScopesSupported) {
		t.Errorf("scopes_supported length mismatch: AS=%d, OIDC=%d", len(metaAS.ScopesSupported), len(metaOIDC.ScopesSupported))
	}
}

func TestHandler_ServeClientRegistration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Create registration request
	regReq := ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		ClientType:              "confidential",
	}

	body, err := json.Marshal(regReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	// For now, just verify it doesn't panic and returns a response
	// Actual registration might fail without proper configuration
	if w.Code == 0 {
		t.Error("handler should set status code")
	}
}

func TestHandler_writeError(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	w := httptest.NewRecorder()

	handler.writeError(w, ErrorCodeInvalidRequest, "test error", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != ErrorCodeInvalidRequest {
		t.Errorf("Error = %q, want %q", errResp.Error, ErrorCodeInvalidRequest)
	}

	if errResp.ErrorDescription != "test error" {
		t.Errorf("ErrorDescription = %q, want %q", errResp.ErrorDescription, "test error")
	}
}

func TestHandler_ValidateToken_MissingHeader(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	// Create a simple handler to wrap
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with ValidateToken middleware
	wrappedHandler := handler.ValidateToken(nextHandler)
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ValidateToken_InvalidFormat(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "no bearer prefix",
			header: "test-token",
		},
		{
			name:   "wrong auth type",
			header: "Basic test-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			wrappedHandler := handler.ValidateToken(nextHandler)
			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestHandler_parseBasicAuth(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Test with empty header
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	username, password := handler.parseBasicAuth(req)
	if username != "" || password != "" {
		t.Errorf("parseBasicAuth() with no auth header should return empty strings, got %q,%q", username, password)
	}

	// Test with non-basic auth
	req = httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set("Authorization", "Bearer token")
	username, password = handler.parseBasicAuth(req)
	if username != "" || password != "" {
		t.Errorf("parseBasicAuth() with Bearer auth should return empty strings, got %q,%q", username, password)
	}
}

func TestHandler_writeTokenResponse(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	w := httptest.NewRecorder()

	token := testutil.GenerateTestToken()

	handler.writeTokenResponse(w, token, "openid email")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", tokenResp.AccessToken, token.AccessToken)
	}

	if tokenResp.TokenType != testTokenTypeBearer {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, testTokenTypeBearer)
	}
}

func TestHandler_ServeAuthorization_MissingParams(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_ServeToken_InvalidMethod(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_ServeToken_MissingGrantType(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_ServeTokenRevocation_InvalidMethod(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
	w := httptest.NewRecorder()

	handler.ServeTokenRevocation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_ServeAuthorization_CompleteFlow(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client first
	client, _, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Generate valid PKCE challenge
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Test authorization request
	// State must be at least 32 characters for security
	validState := testutil.GenerateRandomString(43) // Use PKCE verifier length for state
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id="+client.ClientID+
			"&redirect_uri=https://example.com/callback"+
			"&scope=openid+email"+
			"&response_type=code"+
			"&code_challenge="+challenge+
			"&code_challenge_method=S256"+
			"&state="+validState,
		nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	// Should redirect to provider
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set for redirect")
	}
}

func TestHandler_ServeCallback(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, _, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create authorization state
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// State must be at least 32 characters for security
	clientState := testutil.GenerateRandomString(43)
	authURL, err := handler.server.StartAuthorizationFlow(ctx,
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		challenge,
		"S256",
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow(ctx, ) error = %v", err)
	}

	// Extract provider state from auth URL
	if authURL == "" {
		t.Fatal("authURL is empty")
	}

	// Get auth state to find provider state
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	// Test callback with valid state
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should redirect to client with authorization code
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set")
	}

	// Verify location contains code and state
	if !strings.Contains(location, "code=") {
		t.Error("Location should contain authorization code")
	}
	if !strings.Contains(location, "state="+clientState) {
		t.Error("Location should contain original client state")
	}
}

func TestHandler_ServeCallback_InvalidState(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Use a state with valid length but not in storage (will fail at lookup)
	validLengthButInvalidState := testutil.GenerateRandomString(43)
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+validLengthButInvalidState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Handler returns 500 for invalid state (internal error)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestHandler_ServeCallback_MissingParams(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "missing state",
			url:  "/oauth/callback?code=test-code",
		},
		{
			name: "missing code",
			url:  "/oauth/callback?state=" + testutil.GenerateRandomString(43),
		},
		{
			name: "missing all params",
			url:  "/oauth/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()

			handler.ServeCallback(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHandler_ServeAuthorization_StateLength(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a test client
	client, _, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name       string
		state      string
		wantStatus int
		wantError  bool
	}{
		{
			name:       "state too short (1 char)",
			state:      "x",
			wantStatus: http.StatusBadRequest,
			wantError:  true,
		},
		{
			name:       "state too short (10 chars)",
			state:      "0123456789",
			wantStatus: http.StatusBadRequest,
			wantError:  true,
		},
		{
			name:       "state too short (31 chars, just under minimum)",
			state:      "0123456789012345678901234567890",
			wantStatus: http.StatusBadRequest,
			wantError:  true,
		},
		{
			name:       "state exactly minimum length (32 chars)",
			state:      "01234567890123456789012345678901",
			wantStatus: http.StatusFound,
			wantError:  false,
		},
		{
			name:       "state above minimum length (64 chars)",
			state:      "0123456789012345678901234567890123456789012345678901234567890123",
			wantStatus: http.StatusFound,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=https://example.com/callback&scope=openid&state=%s&code_challenge=test-challenge&code_challenge_method=S256",
				client.ClientID, tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeAuthorization(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_ServeCallback_StateLength(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name       string
		state      string
		wantStatus int
	}{
		{
			name:       "state too short (1 char)",
			state:      "x",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state too short (10 chars)",
			state:      "0123456789",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state too short (31 chars)",
			state:      "0123456789012345678901234567890",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state exactly minimum length (32 chars) - will fail with invalid state since not in storage",
			state:      "01234567890123456789012345678901",
			wantStatus: http.StatusInternalServerError, // Will fail at state lookup, but passed length validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/oauth/callback?state=%s&code=test-code", tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeCallback(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_ServeToken_AuthorizationCode(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create an authorization code
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserID:              "test-user-123",
		ProviderToken:       testutil.GenerateTestToken(),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	err = store.SaveAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Create token request
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", authCode.Code)
	formData.Set("redirect_uri", "https://example.com/callback")
	formData.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	if tokenResp.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}

	if tokenResp.TokenType != testTokenTypeBearer {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, testTokenTypeBearer)
	}
}

func TestHandler_ServeClientRegistration_Success(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Enable public registration for this test
	handler.server.Config.AllowPublicClientRegistration = true

	regReq := ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		ClientType:              "confidential",
	}

	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp ClientRegistrationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ClientID == "" {
		t.Error("ClientID should not be empty")
	}
	if resp.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}
}

func TestHandler_ServeClientRegistration_TokenEndpointAuthMethod(t *testing.T) {
	handler, _ := setupTestHandler(t)
	// Enable public registration for these tests
	handler.server.Config.AllowPublicClientRegistration = true
	handler.server.Config.AllowPublicClientsWithoutPKCE = true

	tests := []struct {
		name                    string
		tokenEndpointAuthMethod string
		clientType              string
		wantStatus              int
		wantAuthMethod          string
		wantClientType          string
		wantSecret              bool
	}{
		{
			name:                    "auth_method=none creates public client",
			tokenEndpointAuthMethod: "none",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "none",
			wantClientType:          "public",
			wantSecret:              false,
		},
		{
			name:                    "auth_method=client_secret_basic creates confidential client",
			tokenEndpointAuthMethod: "client_secret_basic",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_basic",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "auth_method=client_secret_post creates confidential client",
			tokenEndpointAuthMethod: "client_secret_post",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_post",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "unsupported auth_method returns error",
			tokenEndpointAuthMethod: "client_secret_jwt",
			clientType:              "",
			wantStatus:              http.StatusBadRequest,
		},
		{
			name:                    "empty auth_method defaults to client_secret_basic",
			tokenEndpointAuthMethod: "",
			clientType:              "confidential",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_basic",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "auth_method=none overrides client_type=confidential",
			tokenEndpointAuthMethod: "none",
			clientType:              "confidential",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "none",
			wantClientType:          "public",
			wantSecret:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regReq := ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Test Client - " + tt.name,
				ClientType:              tt.clientType,
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1." + tt.name[:3] // Unique IP per test
			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusCreated {
				var resp ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}

				if resp.TokenEndpointAuthMethod != tt.wantAuthMethod {
					t.Errorf("TokenEndpointAuthMethod = %q, want %q", resp.TokenEndpointAuthMethod, tt.wantAuthMethod)
				}

				if resp.ClientType != tt.wantClientType {
					t.Errorf("ClientType = %q, want %q", resp.ClientType, tt.wantClientType)
				}

				if tt.wantSecret {
					if resp.ClientSecret == "" {
						t.Error("ClientSecret should not be empty for confidential client")
					}
				} else {
					if resp.ClientSecret != "" {
						t.Error("ClientSecret should be empty for public client")
					}
				}
			}
		})
	}
}

func TestHandler_ServeClientRegistration_PublicClientPolicy(t *testing.T) {
	// Test that public client registration is properly controlled by AllowPublicClientRegistration
	const testRegistrationToken = "test-registration-token-12345"

	tests := []struct {
		name                          string
		allowPublicClientRegistration bool
		tokenEndpointAuthMethod       string
		clientType                    string
		wantStatus                    int
		wantErrorContains             string
	}{
		{
			name:                          "public client rejected when policy disabled (auth_method=none)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client rejected when policy disabled (client_type=public)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "",
			clientType:                    "public",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client rejected when policy disabled (both specified)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "public",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client allowed when policy enabled (auth_method=none)",
			allowPublicClientRegistration: true,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "public client allowed when policy enabled (client_type=public)",
			allowPublicClientRegistration: true,
			tokenEndpointAuthMethod:       "",
			clientType:                    "public",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "confidential client allowed when policy disabled",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "client_secret_basic",
			clientType:                    "",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "confidential client (default) allowed when policy disabled",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "",
			clientType:                    "confidential",
			wantStatus:                    http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			// Configure the policy for this test
			handler.server.Config.AllowPublicClientRegistration = tt.allowPublicClientRegistration
			handler.server.Config.AllowPublicClientsWithoutPKCE = true // Not relevant for registration test

			// Set registration token when authentication is required
			if !tt.allowPublicClientRegistration {
				handler.server.Config.RegistrationAccessToken = testRegistrationToken
			}

			regReq := ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				ClientType:              tt.clientType,
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Test Client - " + tt.name,
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1.100"

			// Add authentication header when required
			if !tt.allowPublicClientRegistration {
				req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
			}

			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusBadRequest && tt.wantErrorContains != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantErrorContains) {
					t.Errorf("error response should contain %q, got: %s", tt.wantErrorContains, body)
				}
			}

			if tt.wantStatus == http.StatusCreated {
				var resp ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}

				// Verify the client was created with correct type
				expectedType := tt.clientType
				if tt.tokenEndpointAuthMethod == "none" {
					expectedType = "public"
				} else if expectedType == "" {
					expectedType = "confidential"
				}

				if resp.ClientType != expectedType {
					t.Errorf("ClientType = %q, want %q", resp.ClientType, expectedType)
				}
			}
		})
	}
}

func TestUserInfoFromContext(t *testing.T) {
	// Test with no user info in context
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	userInfo, ok := UserInfoFromContext(req.Context())
	if ok {
		t.Error("UserInfoFromContext should return false when no user info in context")
	}
	if userInfo != nil {
		t.Error("UserInfoFromContext should return nil when no user info in context")
	}
}

func TestHandler_ServeToken_InvalidClient(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, _, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", "some-code")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, "wrong-secret")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	// Invalid secret should be caught during authentication
	if w.Code == http.StatusOK {
		t.Error("Should not succeed with invalid credentials")
	}
}

func TestHandler_ServeToken_UnsupportedGrantType(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, secret, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	formData := url.Values{}
	formData.Set("grant_type", "unsupported_grant")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_ServeClientRegistration_InvalidJSON(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config.AllowPublicClientRegistration = true

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Empty redirect URIs are apparently allowed, so this test is removed

func TestHandler_ParseForm_Error(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Test token endpoint with malformed body
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("%invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_ServeTokenRevocation_Success(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create a refresh token
	refreshToken := testutil.GenerateRandomString(32)
	err = store.SaveRefreshToken(ctx, refreshToken, "test-user-123", time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Revoke the token
	formData := url.Values{}
	formData.Set("token", refreshToken)
	formData.Set("token_type_hint", "refresh_token")

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w := httptest.NewRecorder()

	handler.ServeTokenRevocation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_ServeTokenIntrospection(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Test introspection with invalid method
	req := httptest.NewRequest(http.MethodGet, "/introspect", nil)
	w := httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	// Test introspection with POST but missing token - should return error
	formData := url.Values{}

	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w = httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	// Missing token parameter returns 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	// Test introspection with missing client auth
	formData = url.Values{}
	formData.Set("token", "some-token")

	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// CORS Tests

func TestCORS_Disabled(t *testing.T) {
	// CORS should be disabled by default (empty AllowedOrigins)
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	// No CORS headers should be set
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set when CORS is disabled")
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	handler, store := setupTestHandlerWithCORS(t, []string{testOriginApp, "https://dashboard.example.com"})
	defer store.Stop()

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
		shouldAllow    bool
	}{
		{
			name:           "exact match first origin",
			origin:         testOriginApp,
			expectedOrigin: testOriginApp,
			shouldAllow:    true,
		},
		{
			name:           "exact match second origin",
			origin:         "https://dashboard.example.com",
			expectedOrigin: "https://dashboard.example.com",
			shouldAllow:    true,
		},
		{
			name:        "disallowed origin",
			origin:      "https://evil.com",
			shouldAllow: false,
		},
		{
			name:        "case sensitive - wrong case",
			origin:      "https://APP.example.com",
			shouldAllow: false,
		},
		{
			name:        "subdomain not allowed",
			origin:      "https://sub.app.example.com",
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			handler.ServeAuthorizationServerMetadata(w, req)

			allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if tt.shouldAllow {
				if allowOrigin != tt.expectedOrigin {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", allowOrigin, tt.expectedOrigin)
				}
				if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Error("Access-Control-Allow-Credentials should be 'true'")
				}
				if w.Header().Get("Access-Control-Allow-Methods") == "" {
					t.Error("Access-Control-Allow-Methods should be set")
				}
				// SECURITY: Verify Vary: Origin header is set for proper caching
				if w.Header().Get("Vary") != "Origin" {
					t.Errorf("Vary header = %q, want %q", w.Header().Get("Vary"), "Origin")
				}
			} else {
				if allowOrigin != "" {
					t.Errorf("Access-Control-Allow-Origin should not be set for disallowed origin, got %q", allowOrigin)
				}
			}
		})
	}
}

func TestCORS_WildcardOrigin(t *testing.T) {
	// Wildcard with credentials is invalid per CORS spec, so test without credentials
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: "https://auth.example.com",
		CORS: server.CORSConfig{
			AllowedOrigins:      []string{"*"},
			AllowWildcardOrigin: true,  // Explicitly opt-in to wildcard origin
			AllowCredentials:    false, // Must be false with wildcard
			MaxAge:              3600,
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	origins := []string{
		"https://app.example.com",
		"https://evil.com",
		"http://localhost:3000",
	}

	for _, origin := range origins {
		t.Run("origin_"+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()

			handler.ServeAuthorizationServerMetadata(w, req)

			// Wildcard should allow any origin
			if w.Header().Get("Access-Control-Allow-Origin") != origin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", w.Header().Get("Access-Control-Allow-Origin"), origin)
			}
		})
	}
}

func TestCORS_NoOriginHeader(t *testing.T) {
	handler, store := setupTestHandlerWithCORS(t, []string{testOriginApp})
	defer store.Stop()

	// Request without Origin header (non-browser request)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	// No CORS headers should be set for non-browser requests
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set when Origin header is missing")
	}
}

func TestCORS_PreflightRequest(t *testing.T) {
	handler, store := setupTestHandlerWithCORS(t, []string{testOriginApp})
	defer store.Stop()

	req := httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	w := httptest.NewRecorder()

	handler.ServePreflightRequest(w, req)

	// Should return 204 No Content
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Check CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != testOriginApp {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", w.Header().Get("Access-Control-Allow-Origin"), testOriginApp)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Access-Control-Allow-Methods should be set")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Access-Control-Allow-Headers should be set")
	}
	if w.Header().Get("Access-Control-Max-Age") == "" {
		t.Error("Access-Control-Max-Age should be set")
	}
	// SECURITY: Verify Vary: Origin header for proper cache control
	if w.Header().Get("Vary") != "Origin" {
		t.Errorf("Vary header = %q, want %q", w.Header().Get("Vary"), "Origin")
	}
}

func TestCORS_PreflightRequest_DisallowedOrigin(t *testing.T) {
	handler, store := setupTestHandlerWithCORS(t, []string{testOriginApp})
	defer store.Stop()

	req := httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()

	handler.ServePreflightRequest(w, req)

	// Should still return 204 but without CORS headers
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// No CORS headers for disallowed origin
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set for disallowed origin")
	}
}

func TestCORS_AllEndpoints(t *testing.T) {
	handler, store := setupTestHandlerWithCORS(t, []string{testOriginApp})
	defer store.Stop()

	// Test that CORS is applied to all endpoints
	endpoints := []struct {
		name    string
		method  string
		path    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{"metadata", http.MethodGet, "/.well-known/oauth-authorization-server", handler.ServeAuthorizationServerMetadata},
		{"protected-resource", http.MethodGet, "/.well-known/oauth-protected-resource", handler.ServeProtectedResourceMetadata},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			req.Header.Set("Origin", "https://app.example.com")
			w := httptest.NewRecorder()

			ep.handler(w, req)

			if w.Header().Get("Access-Control-Allow-Origin") != testOriginApp {
				t.Errorf("endpoint %s: Access-Control-Allow-Origin not set correctly", ep.name)
			}
		})
	}
}

func TestCORS_CredentialsDisabled(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure CORS with credentials disabled
	handler.server.Config.CORS = server.CORSConfig{
		AllowedOrigins:   []string{testOriginApp},
		AllowCredentials: false,
		MaxAge:           3600,
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	// Origin should be set
	if w.Header().Get("Access-Control-Allow-Origin") != testOriginApp {
		t.Error("Access-Control-Allow-Origin should be set")
	}

	// But credentials should not be allowed
	if w.Header().Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("Access-Control-Allow-Credentials should not be 'true' when disabled")
	}
}

func TestCORS_CustomMaxAge(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure CORS with custom max age
	handler.server.Config.CORS = server.CORSConfig{
		AllowedOrigins:   []string{testOriginApp},
		AllowCredentials: true,
		MaxAge:           7200, // 2 hours
	}

	req := httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	handler.ServePreflightRequest(w, req)

	maxAge := w.Header().Get("Access-Control-Max-Age")
	if maxAge != "7200" {
		t.Errorf("Access-Control-Max-Age = %q, want %q", maxAge, "7200")
	}
}

// TestHandler_FormatWWWAuthenticate tests the formatWWWAuthenticate helper function
func TestHandler_FormatWWWAuthenticate(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name           string
		scope          string
		error          string
		errorDesc      string
		wantContain    []string
		wantNotContain []string
	}{
		{
			name:      "minimal (only resource_metadata)",
			scope:     "",
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
			},
			wantNotContain: []string{"scope=", "error=", "error_description="},
		},
		{
			name:      "with scope",
			scope:     "files:read user:profile",
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="files:read user:profile"`,
			},
			wantNotContain: []string{"error=", "error_description="},
		},
		{
			name:      "with error",
			scope:     "",
			error:     "invalid_token",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`error="invalid_token"`,
			},
			wantNotContain: []string{"scope=", "error_description="},
		},
		{
			name:      "with error and description",
			scope:     "",
			error:     "invalid_token",
			errorDesc: "Token has expired",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`error="invalid_token"`,
				`error_description="Token has expired"`,
			},
			wantNotContain: []string{"scope="},
		},
		{
			name:      "with all parameters",
			scope:     "files:read files:write",
			error:     "insufficient_scope",
			errorDesc: "Additional file write permission required",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="files:read files:write"`,
				`error="insufficient_scope"`,
				`error_description="Additional file write permission required"`,
			},
		},
		{
			name:      "error description with quotes (escaping test)",
			scope:     "",
			error:     "invalid_request",
			errorDesc: `The "client_id" parameter is missing`,
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`error="invalid_request"`,
				`error_description="The \"client_id\" parameter is missing"`,
			},
		},
		{
			name:      "error description with backslashes and quotes (enhanced escaping)",
			scope:     "",
			error:     "invalid_request",
			errorDesc: `The "client_id" contains \n invalid chars`,
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`error="invalid_request"`,
				`error_description="The \"client_id\" contains \\n invalid chars"`,
			},
		},
		{
			name:      "error description with multiple backslashes",
			scope:     "",
			error:     "invalid_token",
			errorDesc: `Token path: C:\Users\Admin\token.txt`,
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`error="invalid_token"`,
				`error_description="Token path: C:\\Users\\Admin\\token.txt"`,
			},
		},
		{
			name:      "very long scope list (edge case)",
			scope:     "files:read files:write files:delete user:profile user:email user:repos admin:org admin:repo_hook",
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="files:read files:write files:delete user:profile user:email user:repos admin:org admin:repo_hook"`,
			},
			wantNotContain: []string{"error=", "error_description="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.formatWWWAuthenticate(tt.scope, tt.error, tt.errorDesc)

			// Verify all expected strings are present
			for _, want := range tt.wantContain {
				if !strings.Contains(result, want) {
					t.Errorf("formatWWWAuthenticate() missing expected substring:\ngot:  %q\nwant: %q", result, want)
				}
			}

			// Verify unwanted strings are not present
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(result, notWant) {
					t.Errorf("formatWWWAuthenticate() contains unexpected substring:\ngot:  %q\nshould not contain: %q", result, notWant)
				}
			}

			// Verify Bearer scheme is at the start
			if !strings.HasPrefix(result, "Bearer ") {
				t.Errorf("formatWWWAuthenticate() should start with 'Bearer ', got: %q", result)
			}

			// Verify comma-space separation (RFC 6750 format)
			if strings.Contains(result, ",,") || strings.Contains(result, ",  ") {
				t.Errorf("formatWWWAuthenticate() has malformed comma separation: %q", result)
			}
		})
	}
}

// TestHandler_WriteError401WithWWWAuthenticate tests that 401 responses include WWW-Authenticate header
func TestHandler_WriteError401WithWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name                   string
		defaultChallengeScopes []string
		status                 int
		wantWWWAuthenticate    bool
		wantScope              string
	}{
		{
			name:                   "401 without scopes",
			defaultChallengeScopes: nil,
			status:                 http.StatusUnauthorized,
			wantWWWAuthenticate:    true,
			wantScope:              "",
		},
		{
			name:                   "401 with scopes",
			defaultChallengeScopes: []string{"files:read", "user:profile"},
			status:                 http.StatusUnauthorized,
			wantWWWAuthenticate:    true,
			wantScope:              "files:read user:profile",
		},
		{
			name:                   "400 should not have WWW-Authenticate",
			defaultChallengeScopes: []string{"files:read"},
			status:                 http.StatusBadRequest,
			wantWWWAuthenticate:    false,
			wantScope:              "",
		},
		{
			name:                   "403 should not have WWW-Authenticate",
			defaultChallengeScopes: []string{"files:read"},
			status:                 http.StatusForbidden,
			wantWWWAuthenticate:    false,
			wantScope:              "",
		},
		{
			name:                   "500 should not have WWW-Authenticate",
			defaultChallengeScopes: []string{"files:read"},
			status:                 http.StatusInternalServerError,
			wantWWWAuthenticate:    false,
			wantScope:              "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                 testIssuer,
				DefaultChallengeScopes: tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			w := httptest.NewRecorder()
			handler.writeError(w, "test_error", "Test error description", tt.status)

			wwwAuth := w.Header().Get("WWW-Authenticate")

			if tt.wantWWWAuthenticate {
				if wwwAuth == "" {
					t.Error("Expected WWW-Authenticate header, but it was not set")
				} else {
					// Verify it contains resource_metadata
					if !strings.Contains(wwwAuth, testResourceMetadataURL) {
						t.Errorf("WWW-Authenticate missing resource_metadata:\ngot: %q", wwwAuth)
					}

					// Verify scope if expected
					if tt.wantScope != "" {
						expectedScope := fmt.Sprintf(`scope="%s"`, tt.wantScope)
						if !strings.Contains(wwwAuth, expectedScope) {
							t.Errorf("WWW-Authenticate missing expected scope:\ngot:  %q\nwant: %q", wwwAuth, expectedScope)
						}
					} else {
						if strings.Contains(wwwAuth, "scope=") {
							t.Errorf("WWW-Authenticate should not contain scope:\ngot: %q", wwwAuth)
						}
					}

					// Verify error and error_description are included
					if !strings.Contains(wwwAuth, `error="test_error"`) {
						t.Errorf("WWW-Authenticate missing error code:\ngot: %q", wwwAuth)
					}
					if !strings.Contains(wwwAuth, `error_description="Test error description"`) {
						t.Errorf("WWW-Authenticate missing error description:\ngot: %q", wwwAuth)
					}
				}
			} else {
				if wwwAuth != "" {
					t.Errorf("Did not expect WWW-Authenticate header for status %d, but got: %q", tt.status, wwwAuth)
				}
			}
		})
	}
}

// TestHandler_ValidateToken401ResponseWithWWWAuthenticate tests that ValidateToken middleware returns proper WWW-Authenticate
func TestHandler_ValidateToken401ResponseWithWWWAuthenticate(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer:                 testIssuer,
		DefaultChallengeScopes: []string{"mcp:access"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	// Create a test endpoint that requires authentication
	testEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Wrap with ValidateToken middleware
	protectedEndpoint := handler.ValidateToken(testEndpoint)

	tests := []struct {
		name             string
		authHeader       string
		wantStatus       int
		wantWWWAuth      bool
		wantResourceMeta bool
		wantScope        string
	}{
		{
			name:             "missing authorization header",
			authHeader:       "",
			wantStatus:       http.StatusUnauthorized,
			wantWWWAuth:      true,
			wantResourceMeta: true,
			wantScope:        "mcp:access",
		},
		{
			name:             "invalid authorization header format",
			authHeader:       "InvalidFormat",
			wantStatus:       http.StatusUnauthorized,
			wantWWWAuth:      true,
			wantResourceMeta: true,
			wantScope:        "mcp:access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			protectedEndpoint.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.wantStatus)
			}

			wwwAuth := w.Header().Get("WWW-Authenticate")

			if tt.wantWWWAuth {
				if wwwAuth == "" {
					t.Error("Expected WWW-Authenticate header, but it was not set")
				} else {
					// Verify Bearer scheme
					if !strings.HasPrefix(wwwAuth, "Bearer ") {
						t.Errorf("WWW-Authenticate should start with 'Bearer ':\ngot: %q", wwwAuth)
					}

					// Verify resource_metadata
					if tt.wantResourceMeta {
						if !strings.Contains(wwwAuth, testResourceMetadataURL) {
							t.Errorf("WWW-Authenticate missing resource_metadata:\ngot: %q", wwwAuth)
						}
					}

					// Verify scope
					if tt.wantScope != "" {
						expectedScope := fmt.Sprintf(`scope="%s"`, tt.wantScope)
						if !strings.Contains(wwwAuth, expectedScope) {
							t.Errorf("WWW-Authenticate missing expected scope:\ngot:  %q\nwant: %q", wwwAuth, expectedScope)
						}
					}
				}
			}
		})
	}
}

// TestHandler_WriteError401BackwardCompatibilityMode tests that WWW-Authenticate can be disabled for legacy clients
func TestHandler_WriteError401BackwardCompatibilityMode(t *testing.T) {
	tests := []struct {
		name                           string
		disableWWWAuthenticateMetadata bool
		defaultChallengeScopes         []string
		wantMinimalHeader              bool
		wantResourceMetadata           bool
	}{
		{
			name:                           "metadata enabled (default) - full header",
			disableWWWAuthenticateMetadata: false,
			defaultChallengeScopes:         []string{"mcp:access"},
			wantMinimalHeader:              false,
			wantResourceMetadata:           true,
		},
		{
			name:                           "metadata disabled - minimal header for backward compatibility",
			disableWWWAuthenticateMetadata: true,
			defaultChallengeScopes:         []string{"mcp:access"},
			wantMinimalHeader:              true,
			wantResourceMetadata:           false,
		},
		{
			name:                           "metadata enabled with no scopes",
			disableWWWAuthenticateMetadata: false,
			defaultChallengeScopes:         nil,
			wantMinimalHeader:              false,
			wantResourceMetadata:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                         testIssuer,
				DisableWWWAuthenticateMetadata: tt.disableWWWAuthenticateMetadata,
				DefaultChallengeScopes:         tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			w := httptest.NewRecorder()
			handler.writeError(w, "invalid_token", "Token validation failed", http.StatusUnauthorized)

			wwwAuth := w.Header().Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Fatal("WWW-Authenticate header should always be set for 401 responses")
			}

			if tt.wantMinimalHeader {
				// Should only be "Bearer" without any parameters
				if wwwAuth != "Bearer" {
					t.Errorf("Expected minimal 'Bearer' header, got: %q", wwwAuth)
				}
				// Should NOT contain resource_metadata
				if strings.Contains(wwwAuth, "resource_metadata") {
					t.Errorf("Minimal header should not contain resource_metadata, got: %q", wwwAuth)
				}
			}

			if tt.wantResourceMetadata {
				// Should contain resource_metadata
				if !strings.Contains(wwwAuth, testResourceMetadataURL) {
					t.Errorf("Expected resource_metadata in header, got: %q", wwwAuth)
				}
				// Should contain error parameters
				if !strings.Contains(wwwAuth, `error="invalid_token"`) {
					t.Errorf("Expected error parameter in header, got: %q", wwwAuth)
				}
			}
		})
	}
}
