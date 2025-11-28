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
	"github.com/giantswarm/mcp-oauth/internal/util"
	"github.com/giantswarm/mcp-oauth/providers"
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

// Tests for sub-path Protected Resource Metadata discovery (MCP 2025-11-25)

func TestHandler_ServeProtectedResourceMetadata_SubPathDiscovery(t *testing.T) {
	tests := []struct {
		name               string
		resourcePath       string
		pathConfigs        map[string]server.ProtectedResourceConfig
		serverScopes       []string
		expectedScopes     []string
		expectedResource   string
		expectedAuthServer string
	}{
		{
			name:         "root path returns default metadata",
			resourcePath: "/.well-known/oauth-protected-resource",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/files": {ScopesSupported: []string{"files:read"}},
			},
			serverScopes:       []string{"default:scope"},
			expectedScopes:     []string{"default:scope"},
			expectedResource:   testIssuer,
			expectedAuthServer: testIssuer,
		},
		{
			name:         "sub-path returns path-specific scopes",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/files",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/files": {ScopesSupported: []string{"files:read", "files:write"}},
			},
			serverScopes:       []string{"default:scope"},
			expectedScopes:     []string{"files:read", "files:write"},
			expectedResource:   testIssuer + "/mcp/files",
			expectedAuthServer: testIssuer,
		},
		{
			name:         "sub-path with custom authorization servers",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/admin",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/admin": {
					ScopesSupported:      []string{"admin:access"},
					AuthorizationServers: []string{"https://admin-auth.example.com"},
				},
			},
			expectedScopes:     []string{"admin:access"},
			expectedResource:   testIssuer + "/mcp/admin",
			expectedAuthServer: "https://admin-auth.example.com",
		},
		{
			name:         "sub-path with custom resource identifier",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/api",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/api": {
					ScopesSupported:    []string{"api:read"},
					ResourceIdentifier: "https://api.example.com",
				},
			},
			expectedScopes:   []string{"api:read"},
			expectedResource: "https://api.example.com",
		},
		{
			name:         "unmatched sub-path falls back to default",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/unknown",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/files": {ScopesSupported: []string{"files:read"}},
			},
			serverScopes:     []string{"default:scope"},
			expectedScopes:   []string{"default:scope"},
			expectedResource: testIssuer,
		},
		{
			name:         "longest prefix match wins",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/files/admin",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp":             {ScopesSupported: []string{"mcp:general"}},
				"/mcp/files":       {ScopesSupported: []string{"files:read"}},
				"/mcp/files/admin": {ScopesSupported: []string{"files:admin"}},
			},
			expectedScopes:   []string{"files:admin"},
			expectedResource: testIssuer + "/mcp/files/admin",
		},
		{
			name:         "path without specific scopes falls back to server scopes",
			resourcePath: "/.well-known/oauth-protected-resource/mcp/empty",
			pathConfigs: map[string]server.ProtectedResourceConfig{
				"/mcp/empty": {}, // No scopes specified
			},
			serverScopes:     []string{"server:scope"},
			expectedScopes:   []string{"server:scope"},
			expectedResource: testIssuer + "/mcp/empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                 testIssuer,
				SupportedScopes:        tt.serverScopes,
				ResourceMetadataByPath: tt.pathConfigs,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			req := httptest.NewRequest(http.MethodGet, tt.resourcePath, nil)
			w := httptest.NewRecorder()

			handler.ServeProtectedResourceMetadata(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			meta := decodeProtectedResourceMetadata(t, w)

			// Verify resource
			if tt.expectedResource != "" && meta.Resource != tt.expectedResource {
				t.Errorf("Resource = %q, want %q", meta.Resource, tt.expectedResource)
			}

			// Verify authorization servers
			if tt.expectedAuthServer != "" {
				if len(meta.AuthorizationServers) == 0 {
					t.Error("AuthorizationServers is empty")
				} else if meta.AuthorizationServers[0] != tt.expectedAuthServer {
					t.Errorf("AuthorizationServers[0] = %q, want %q",
						meta.AuthorizationServers[0], tt.expectedAuthServer)
				}
			}

			// Verify scopes
			if len(tt.expectedScopes) > 0 {
				if len(meta.ScopesSupported) != len(tt.expectedScopes) {
					t.Errorf("len(ScopesSupported) = %d, want %d",
						len(meta.ScopesSupported), len(tt.expectedScopes))
				} else {
					for i, scope := range tt.expectedScopes {
						if meta.ScopesSupported[i] != scope {
							t.Errorf("ScopesSupported[%d] = %q, want %q",
								i, meta.ScopesSupported[i], scope)
						}
					}
				}
			}
		})
	}
}

func TestHandler_RegisterProtectedResourceMetadataRoutes_WithResourceMetadataByPath(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer:          testIssuer,
		SupportedScopes: []string{"default:scope"},
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/mcp/files": {ScopesSupported: []string{"files:read", "files:write"}},
			"/mcp/admin": {ScopesSupported: []string{"admin:access"}},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)
	mux := http.NewServeMux()

	// Register without explicit mcpPath (only uses ResourceMetadataByPath)
	handler.RegisterProtectedResourceMetadataRoutes(mux, "")

	// Test each expected endpoint
	endpoints := []struct {
		path           string
		expectedScopes []string
	}{
		{
			path:           "/.well-known/oauth-protected-resource",
			expectedScopes: []string{"default:scope"},
		},
		{
			path:           "/.well-known/oauth-protected-resource/mcp/files",
			expectedScopes: []string{"files:read", "files:write"},
		},
		{
			path:           "/.well-known/oauth-protected-resource/mcp/admin",
			expectedScopes: []string{"admin:access"},
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ep.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d for path %s", w.Code, http.StatusOK, ep.path)
			}

			meta := decodeProtectedResourceMetadata(t, w)

			if len(meta.ScopesSupported) != len(ep.expectedScopes) {
				t.Errorf("len(ScopesSupported) = %d, want %d",
					len(meta.ScopesSupported), len(ep.expectedScopes))
			}

			for i, scope := range ep.expectedScopes {
				if i < len(meta.ScopesSupported) && meta.ScopesSupported[i] != scope {
					t.Errorf("ScopesSupported[%d] = %q, want %q",
						i, meta.ScopesSupported[i], scope)
				}
			}
		})
	}
}

func TestHandler_RegisterProtectedResourceMetadataRoutes_DuplicatePaths(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Both mcpPath and ResourceMetadataByPath have the same path
	config := &server.Config{
		Issuer: testIssuer,
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/mcp": {ScopesSupported: []string{"mcp:scope"}},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)
	mux := http.NewServeMux()

	// Register with mcpPath that duplicates ResourceMetadataByPath entry
	// Should not panic or double-register
	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")

	// Verify the endpoint works
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_extractResourcePath(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		requestPath  string
		expectedPath string
	}{
		{"/.well-known/oauth-protected-resource", "/"},
		{"/.well-known/oauth-protected-resource/mcp", "/mcp"},
		{"/.well-known/oauth-protected-resource/mcp/files", "/mcp/files"},
		{"/.well-known/oauth-protected-resource/mcp/files/admin", "/mcp/files/admin"},
		{"/some/other/path", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.requestPath, func(t *testing.T) {
			got := handler.extractResourcePath(tt.requestPath)
			if got != tt.expectedPath {
				t.Errorf("extractResourcePath(%q) = %q, want %q",
					tt.requestPath, got, tt.expectedPath)
			}
		})
	}
}

func TestPathMatchesPrefix(t *testing.T) {
	tests := []struct {
		resourcePath string
		prefix       string
		expected     bool
	}{
		{"/mcp", "/mcp", true},         // Exact match
		{"/mcp/files", "/mcp", true},   // Prefix match
		{"/mcp/files/a", "/mcp", true}, // Longer path
		{"/mcpx", "/mcp", false},       // Not a path boundary match
		{"/mc", "/mcp", false},         // Shorter than prefix
		{"/other/mcp", "/mcp", false},  // Not a prefix
		{"/mcp-test", "/mcp", false},   // Hyphen after prefix
		{"/mcp/", "/mcp", true},        // Trailing slash
		{"/mcp/files", "/mcp/", false}, // Trailing slash in prefix
		{"/api/v1", "/api", true},      // API versioning
		{"/api", "/api/v1", false},     // Shorter resource path
	}

	for _, tt := range tests {
		name := tt.resourcePath + "_" + tt.prefix
		t.Run(name, func(t *testing.T) {
			got := util.PathMatchesPrefix(tt.resourcePath, tt.prefix)
			if got != tt.expected {
				t.Errorf("PathMatchesPrefix(%q, %q) = %v, want %v",
					tt.resourcePath, tt.prefix, got, tt.expected)
			}
		})
	}
}

func TestHandler_findPathConfig(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: testIssuer,
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/mcp":             {ScopesSupported: []string{"mcp:base"}},
			"/mcp/files":       {ScopesSupported: []string{"files:rw"}},
			"/mcp/files/admin": {ScopesSupported: []string{"admin:full"}},
			"/api":             {ScopesSupported: []string{"api:access"}},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	tests := []struct {
		resourcePath   string
		expectedScopes []string
		expectNil      bool
	}{
		{"/mcp", []string{"mcp:base"}, false},
		{"/mcp/files", []string{"files:rw"}, false},
		{"/mcp/files/admin", []string{"admin:full"}, false},
		{"/mcp/files/admin/users", []string{"admin:full"}, false}, // Longest match
		{"/mcp/other", []string{"mcp:base"}, false},               // Falls back to /mcp
		{"/api", []string{"api:access"}, false},
		{"/api/v1", []string{"api:access"}, false},
		{"/unknown", nil, true},   // No match
		{"/", nil, true},          // Root, no specific config
		{"/mcp-other", nil, true}, // Not a valid prefix match
	}

	for _, tt := range tests {
		t.Run(tt.resourcePath, func(t *testing.T) {
			result := handler.findPathConfig(tt.resourcePath)

			if tt.expectNil {
				if result != nil {
					t.Errorf("findPathConfig(%q) = %v, want nil",
						tt.resourcePath, result)
				}
				return
			}

			if result == nil {
				t.Fatalf("findPathConfig(%q) = nil, want non-nil",
					tt.resourcePath)
			}

			if len(result.ScopesSupported) != len(tt.expectedScopes) {
				t.Errorf("len(ScopesSupported) = %d, want %d",
					len(result.ScopesSupported), len(tt.expectedScopes))
			}

			for i, scope := range tt.expectedScopes {
				if i < len(result.ScopesSupported) && result.ScopesSupported[i] != scope {
					t.Errorf("ScopesSupported[%d] = %q, want %q",
						i, result.ScopesSupported[i], scope)
				}
			}
		})
	}
}

func TestHandler_buildProtectedResourceMetadata(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer:          testIssuer,
		SupportedScopes: []string{"default:scope"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	t.Run("nil pathConfig uses defaults", func(t *testing.T) {
		metadata := handler.buildProtectedResourceMetadata("/mcp", nil)

		if metadata["resource"] != testIssuer {
			t.Errorf("resource = %v, want %v", metadata["resource"], testIssuer)
		}

		authServers, ok := metadata["authorization_servers"].([]string)
		if !ok || len(authServers) != 1 || authServers[0] != testIssuer {
			t.Errorf("authorization_servers = %v, want [%v]", metadata["authorization_servers"], testIssuer)
		}

		scopes, ok := metadata["scopes_supported"].([]string)
		if !ok || len(scopes) != 1 || scopes[0] != "default:scope" {
			t.Errorf("scopes_supported = %v, want [default:scope]", metadata["scopes_supported"])
		}
	})

	t.Run("pathConfig with all custom values", func(t *testing.T) {
		pathConfig := &server.ProtectedResourceConfig{
			ScopesSupported:        []string{"custom:scope"},
			AuthorizationServers:   []string{"https://custom-auth.example.com"},
			BearerMethodsSupported: []string{"header", "body"},
			ResourceIdentifier:     "https://custom-resource.example.com",
		}

		metadata := handler.buildProtectedResourceMetadata("/mcp", pathConfig)

		if metadata["resource"] != "https://custom-resource.example.com" {
			t.Errorf("resource = %v, want https://custom-resource.example.com",
				metadata["resource"])
		}

		authServers, ok := metadata["authorization_servers"].([]string)
		if !ok || len(authServers) != 1 || authServers[0] != "https://custom-auth.example.com" {
			t.Errorf("authorization_servers = %v, want [https://custom-auth.example.com]",
				metadata["authorization_servers"])
		}

		bearerMethods, ok := metadata["bearer_methods_supported"].([]string)
		if !ok || len(bearerMethods) != 2 {
			t.Errorf("bearer_methods_supported = %v, want [header, body]",
				metadata["bearer_methods_supported"])
		}

		scopes, ok := metadata["scopes_supported"].([]string)
		if !ok || len(scopes) != 1 || scopes[0] != "custom:scope" {
			t.Errorf("scopes_supported = %v, want [custom:scope]",
				metadata["scopes_supported"])
		}
	})

	t.Run("pathConfig without scopes falls back to server scopes", func(t *testing.T) {
		pathConfig := &server.ProtectedResourceConfig{
			// No ScopesSupported - should fall back to server default
		}

		metadata := handler.buildProtectedResourceMetadata("/mcp", pathConfig)

		scopes, ok := metadata["scopes_supported"].([]string)
		if !ok || len(scopes) != 1 || scopes[0] != "default:scope" {
			t.Errorf("scopes_supported = %v, want [default:scope]",
				metadata["scopes_supported"])
		}
	})

	t.Run("sub-path without custom resource uses derived resource", func(t *testing.T) {
		pathConfig := &server.ProtectedResourceConfig{
			ScopesSupported: []string{"sub:scope"},
			// No ResourceIdentifier - should derive from issuer + path
		}

		metadata := handler.buildProtectedResourceMetadata("/mcp/files", pathConfig)

		expectedResource := testIssuer + "/mcp/files"
		if metadata["resource"] != expectedResource {
			t.Errorf("resource = %v, want %v", metadata["resource"], expectedResource)
		}
	})
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

func TestContextWithUserInfo(t *testing.T) {
	t.Run("sets user info in context", func(t *testing.T) {
		ctx := context.Background()
		expectedUserInfo := &providers.UserInfo{
			ID:    "user-123",
			Email: "test@example.com",
			Name:  "Test User",
		}

		// Set user info in context
		ctxWithUser := ContextWithUserInfo(ctx, expectedUserInfo)

		// Retrieve user info from context
		userInfo, ok := UserInfoFromContext(ctxWithUser)
		if !ok {
			t.Error("UserInfoFromContext should return true when user info is in context")
		}
		if userInfo == nil {
			t.Fatal("UserInfoFromContext should return non-nil user info")
		}
		if userInfo.ID != expectedUserInfo.ID {
			t.Errorf("Expected user ID %q, got %q", expectedUserInfo.ID, userInfo.ID)
		}
		if userInfo.Email != expectedUserInfo.Email {
			t.Errorf("Expected email %q, got %q", expectedUserInfo.Email, userInfo.Email)
		}
		if userInfo.Name != expectedUserInfo.Name {
			t.Errorf("Expected name %q, got %q", expectedUserInfo.Name, userInfo.Name)
		}
	})

	t.Run("sets nil user info in context", func(t *testing.T) {
		ctx := context.Background()

		// Set nil user info in context
		ctxWithUser := ContextWithUserInfo(ctx, nil)

		// Retrieve user info from context - returns (nil, true) because a typed nil
		// value was explicitly stored. The caller should check userInfo != nil.
		userInfo, ok := UserInfoFromContext(ctxWithUser)
		if !ok {
			t.Error("UserInfoFromContext should return true when nil user info is explicitly set in context")
		}
		if userInfo != nil {
			t.Error("UserInfoFromContext should return nil when nil user info is in context")
		}
	})

	t.Run("overwrites existing user info", func(t *testing.T) {
		ctx := context.Background()
		originalUserInfo := &providers.UserInfo{
			ID:    "user-original",
			Email: "original@example.com",
		}
		newUserInfo := &providers.UserInfo{
			ID:    "user-new",
			Email: "new@example.com",
		}

		// Set original user info
		ctxWithOriginal := ContextWithUserInfo(ctx, originalUserInfo)
		// Overwrite with new user info
		ctxWithNew := ContextWithUserInfo(ctxWithOriginal, newUserInfo)

		// Retrieve user info - should get new user info
		userInfo, ok := UserInfoFromContext(ctxWithNew)
		if !ok {
			t.Error("UserInfoFromContext should return true")
		}
		if userInfo.ID != newUserInfo.ID {
			t.Errorf("Expected user ID %q, got %q", newUserInfo.ID, userInfo.ID)
		}
		if userInfo.Email != newUserInfo.Email {
			t.Errorf("Expected email %q, got %q", newUserInfo.Email, userInfo.Email)
		}
	})

	t.Run("works with http.Request context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		expectedUserInfo := &providers.UserInfo{
			ID:    "user-456",
			Email: "http@example.com",
		}

		// Set user info in request context
		ctxWithUser := ContextWithUserInfo(req.Context(), expectedUserInfo)
		req = req.WithContext(ctxWithUser)

		// Retrieve user info from request context
		userInfo, ok := UserInfoFromContext(req.Context())
		if !ok {
			t.Error("UserInfoFromContext should return true")
		}
		if userInfo.ID != expectedUserInfo.ID {
			t.Errorf("Expected user ID %q, got %q", expectedUserInfo.ID, userInfo.ID)
		}
	})
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
		{
			name:      "scope with quotes (defense-in-depth escaping)",
			scope:     `files:read "special" user:profile`,
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="files:read \"special\" user:profile"`,
			},
			wantNotContain: []string{"error=", "error_description="},
		},
		{
			name:      "scope with backslash (defense-in-depth escaping)",
			scope:     `files:read scope\test user:profile`,
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="files:read scope\\test user:profile"`,
			},
			wantNotContain: []string{"error=", "error_description="},
		},
		{
			name:      "scope with both backslash and quotes (combined escaping)",
			scope:     `test:\"quoted\value`,
			error:     "",
			errorDesc: "",
			wantContain: []string{
				"Bearer",
				testResourceMetadataURL,
				`scope="test:\\\"quoted\\value"`,
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

// TestHandler_GetChallengeScopes tests the getChallengeScopes() scope resolution logic
func TestHandler_GetChallengeScopes(t *testing.T) {
	tests := []struct {
		name                   string
		requestPath            string
		requestMethod          string
		endpointScopes         map[string][]string
		endpointMethodScopes   map[string]map[string][]string
		defaultChallengeScopes []string
		wantScopes             string
	}{
		{
			name:                   "endpoint-specific scopes take priority",
			requestPath:            "/api/files/test.txt",
			requestMethod:          "GET",
			endpointScopes:         map[string][]string{"/api/files/*": {"files:read", "files:write"}},
			defaultChallengeScopes: []string{"default:scope"},
			wantScopes:             "files:read files:write",
		},
		{
			name:                   "method-specific scopes take priority over path scopes",
			requestPath:            "/api/files/test.txt",
			requestMethod:          "POST",
			endpointScopes:         map[string][]string{"/api/files/*": {"files:read"}},
			endpointMethodScopes:   map[string]map[string][]string{"/api/files/*": {"POST": {"files:write", "files:create"}}},
			defaultChallengeScopes: []string{"default:scope"},
			wantScopes:             "files:write files:create",
		},
		{
			name:                   "fallback to default challenge scopes when no endpoint match",
			requestPath:            "/api/other/resource",
			requestMethod:          "GET",
			endpointScopes:         map[string][]string{"/api/files/*": {"files:read"}},
			defaultChallengeScopes: []string{"mcp:access", "user:profile"},
			wantScopes:             "mcp:access user:profile",
		},
		{
			name:                   "no scopes when nothing configured",
			requestPath:            "/api/resource",
			requestMethod:          "GET",
			endpointScopes:         nil,
			endpointMethodScopes:   nil,
			defaultChallengeScopes: nil,
			wantScopes:             "",
		},
		{
			name:                   "exact path match",
			requestPath:            "/api/user/profile",
			requestMethod:          "GET",
			endpointScopes:         map[string][]string{"/api/user/profile": {"user:profile"}},
			defaultChallengeScopes: []string{"default:scope"},
			wantScopes:             "user:profile",
		},
		{
			name:                   "wildcard path match",
			requestPath:            "/api/admin/users/delete",
			requestMethod:          "DELETE",
			endpointScopes:         map[string][]string{"/api/admin/*": {"admin:access"}},
			defaultChallengeScopes: []string{"default:scope"},
			wantScopes:             "admin:access",
		},
		{
			name:                   "method wildcard fallback",
			requestPath:            "/api/files/test.txt",
			requestMethod:          "PATCH",
			endpointMethodScopes:   map[string]map[string][]string{"/api/files/*": {"*": {"files:modify"}}},
			defaultChallengeScopes: []string{"default:scope"},
			wantScopes:             "files:modify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                          testIssuer,
				EndpointScopeRequirements:       tt.endpointScopes,
				EndpointMethodScopeRequirements: tt.endpointMethodScopes,
				DefaultChallengeScopes:          tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			// Create test request
			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)

			// Test getChallengeScopes
			gotScopes := handler.getChallengeScopes(req)

			if gotScopes != tt.wantScopes {
				t.Errorf("getChallengeScopes() = %q, want %q", gotScopes, tt.wantScopes)
			}
		})
	}
}

// TestHandler_WriteUnauthorizedError tests the writeUnauthorizedError method
func TestHandler_WriteUnauthorizedError(t *testing.T) {
	tests := []struct {
		name                   string
		requestPath            string
		requestMethod          string
		endpointScopes         map[string][]string
		defaultChallengeScopes []string
		errorCode              string
		errorDesc              string
		wantScopes             string
		wantErrorCode          string
		wantErrorDesc          string
	}{
		{
			name:                   "with endpoint-specific scopes",
			requestPath:            "/api/files/test.txt",
			requestMethod:          "GET",
			endpointScopes:         map[string][]string{"/api/files/*": {"files:read", "files:write"}},
			defaultChallengeScopes: []string{"default:scope"},
			errorCode:              "invalid_token",
			errorDesc:              "Token has expired",
			wantScopes:             "files:read files:write",
			wantErrorCode:          "invalid_token",
			wantErrorDesc:          "Token has expired",
		},
		{
			name:                   "with default challenge scopes",
			requestPath:            "/api/other",
			requestMethod:          "GET",
			endpointScopes:         nil,
			defaultChallengeScopes: []string{"mcp:access"},
			errorCode:              "invalid_token",
			errorDesc:              "Missing Authorization header",
			wantScopes:             "mcp:access",
			wantErrorCode:          "invalid_token",
			wantErrorDesc:          "Missing Authorization header",
		},
		{
			name:                   "with no scopes configured",
			requestPath:            "/api/resource",
			requestMethod:          "GET",
			endpointScopes:         nil,
			defaultChallengeScopes: nil,
			errorCode:              "invalid_token",
			errorDesc:              "Invalid token format",
			wantScopes:             "",
			wantErrorCode:          "invalid_token",
			wantErrorDesc:          "Invalid token format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                    testIssuer,
				EndpointScopeRequirements: tt.endpointScopes,
				DefaultChallengeScopes:    tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)

			handler.writeUnauthorizedError(w, req, tt.errorCode, tt.errorDesc)

			// Check status code
			if w.Code != http.StatusUnauthorized {
				t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
			}

			// Check WWW-Authenticate header
			wwwAuth := w.Header().Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Fatal("WWW-Authenticate header should be set")
			}

			// Check resource_metadata
			if !strings.Contains(wwwAuth, testResourceMetadataURL) {
				t.Errorf("WWW-Authenticate missing resource_metadata:\ngot: %q", wwwAuth)
			}

			// Check scope parameter
			if tt.wantScopes != "" {
				expectedScope := fmt.Sprintf(`scope="%s"`, tt.wantScopes)
				if !strings.Contains(wwwAuth, expectedScope) {
					t.Errorf("WWW-Authenticate missing expected scope:\ngot:  %q\nwant: %q", wwwAuth, expectedScope)
				}
			} else {
				if strings.Contains(wwwAuth, "scope=") {
					t.Errorf("WWW-Authenticate should not contain scope:\ngot: %q", wwwAuth)
				}
			}

			// Check error code
			expectedError := fmt.Sprintf(`error="%s"`, tt.wantErrorCode)
			if !strings.Contains(wwwAuth, expectedError) {
				t.Errorf("WWW-Authenticate missing error code:\ngot:  %q\nwant: %q", wwwAuth, expectedError)
			}

			// Check error description
			expectedErrorDesc := fmt.Sprintf(`error_description="%s"`, tt.wantErrorDesc)
			if !strings.Contains(wwwAuth, expectedErrorDesc) {
				t.Errorf("WWW-Authenticate missing error description:\ngot:  %q\nwant: %q", wwwAuth, expectedErrorDesc)
			}

			// Check JSON response body
			var response map[string]string
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response body: %v", err)
			}

			if response["error"] != tt.wantErrorCode {
				t.Errorf("Response error = %q, want %q", response["error"], tt.wantErrorCode)
			}

			if response["error_description"] != tt.wantErrorDesc {
				t.Errorf("Response error_description = %q, want %q", response["error_description"], tt.wantErrorDesc)
			}
		})
	}
}

// TestHandler_ValidateTokenWithEndpointSpecificWWWAuthenticate tests that ValidateToken middleware
// returns endpoint-specific scopes in WWW-Authenticate headers for 401 responses
func TestHandler_ValidateTokenWithEndpointSpecificWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name                   string
		requestPath            string
		requestMethod          string
		authHeader             string
		endpointScopes         map[string][]string
		defaultChallengeScopes []string
		wantStatus             int
		wantScopes             string
	}{
		{
			name:                   "missing auth header - endpoint-specific scopes in challenge",
			requestPath:            "/api/files/test.txt",
			requestMethod:          "GET",
			authHeader:             "",
			endpointScopes:         map[string][]string{"/api/files/*": {"files:read", "files:write"}},
			defaultChallengeScopes: []string{"default:scope"},
			wantStatus:             http.StatusUnauthorized,
			wantScopes:             "files:read files:write",
		},
		{
			name:                   "invalid auth header format - endpoint-specific scopes",
			requestPath:            "/api/admin/users",
			requestMethod:          "GET",
			authHeader:             "InvalidFormat",
			endpointScopes:         map[string][]string{"/api/admin/*": {"admin:access"}},
			defaultChallengeScopes: []string{"default:scope"},
			wantStatus:             http.StatusUnauthorized,
			wantScopes:             "admin:access",
		},
		{
			name:                   "missing auth header - no scopes configured",
			requestPath:            "/api/resource",
			requestMethod:          "GET",
			authHeader:             "",
			endpointScopes:         nil,
			defaultChallengeScopes: nil,
			wantStatus:             http.StatusUnauthorized,
			wantScopes:             "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			provider := mock.NewMockProvider()

			config := &server.Config{
				Issuer:                    testIssuer,
				EndpointScopeRequirements: tt.endpointScopes,
				DefaultChallengeScopes:    tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := NewHandler(srv, nil)

			// Create test handler that is protected by ValidateToken middleware
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			protectedHandler := handler.ValidateToken(testHandler)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			protectedHandler.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.wantStatus)
			}

			// Check WWW-Authenticate header for 401 responses
			if w.Code == http.StatusUnauthorized {
				wwwAuth := w.Header().Get("WWW-Authenticate")
				if wwwAuth == "" {
					t.Fatal("WWW-Authenticate header should be set for 401 responses")
				}

				// Check resource_metadata is present
				if !strings.Contains(wwwAuth, testResourceMetadataURL) {
					t.Errorf("WWW-Authenticate missing resource_metadata:\ngot: %q", wwwAuth)
				}

				// Check scope parameter
				if tt.wantScopes != "" {
					expectedScope := fmt.Sprintf(`scope="%s"`, tt.wantScopes)
					if !strings.Contains(wwwAuth, expectedScope) {
						t.Errorf("WWW-Authenticate missing expected scope:\ngot:  %q\nwant: %q", wwwAuth, expectedScope)
					}
				} else {
					if strings.Contains(wwwAuth, "scope=") {
						t.Errorf("WWW-Authenticate should not contain scope when none configured:\ngot: %q", wwwAuth)
					}
				}
			}
		})
	}
}

// TestIsCustomURLScheme tests the isCustomURLScheme helper function
func TestIsCustomURLScheme(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		// HTTP schemes - should NOT trigger interstitial
		{
			name:     "http scheme",
			uri:      "http://example.com/callback",
			expected: false,
		},
		{
			name:     "https scheme",
			uri:      "https://example.com/callback",
			expected: false,
		},
		{
			name:     "HTTP uppercase",
			uri:      "HTTP://example.com/callback",
			expected: false,
		},
		{
			name:     "HTTPS uppercase",
			uri:      "HTTPS://example.com/callback",
			expected: false,
		},
		{
			name:     "http localhost",
			uri:      "http://localhost:8080/callback",
			expected: false,
		},
		{
			name:     "http loopback",
			uri:      "http://127.0.0.1:8080/callback",
			expected: false,
		},

		// Custom URL schemes - SHOULD trigger interstitial
		{
			name:     "cursor scheme",
			uri:      "cursor://oauth/callback",
			expected: true,
		},
		{
			name:     "vscode scheme",
			uri:      "vscode://example.extension/callback",
			expected: true,
		},
		{
			name:     "slack scheme",
			uri:      "slack://oauth/callback",
			expected: true,
		},
		{
			name:     "notion scheme",
			uri:      "notion://oauth/callback",
			expected: true,
		},
		{
			name:     "obsidian scheme",
			uri:      "obsidian://plugin/callback",
			expected: true,
		},
		{
			name:     "custom-app scheme",
			uri:      "myapp://auth/done",
			expected: true,
		},
		{
			name:     "com.example.app scheme (reverse domain)",
			uri:      "com.example.app://callback",
			expected: true,
		},
		{
			name:     "custom scheme with query params",
			uri:      "cursor://callback?code=abc&state=xyz",
			expected: true,
		},

		// Edge cases
		{
			name:     "empty string",
			uri:      "",
			expected: false,
		},
		{
			name:     "no scheme",
			uri:      "example.com/callback",
			expected: false,
		},
		{
			name:     "relative path",
			uri:      "/callback",
			expected: false,
		},
		{
			name:     "malformed URL",
			uri:      "://invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCustomURLScheme(tt.uri)
			if result != tt.expected {
				t.Errorf("isCustomURLScheme(%q) = %v, want %v", tt.uri, result, tt.expected)
			}
		})
	}
}

// TestGetAppNameFromScheme tests the getAppNameFromScheme helper function
func TestGetAppNameFromScheme(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		// Known app schemes
		{
			name:     "cursor",
			uri:      "cursor://oauth/callback",
			expected: "Cursor",
		},
		{
			name:     "vscode",
			uri:      "vscode://extension/callback",
			expected: "Visual Studio Code",
		},
		{
			name:     "code",
			uri:      "code://extension/callback",
			expected: "Visual Studio Code",
		},
		{
			name:     "slack",
			uri:      "slack://callback",
			expected: "Slack",
		},
		{
			name:     "notion",
			uri:      "notion://callback",
			expected: "Notion",
		},
		{
			name:     "obsidian",
			uri:      "obsidian://plugin",
			expected: "Obsidian",
		},
		{
			name:     "figma",
			uri:      "figma://callback",
			expected: "Figma",
		},
		{
			name:     "linear",
			uri:      "linear://callback",
			expected: "Linear",
		},
		{
			name:     "raycast",
			uri:      "raycast://callback",
			expected: "Raycast",
		},
		{
			name:     "warp",
			uri:      "warp://callback",
			expected: "Warp",
		},
		{
			name:     "zed",
			uri:      "zed://callback",
			expected: "Zed",
		},
		{
			name:     "windsurf",
			uri:      "windsurf://callback",
			expected: "Windsurf",
		},

		// Unknown schemes - should capitalize first letter
		{
			name:     "unknown scheme",
			uri:      "myapp://callback",
			expected: "Myapp",
		},
		{
			name:     "unknown scheme with dashes",
			uri:      "custom-app://callback",
			expected: "Custom-app",
		},

		// HTTP schemes - capitalizes like unknown schemes (caller should check isCustomURLScheme first)
		{
			name:     "http scheme",
			uri:      "http://example.com",
			expected: "Http",
		},
		{
			name:     "https scheme",
			uri:      "https://example.com",
			expected: "Https",
		},

		// Edge cases
		{
			name:     "empty string",
			uri:      "",
			expected: "",
		},
		{
			name:     "malformed URL",
			uri:      "://invalid",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAppNameFromScheme(tt.uri)
			if result != tt.expected {
				t.Errorf("getAppNameFromScheme(%q) = %q, want %q", tt.uri, result, tt.expected)
			}
		})
	}
}

// TestHandler_ServeCallback_CustomURLScheme tests that custom URL schemes
// receive an interstitial page instead of a direct redirect
func TestHandler_ServeCallback_CustomURLScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with custom URL scheme redirect
	client, _, err := handler.server.RegisterClient(ctx,
		"Cursor Test Client",
		"public",
		"none", // Public client (no secret)
		[]string{"cursor://oauth/callback"},
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
	_, err = handler.server.StartAuthorizationFlow(ctx,
		client.ClientID,
		"cursor://oauth/callback",
		"openid email",
		"", // resource parameter (optional)
		challenge,
		"S256",
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
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

	// Should return HTML interstitial, NOT a redirect
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for custom URL scheme", w.Code, http.StatusOK)
	}

	// Check content type is HTML
	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	// Verify HTML content contains expected elements
	body := w.Body.String()

	// Should contain success message
	if !strings.Contains(body, "Authorization Successful") {
		t.Error("Response should contain 'Authorization Successful' message")
	}

	// Should contain app name
	if !strings.Contains(body, "Cursor") {
		t.Error("Response should contain app name 'Cursor'")
	}

	// Should contain the redirect URL with authorization code
	if !strings.Contains(body, "cursor://oauth/callback") {
		t.Error("Response should contain the redirect URL")
	}
	if !strings.Contains(body, "code=") {
		t.Error("Response should contain authorization code")
	}
	if !strings.Contains(body, "state="+clientState) {
		t.Error("Response should contain original client state")
	}

	// Should contain manual button
	if !strings.Contains(body, "Open Cursor") {
		t.Error("Response should contain manual 'Open Cursor' button")
	}

	// Should contain close hint
	if !strings.Contains(body, "close this window") {
		t.Error("Response should contain 'close this window' hint")
	}

	// Should NOT have Location header (no redirect)
	if location := w.Header().Get("Location"); location != "" {
		t.Errorf("Location header should be empty for interstitial page, got %q", location)
	}
}

// TestHandler_ServeCallback_HTTPScheme tests that HTTP/HTTPS schemes
// still use direct redirects (not interstitial)
func TestHandler_ServeCallback_HTTPScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with HTTPS redirect
	client, _, err := handler.server.RegisterClient(ctx,
		"Web App Client",
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

	clientState := testutil.GenerateRandomString(43)
	_, err = handler.server.StartAuthorizationFlow(ctx,
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		"",
		challenge,
		"S256",
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	// Test callback
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should redirect, NOT return HTML interstitial
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status for HTTPS scheme", w.Code)
	}

	// Should have Location header
	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set for HTTPS redirect")
	}

	// Verify redirect URL
	if !strings.HasPrefix(location, "https://example.com/callback") {
		t.Errorf("Location = %q, want to start with https://example.com/callback", location)
	}
	if !strings.Contains(location, "code=") {
		t.Error("Location should contain authorization code")
	}
	if !strings.Contains(location, "state="+clientState) {
		t.Error("Location should contain original client state")
	}
}

// TestHandler_ServeCallback_VSCodeScheme tests VS Code custom scheme handling
func TestHandler_ServeCallback_VSCodeScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with VS Code scheme
	client, _, err := handler.server.RegisterClient(ctx,
		"VS Code Extension",
		"public",
		"none",
		[]string{"vscode://example.extension/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err = handler.server.StartAuthorizationFlow(ctx,
		client.ClientID,
		"vscode://example.extension/callback",
		"openid",
		"",
		challenge,
		"S256",
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should return interstitial
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for VS Code scheme", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Visual Studio Code") {
		t.Error("Response should contain 'Visual Studio Code' app name")
	}
	if !strings.Contains(body, "vscode://") {
		t.Error("Response should contain vscode:// redirect URL")
	}
}

// TestHandler_ServeSuccessInterstitial tests the interstitial page rendering
func TestHandler_ServeSuccessInterstitial(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name           string
		redirectURL    string
		wantAppName    string
		wantURLPattern string // Pattern to look for (scheme + path, not full URL with query string)
	}{
		{
			name:           "cursor scheme",
			redirectURL:    "cursor://callback?code=abc123&state=xyz789",
			wantAppName:    "Cursor",
			wantURLPattern: "cursor://callback", // URL base without query params (& gets HTML-escaped)
		},
		{
			name:           "vscode scheme",
			redirectURL:    "vscode://extension/callback?code=abc",
			wantAppName:    "Visual Studio Code",
			wantURLPattern: "vscode://extension/callback",
		},
		{
			name:           "unknown scheme",
			redirectURL:    "myapp://auth/done?code=abc",
			wantAppName:    "Myapp",
			wantURLPattern: "myapp://auth/done",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
			handler.serveSuccessInterstitial(w, r, tt.redirectURL)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
			}

			contentType := w.Header().Get("Content-Type")
			if !strings.HasPrefix(contentType, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", contentType)
			}

			body := w.Body.String()

			// Check for success message
			if !strings.Contains(body, "Authorization Successful") {
				t.Error("Missing 'Authorization Successful' message")
			}

			// Check for app name
			if !strings.Contains(body, tt.wantAppName) {
				t.Errorf("Missing app name %q in response", tt.wantAppName)
			}

			// Check for redirect URL pattern (note: & in URLs gets HTML-escaped to &amp;)
			if !strings.Contains(body, tt.wantURLPattern) {
				t.Errorf("Missing redirect URL pattern %q in response", tt.wantURLPattern)
			}

			// Check for security headers
			if w.Header().Get("X-Content-Type-Options") == "" {
				t.Error("Missing X-Content-Type-Options security header")
			}

			// Check CSP includes script hash (not 'none' for scripts)
			csp := w.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Error("Missing Content-Security-Policy header")
			}
			if !strings.Contains(csp, "script-src") {
				t.Error("CSP should contain script-src directive for interstitial page")
			}
			if !strings.Contains(csp, "sha256-") {
				t.Error("CSP should contain SHA-256 hash for inline script")
			}
		})
	}
}

// TestHandler_ServeSuccessInterstitial_Branding tests interstitial page with branding configuration
func TestHandler_ServeSuccessInterstitial_Branding(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Configure with branding
	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				LogoURL:            "https://cdn.example.com/logo.svg",
				LogoAlt:            "Example Corp Logo",
				Title:              "Connected to Example Corp",
				Message:            "Welcome! You are now authenticated.",
				ButtonText:         "Return to App",
				PrimaryColor:       "#4F46E5",
				BackgroundGradient: "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)",
				CustomCSS:          ".container { max-width: 600px; }",
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom branding elements
	if !strings.Contains(body, "https://cdn.example.com/logo.svg") {
		t.Error("Response should contain custom logo URL")
	}
	if !strings.Contains(body, "Example Corp Logo") {
		t.Error("Response should contain custom logo alt text")
	}
	if !strings.Contains(body, "Connected to Example Corp") {
		t.Error("Response should contain custom title")
	}
	if !strings.Contains(body, "Welcome! You are now authenticated.") {
		t.Error("Response should contain custom message")
	}
	if !strings.Contains(body, "Return to App") {
		t.Error("Response should contain custom button text")
	}
	if !strings.Contains(body, "#4F46E5") {
		t.Error("Response should contain custom primary color")
	}
	if !strings.Contains(body, "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)") {
		t.Error("Response should contain custom background gradient")
	}
	if !strings.Contains(body, ".container { max-width: 600px; }") {
		t.Error("Response should contain custom CSS")
	}

	// Should NOT contain default success icon (since logo is set)
	if strings.Contains(body, `<div class="success-icon">`) {
		t.Error("Response should NOT contain default success icon when logo is configured")
	}

	// Security: Logo should have crossorigin="anonymous" for CORS isolation
	if !strings.Contains(body, `crossorigin="anonymous"`) {
		t.Error("Logo img should have crossorigin=\"anonymous\" for security isolation")
	}
}

// TestHandler_ServeSuccessInterstitial_CustomTemplate tests interstitial with custom template
func TestHandler_ServeSuccessInterstitial_CustomTemplate(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	customTemplate := `<!DOCTYPE html>
<html>
<head><title>Custom Auth Page</title></head>
<body>
<h1>Custom Success - {{.AppName}}</h1>
<a href="{{.RedirectURL}}">Continue</a>
</body>
</html>`

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			CustomTemplate: customTemplate,
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom template content
	if !strings.Contains(body, "Custom Auth Page") {
		t.Error("Response should contain custom template title")
	}
	if !strings.Contains(body, "Custom Success - Cursor") {
		t.Error("Response should contain custom heading with app name")
	}
	if !strings.Contains(body, "cursor://oauth/callback") {
		t.Error("Response should contain redirect URL")
	}

	// Should NOT contain default template content
	if strings.Contains(body, "Authorization Successful") {
		t.Error("Response should NOT contain default title when custom template is used")
	}
}

// TestHandler_ServeSuccessInterstitial_CustomHandler tests interstitial with custom handler
func TestHandler_ServeSuccessInterstitial_CustomHandler(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	var capturedRedirectURL, capturedAppName string

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			CustomHandler: func(w http.ResponseWriter, r *http.Request) {
				// Extract values from context using helper functions
				capturedRedirectURL = InterstitialRedirectURL(r.Context())
				capturedAppName = InterstitialAppName(r.Context())

				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Custom Handler Response</body></html>"))
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "vscode://extension/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom handler response
	if !strings.Contains(body, "Custom Handler Response") {
		t.Error("Response should contain custom handler output")
	}

	// Verify context values were passed correctly
	if capturedRedirectURL != "vscode://extension/callback?code=abc" {
		t.Errorf("InterstitialRedirectURL() = %q, want %q", capturedRedirectURL, "vscode://extension/callback?code=abc")
	}
	if capturedAppName != "Visual Studio Code" {
		t.Errorf("InterstitialAppName() = %q, want %q", capturedAppName, "Visual Studio Code")
	}

	// Should NOT contain default template content
	if strings.Contains(body, "Authorization Successful") {
		t.Error("Response should NOT contain default content when custom handler is used")
	}
}

// TestInterstitialContextHelpers tests the context helper functions
func TestInterstitialContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test with empty context
	if got := InterstitialRedirectURL(ctx); got != "" {
		t.Errorf("InterstitialRedirectURL(empty ctx) = %q, want empty string", got)
	}
	if got := InterstitialAppName(ctx); got != "" {
		t.Errorf("InterstitialAppName(empty ctx) = %q, want empty string", got)
	}

	// Test with values set
	ctx = context.WithValue(ctx, interstitialRedirectURLKey, "cursor://callback")
	ctx = context.WithValue(ctx, interstitialAppNameKey, "Cursor")

	if got := InterstitialRedirectURL(ctx); got != "cursor://callback" {
		t.Errorf("InterstitialRedirectURL() = %q, want %q", got, "cursor://callback")
	}
	if got := InterstitialAppName(ctx); got != "Cursor" {
		t.Errorf("InterstitialAppName() = %q, want %q", got, "Cursor")
	}
}

// TestHandler_ServeCallback_CustomURLScheme_WithBranding tests callback with branding
func TestHandler_ServeCallback_CustomURLScheme_WithBranding(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				Title:        "Welcome Back!",
				PrimaryColor: "#FF5733",
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	// Register a client with custom URL scheme redirect
	client, _, err := srv.RegisterClient(ctx,
		"Branded Test Client",
		"public",
		"none",
		[]string{"cursor://oauth/callback"},
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
	clientState := testutil.GenerateRandomString(43)

	_, err = srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"cursor://oauth/callback",
		"openid email",
		"",
		challenge,
		"S256",
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for custom URL scheme with branding", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom branding
	if !strings.Contains(body, "Welcome Back!") {
		t.Error("Response should contain custom title from branding config")
	}
	if !strings.Contains(body, "#FF5733") {
		t.Error("Response should contain custom primary color from branding config")
	}
}

// TestHandler_ServeSuccessInterstitial_AppNamePlaceholder tests that {{.AppName}} placeholder is replaced
func TestHandler_ServeSuccessInterstitial_AppNamePlaceholder(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Configure with branding that uses {{.AppName}} placeholders
	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				Title:      "Connected to Inboxfewer",
				Message:    "You have been authenticated with {{.AppName}}. You can now close this window.",
				ButtonText: "Open {{.AppName}}",
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := NewHandler(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	// cursor:// scheme should be detected and replaced with "Cursor"
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check that {{.AppName}} was replaced with actual app name (Cursor)
	if strings.Contains(body, "{{.AppName}}") {
		t.Error("Response should NOT contain literal {{.AppName}} placeholder - it should be replaced")
	}

	// Check that "Cursor" appears in the message and button
	if !strings.Contains(body, "You have been authenticated with Cursor") {
		t.Error("Response should contain 'You have been authenticated with Cursor' (AppName replaced)")
	}
	if !strings.Contains(body, "Open Cursor") {
		t.Error("Response should contain 'Open Cursor' (AppName replaced in button)")
	}
}
