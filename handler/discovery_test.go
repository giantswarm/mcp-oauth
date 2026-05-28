package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

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
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer:          testIssuer,
		SupportedScopes: []string{"files:read", "files:write", "user:profile"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, config, nil)

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
	handler.config.SupportedScopes = []string{}

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

			handler.config.SupportedScopes = []string{"test:scope"}

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

			handler.config.SupportedScopes = []string{"test:scope"}

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
			} else if err != nil {
				t.Errorf("validateMetadataPath() unexpected error = %v", err)
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

			provider := mock.NewProvider()

			config := &server.Config{
				Issuer:                 testIssuer,
				SupportedScopes:        tt.serverScopes,
				ResourceMetadataByPath: tt.pathConfigs,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, config, nil)

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

	provider := mock.NewProvider()

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

	handler := New(srv, config, nil)
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

	provider := mock.NewProvider()

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

	handler := New(srv, config, nil)
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
			got := helpers.PathMatchesPrefix(tt.resourcePath, tt.prefix)
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

	provider := mock.NewProvider()

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

	handler := New(srv, config, nil)

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

	provider := mock.NewProvider()

	config := &server.Config{
		Issuer:          testIssuer,
		SupportedScopes: []string{"default:scope"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, config, nil)

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
	handler.config.RegistrationAccessToken = "test-token"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
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

	// RFC 9207: servers that include the `iss` parameter in authorization responses
	// MUST advertise the capability so clients can enable the corresponding check.
	if !meta.AuthorizationResponseIssParameterSupported {
		t.Error("AuthorizationResponseIssParameterSupported should be true (RFC 9207)")
	}
}

func TestHandler_ServeAuthorizationServerMetadata_NoRegistration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Ensure client registration is disabled (neither token, public registration, nor trusted schemes)
	handler.config.AllowPublicClientRegistration = false
	handler.config.RegistrationAccessToken = ""
	handler.config.TrustedPublicRegistrationSchemes = nil

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
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
	handler.config.AllowPublicClientRegistration = true
	handler.config.RegistrationAccessToken = ""

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify registration_endpoint IS included when public registration is enabled
	if meta.RegistrationEndpoint != "https://auth.example.com/oauth/register" {
		t.Errorf("registration_endpoint = %q, want %q", meta.RegistrationEndpoint, "https://auth.example.com/oauth/register")
	}
}

// TestHandler_ServeAuthorizationServerMetadata_TrustedSchemes verifies that
// registration_endpoint is advertised when TrustedPublicRegistrationSchemes is configured
// This enables Cursor/VSCode to discover the DCR endpoint for token-less registration
func TestHandler_ServeAuthorizationServerMetadata_TrustedSchemes(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure trusted schemes for Cursor/VSCode (without token or public registration)
	handler.config.AllowPublicClientRegistration = false
	handler.config.RegistrationAccessToken = ""
	handler.config.TrustedPublicRegistrationSchemes = []string{"cursor", "vscode"}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify registration_endpoint IS included when trusted schemes are configured
	// This allows Cursor/VSCode to discover DCR even without a registration token
	if meta.RegistrationEndpoint != "https://auth.example.com/oauth/register" {
		t.Errorf("registration_endpoint = %q, want %q (trusted schemes should enable DCR discovery)",
			meta.RegistrationEndpoint, "https://auth.example.com/oauth/register")
	}
}

// TestHandler_ServeAuthorizationServerMetadata_EnhancedFields tests the new metadata fields
// added for MCP 2025-11-25 compliance (issue #78)
func TestHandler_ServeAuthorizationServerMetadata_EnhancedFields(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Configure supported scopes
	handler.config.SupportedScopes = []string{"openid", "profile", "email", "files:read", "files:write"}

	// Enable enhanced endpoints for testing
	handler.config.EnableClientIDMetadataDocuments = true
	handler.config.EnableRevocationEndpoint = true
	handler.config.EnableIntrospectionEndpoint = true

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
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
	handler.config.EnableRevocationEndpoint = false
	handler.config.EnableIntrospectionEndpoint = false
	handler.config.EnableClientIDMetadataDocuments = false

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
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
	handler.config.SupportedScopes = nil

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta oauth.AuthorizationServerMetadata
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
	handler.config.SupportedScopes = []string{"openid", "profile"}
	handler.config.EnableClientIDMetadataDocuments = true
	handler.config.EnableRevocationEndpoint = true
	handler.config.EnableIntrospectionEndpoint = true

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
	var metaAS, metaOIDC oauth.AuthorizationServerMetadata
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

func TestHandler_ServeAuthorizationServerMetadata_CacheControl(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorizationServerMetadata(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"),
		"discovery responses must advertise RFC 8414 §3 cache headers")
	require.Empty(t, w.Header().Get("Pragma"),
		"Pragma must not leak the legacy no-cache from SetSecurityHeaders")
	require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"),
		"other security headers must survive the cache-policy override")
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

func TestHandler_ServeProtectedResourceMetadata_CacheControl(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()
	handler.ServeProtectedResourceMetadata(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))
	require.Empty(t, w.Header().Get("Pragma"))
}

func TestHandler_ServeAuthorizationServerMetadata_OIDCRequiredFields(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	handler.ServeOpenIDConfiguration(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&meta))

	require.ElementsMatch(t, []any{"public"}, meta["subject_types_supported"])
	require.Contains(t, meta["id_token_signing_alg_values_supported"], "RS256",
		"OIDC Discovery §3 requires id_token_signing_alg_values_supported non-empty")
	require.Subset(t, meta["claims_supported"], []any{"sub", "iss", "aud", "exp", "iat", "nonce"})

	// userinfo_endpoint is intentionally absent until /userinfo is implemented.
	require.NotContains(t, meta, "userinfo_endpoint")
}

func TestHandler_ServeAuthorizationServerMetadata_CacheMaxAgeOverride(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()
	handler.config.DiscoveryCacheMaxAge = 90 * time.Second

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorizationServerMetadata(w, req)

	require.Equal(t, "public, max-age=90", w.Header().Get("Cache-Control"))
}
