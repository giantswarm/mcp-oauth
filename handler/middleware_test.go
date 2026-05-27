package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestHandler_ValidateToken_MissingHeader(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	// Create a simple handler to wrap
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestHandler_RequestBodyTooLarge(t *testing.T) {
	const tinyLimit int64 = 16

	tests := []struct {
		name    string
		method  string
		path    string
		handler func(h *Handler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:   "ServeToken",
			method: http.MethodPost,
			path:   "/token",
			handler: func(h *Handler, w http.ResponseWriter, r *http.Request) {
				h.ServeToken(w, r)
			},
		},
		{
			name:   "ServeTokenRevocation",
			method: http.MethodPost,
			path:   "/revoke",
			handler: func(h *Handler, w http.ResponseWriter, r *http.Request) {
				h.ServeTokenRevocation(w, r)
			},
		},
		{
			name:   "ServeTokenIntrospection",
			method: http.MethodPost,
			path:   "/introspect",
			handler: func(h *Handler, w http.ResponseWriter, r *http.Request) {
				h.ServeTokenIntrospection(w, r)
			},
		},
		{
			name:   "ServeClientRegistration",
			method: http.MethodPost,
			path:   "/register",
			handler: func(h *Handler, w http.ResponseWriter, r *http.Request) {
				h.ServeClientRegistration(w, r)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, store := setupTestHandlerWithBodyLimit(t, tinyLimit)
			defer store.Stop()

			oversizedBody := strings.Repeat("x", int(tinyLimit)+1)

			var body string
			var contentType string
			if tc.name == "ServeClientRegistration" {
				body = fmt.Sprintf(`{"client_name":"%s"}`, oversizedBody)
				contentType = "application/json"
			} else {
				body = fmt.Sprintf("grant_type=%s", oversizedBody)
				contentType = "application/x-www-form-urlencoded"
			}

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()

			tc.handler(handler, w, req)

			if w.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
			}

			var errResp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if errResp["error"] != constants.ErrorCodeInvalidRequest {
				t.Errorf("error = %q, want %q", errResp["error"], constants.ErrorCodeInvalidRequest)
			}
			if !strings.Contains(errResp["error_description"], "too large") {
				t.Errorf("error_description = %q, want it to contain 'too large'", errResp["error_description"])
			}
		})
	}
}

func TestHandler_RequestBodyWithinLimit(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	body := "grant_type=authorization_code&code=test"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code == http.StatusRequestEntityTooLarge {
		t.Errorf("expected request to be within default body limit, got 413")
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
			} else if allowOrigin != "" {
				t.Errorf("Access-Control-Allow-Origin should not be set for disallowed origin, got %q", allowOrigin)
			}
		})
	}
}

func TestCORS_WildcardOrigin(t *testing.T) {
	// Wildcard with credentials is invalid per CORS spec, so test without credentials
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

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

	handler := New(srv, nil)

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

			provider := mock.NewProvider()

			config := &server.Config{
				Issuer:                 testIssuer,
				DefaultChallengeScopes: tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, nil)

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
					} else if strings.Contains(wwwAuth, "scope=") {
						t.Errorf("WWW-Authenticate should not contain scope:\ngot: %q", wwwAuth)
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

	provider := mock.NewProvider()

	config := &server.Config{
		Issuer:                 testIssuer,
		DefaultChallengeScopes: []string{"mcp:access"},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	// Create a test endpoint that requires authentication
	testEndpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

			provider := mock.NewProvider()

			config := &server.Config{
				Issuer:                         testIssuer,
				DisableWWWAuthenticateMetadata: tt.disableWWWAuthenticateMetadata,
				DefaultChallengeScopes:         tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, nil)

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

			provider := mock.NewProvider()

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

			handler := New(srv, nil)

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

			provider := mock.NewProvider()

			config := &server.Config{
				Issuer:                    testIssuer,
				EndpointScopeRequirements: tt.endpointScopes,
				DefaultChallengeScopes:    tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, nil)

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
			} else if strings.Contains(wwwAuth, "scope=") {
				t.Errorf("WWW-Authenticate should not contain scope:\ngot: %q", wwwAuth)
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

			provider := mock.NewProvider()

			config := &server.Config{
				Issuer:                    testIssuer,
				EndpointScopeRequirements: tt.endpointScopes,
				DefaultChallengeScopes:    tt.defaultChallengeScopes,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, nil)

			// Create test handler that is protected by ValidateToken middleware
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
				} else if strings.Contains(wwwAuth, "scope=") {
					t.Errorf("WWW-Authenticate should not contain scope when none configured:\ngot: %q", wwwAuth)
				}
			}
		})
	}
}

func TestHandler_ValidateToken_SessionIDFromContext_WithFamilyID(t *testing.T) {
	store := memory.New()
	defer store.Stop()
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer: testIssuer,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	accessToken := "session-test-at"
	familyID := "family-session-abc"

	ctx := context.Background()
	if err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-access",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: "mock-user-123", ClientID: "client-1", TokenType: "access", Audience: "", FamilyID: familyID, Scopes: nil}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	var capturedSessionID string
	var sessionOK bool

	nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedSessionID, sessionOK = SessionIDFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	handler.ValidateToken(nextHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !sessionOK {
		t.Error("SessionIDFromContext() should return true when FamilyID is set")
	}
	if capturedSessionID != familyID {
		t.Errorf("SessionIDFromContext() = %q, want %q", capturedSessionID, familyID)
	}
}

func TestHandler_ValidateToken_SessionIDFromContext_WithoutFamilyID(t *testing.T) {
	store := memory.New()
	defer store.Stop()
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer: testIssuer,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	accessToken := "session-test-no-family"

	ctx := context.Background()
	if err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-access",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	var capturedSessionID string
	var sessionOK bool

	nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedSessionID, sessionOK = SessionIDFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	handler.ValidateToken(nextHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if sessionOK {
		t.Error("SessionIDFromContext() should return false when no FamilyID is set")
	}
	if capturedSessionID != "" {
		t.Errorf("SessionIDFromContext() = %q, want empty", capturedSessionID)
	}
}

func TestHandler_ValidateToken_UserInfoAndSessionIDCoexist(t *testing.T) {
	store := memory.New()
	defer store.Stop()
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer: testIssuer,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	accessToken := "coexist-test-at"
	familyID := "family-coexist-xyz"

	ctx := context.Background()
	if err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-access",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: "mock-user-123", ClientID: "client-1", TokenType: "access", Audience: "", FamilyID: familyID, Scopes: nil}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		userInfo, uiOK := UserInfoFromContext(r.Context())
		sessionID, sidOK := SessionIDFromContext(r.Context())

		if !uiOK || userInfo == nil {
			t.Error("UserInfoFromContext() should return valid user info")
		}
		if !sidOK || sessionID == "" {
			t.Error("SessionIDFromContext() should return valid session ID")
		}
		if userInfo != nil && userInfo.ID == "" {
			t.Error("UserInfo.ID should not be empty")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	handler.ValidateToken(nextHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestSessionIDFromContext_EmptyContext(t *testing.T) {
	ctx := context.Background()
	id, ok := SessionIDFromContext(ctx)

	if ok {
		t.Error("SessionIDFromContext() on empty context should return false")
	}
	if id != "" {
		t.Errorf("SessionIDFromContext() = %q, want empty", id)
	}
}

func TestContextWithSessionID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithSessionID(ctx, "test-session-42")

	id, ok := SessionIDFromContext(ctx)
	if !ok {
		t.Error("SessionIDFromContext() should return true")
	}
	if id != "test-session-42" {
		t.Errorf("SessionIDFromContext() = %q, want %q", id, "test-session-42")
	}
}

func TestSessionIDFromContext_EmptyString(t *testing.T) {
	ctx := ContextWithSessionID(context.Background(), "")
	_, ok := SessionIDFromContext(ctx)
	if ok {
		t.Error("SessionIDFromContext() should return false for empty string")
	}
}
