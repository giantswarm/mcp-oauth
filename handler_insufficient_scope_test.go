package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	testUserID = "test_user"
)

// TestWriteInsufficientScopeError tests the writeInsufficientScopeError function
func TestWriteInsufficientScopeError(t *testing.T) {
	tests := []struct {
		name            string
		requiredScopes  []string
		description     string
		wantStatus      int
		wantError       string
		wantScopeHeader string
	}{
		{
			name:            "single scope required",
			requiredScopes:  []string{"files:read"},
			description:     "File read access required",
			wantStatus:      http.StatusForbidden,
			wantError:       ErrorCodeInsufficientScope,
			wantScopeHeader: "files:read",
		},
		{
			name:            "multiple scopes required",
			requiredScopes:  []string{"files:read", "files:write", "user:profile"},
			description:     "File and profile access required",
			wantStatus:      http.StatusForbidden,
			wantError:       ErrorCodeInsufficientScope,
			wantScopeHeader: "files:read files:write user:profile",
		},
		{
			name:            "no scopes required",
			requiredScopes:  []string{},
			description:     "No scopes needed",
			wantStatus:      http.StatusForbidden,
			wantError:       ErrorCodeInsufficientScope,
			wantScopeHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server and handler
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer: "https://example.com",
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			// Create response recorder
			w := httptest.NewRecorder()

			// Call writeInsufficientScopeError
			handler.writeInsufficientScopeError(w, tt.requiredScopes, tt.description)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.wantStatus)
			}

			// Check error in response body
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if body["error"] != tt.wantError {
				t.Errorf("Error code = %s, want %s", body["error"], tt.wantError)
			}

			if body["error_description"] != tt.description {
				t.Errorf("Error description = %s, want %s", body["error_description"], tt.description)
			}

			// Check WWW-Authenticate header
			wwwAuth := w.Header().Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Error("WWW-Authenticate header is missing")
			}

			// Verify header contains error="insufficient_scope"
			if !strings.Contains(wwwAuth, `error="insufficient_scope"`) {
				t.Errorf("WWW-Authenticate missing insufficient_scope error: %s", wwwAuth)
			}

			// Verify header contains required scopes if any
			if len(tt.requiredScopes) > 0 {
				if !strings.Contains(wwwAuth, `scope="`+tt.wantScopeHeader+`"`) {
					t.Errorf("WWW-Authenticate missing required scopes: got %s, want scopes %s", wwwAuth, tt.wantScopeHeader)
				}
			}

			// Verify header contains resource_metadata
			if !strings.Contains(wwwAuth, `resource_metadata="https://example.com/.well-known/oauth-protected-resource"`) {
				t.Errorf("WWW-Authenticate missing resource_metadata: %s", wwwAuth)
			}
		})
	}
}

// TestGetRequiredScopes tests the getRequiredScopes function
func TestGetRequiredScopes(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string][]string
		requestPath string
		wantScopes  []string
		wantNil     bool
	}{
		{
			name: "exact path match",
			config: map[string][]string{
				"/api/files": {"files:read"},
			},
			requestPath: "/api/files",
			wantScopes:  []string{"files:read"},
		},
		{
			name: "prefix path match with wildcard",
			config: map[string][]string{
				"/api/files/*": {"files:read", "files:write"},
			},
			requestPath: "/api/files/document.txt",
			wantScopes:  []string{"files:read", "files:write"},
		},
		{
			name: "no match returns nil",
			config: map[string][]string{
				"/api/files/*": {"files:read"},
			},
			requestPath: "/api/admin",
			wantNil:     true,
		},
		{
			name:        "no config returns nil",
			config:      nil,
			requestPath: "/api/files",
			wantNil:     true,
		},
		{
			name: "exact match takes precedence over wildcard",
			config: map[string][]string{
				"/api/files":   {"files:read"},
				"/api/files/*": {"files:read", "files:write"},
			},
			requestPath: "/api/files",
			wantScopes:  []string{"files:read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer:                    "https://example.com",
					EndpointScopeRequirements: tt.config,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			scopes := handler.getRequiredScopes(req)

			if tt.wantNil {
				if scopes != nil {
					t.Errorf("Expected nil scopes, got %v", scopes)
				}
			} else {
				if len(scopes) != len(tt.wantScopes) {
					t.Errorf("Scopes length = %d, want %d", len(scopes), len(tt.wantScopes))
				}
				for i, scope := range scopes {
					if scope != tt.wantScopes[i] {
						t.Errorf("Scope[%d] = %s, want %s", i, scope, tt.wantScopes[i])
					}
				}
			}
		})
	}
}

// TestHasRequiredScopes tests the hasRequiredScopes function
func TestHasRequiredScopes(t *testing.T) {
	tests := []struct {
		name           string
		tokenScopes    []string
		requiredScopes []string
		want           bool
	}{
		{
			name:           "token has all required scopes",
			tokenScopes:    []string{"files:read", "files:write", "user:profile"},
			requiredScopes: []string{"files:read", "files:write"},
			want:           true,
		},
		{
			name:           "token missing one required scope",
			tokenScopes:    []string{"files:read"},
			requiredScopes: []string{"files:read", "files:write"},
			want:           false,
		},
		{
			name:           "token missing all required scopes",
			tokenScopes:    []string{"user:profile"},
			requiredScopes: []string{"files:read", "files:write"},
			want:           false,
		},
		{
			name:           "no required scopes always passes",
			tokenScopes:    []string{},
			requiredScopes: []string{},
			want:           true,
		},
		{
			name:           "empty token scopes with required scopes fails",
			tokenScopes:    []string{},
			requiredScopes: []string{"files:read"},
			want:           false,
		},
		{
			name:           "token has extra scopes",
			tokenScopes:    []string{"files:read", "files:write", "admin:access"},
			requiredScopes: []string{"files:read"},
			want:           true,
		},
		{
			name:           "scope matching is case sensitive",
			tokenScopes:    []string{"Files:Read"},
			requiredScopes: []string{"files:read"},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRequiredScopes(tt.tokenScopes, tt.requiredScopes)
			if got != tt.want {
				t.Errorf("hasRequiredScopes() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestValidateTokenWithScopeValidation tests the ValidateToken middleware with scope validation
func TestValidateTokenWithScopeValidation(t *testing.T) {
	tests := []struct {
		name           string
		tokenScopes    []string
		requiredScopes []string
		wantStatus     int
		wantError      string
	}{
		{
			name:           "sufficient scopes",
			tokenScopes:    []string{"files:read", "files:write"},
			requiredScopes: []string{"files:read"},
			wantStatus:     http.StatusOK,
		},
		{
			name:           "insufficient scopes",
			tokenScopes:    []string{"files:read"},
			requiredScopes: []string{"files:read", "files:write"},
			wantStatus:     http.StatusForbidden,
			wantError:      ErrorCodeInsufficientScope,
		},
		{
			name:           "no token scopes with required scopes",
			tokenScopes:    []string{},
			requiredScopes: []string{"files:read"},
			wantStatus:     http.StatusForbidden,
			wantError:      ErrorCodeInsufficientScope,
		},
		{
			name:           "no required scopes",
			tokenScopes:    []string{"files:read"},
			requiredScopes: nil,
			wantStatus:     http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test store and server
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			// Configure endpoint scope requirements
			endpointScopes := map[string][]string{}
			if tt.requiredScopes != nil {
				endpointScopes["/protected"] = tt.requiredScopes
			}

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer:                    "https://example.com",
					EndpointScopeRequirements: endpointScopes,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Create handler
			handler := NewHandler(srv, nil)

			// Create a test token
			accessToken := "test_access_token"
			userID := testUserID

			// Store user info
			userInfo := &providers.UserInfo{
				ID:            userID,
				Email:         "test@example.com",
				EmailVerified: true,
			}
			if err := store.SaveUserInfo(context.Background(), userID, userInfo); err != nil {
				t.Fatalf("Failed to save user info: %v", err)
			}

			// Store token
			providerToken := &oauth2.Token{
				AccessToken: accessToken,
				Expiry:      time.Now().Add(1 * time.Hour),
			}
			if err := store.SaveToken(context.Background(), accessToken, providerToken); err != nil {
				t.Fatalf("Failed to save token: %v", err)
			}

			// Store token metadata with scopes
			if err := store.SaveTokenMetadataWithScopesAndAudience(accessToken, userID, "test_client", "access", "", tt.tokenScopes); err != nil {
				t.Fatalf("Failed to save token metadata: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)

			// Create response recorder
			w := httptest.NewRecorder()

			// Create a test handler that the middleware wraps
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("success"))
			})

			// Apply middleware
			middleware := handler.ValidateToken(nextHandler)
			middleware.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.wantStatus)
			}

			// If expecting an error, check the response
			if tt.wantStatus == http.StatusForbidden {
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				if body["error"] != tt.wantError {
					t.Errorf("Error code = %s, want %s", body["error"], tt.wantError)
				}

				// Verify WWW-Authenticate header
				wwwAuth := w.Header().Get("WWW-Authenticate")
				if !strings.Contains(wwwAuth, ErrorCodeInsufficientScope) {
					t.Errorf("WWW-Authenticate header missing insufficient_scope: %s", wwwAuth)
				}
			}
		})
	}
}

// TestValidateTokenWithoutScopeMetadata tests that tokens without scope metadata are handled gracefully
func TestValidateTokenWithoutScopeMetadata(t *testing.T) {
	// Create test store and server
	store := memory.New()
	defer store.Stop()
	mockProvider := mock.NewProvider()

	// Configure endpoint to require scopes
	srv, err := server.New(
		mockProvider,
		store,
		store,
		store,
		&server.Config{
			Issuer: "https://example.com",
			EndpointScopeRequirements: map[string][]string{
				"/protected": {"files:read"},
			},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := NewHandler(srv, nil)

	// Create a test token WITHOUT metadata
	accessToken := "test_access_token_no_metadata"
	userID := "test_user"

	// Store user info
	userInfo := &providers.UserInfo{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: true,
	}
	if err := store.SaveUserInfo(context.Background(), userID, userInfo); err != nil {
		t.Fatalf("Failed to save user info: %v", err)
	}

	// Store token but NOT metadata (simulates old tokens)
	providerToken := &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := store.SaveToken(context.Background(), accessToken, providerToken); err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	// Create next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Apply middleware
	middleware := handler.ValidateToken(nextHandler)
	middleware.ServeHTTP(w, req)

	// Should return 403 since token has no scopes but endpoint requires them
	if w.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusForbidden)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if body["error"] != ErrorCodeInsufficientScope {
		t.Errorf("Error code = %s, want %s", body["error"], ErrorCodeInsufficientScope)
	}
}

// TestTokenMetadataWithScopes tests that token metadata correctly stores and retrieves scopes
func TestTokenMetadataWithScopes(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	tokenID := "test_token_123"
	userID := "user_123"
	clientID := "client_123"
	audience := "https://example.com"
	scopes := []string{"files:read", "files:write", "user:profile"}

	// Save token metadata with scopes
	err := store.SaveTokenMetadataWithScopesAndAudience(tokenID, userID, clientID, "access", audience, scopes)
	if err != nil {
		t.Fatalf("Failed to save token metadata: %v", err)
	}

	// Retrieve token metadata
	metadata, err := store.GetTokenMetadata(tokenID)
	if err != nil {
		t.Fatalf("Failed to get token metadata: %v", err)
	}

	// Verify all fields
	if metadata.UserID != userID {
		t.Errorf("UserID = %s, want %s", metadata.UserID, userID)
	}
	if metadata.ClientID != clientID {
		t.Errorf("ClientID = %s, want %s", metadata.ClientID, clientID)
	}
	if metadata.TokenType != "access" {
		t.Errorf("TokenType = %s, want access", metadata.TokenType)
	}
	if metadata.Audience != audience {
		t.Errorf("Audience = %s, want %s", metadata.Audience, audience)
	}

	// Verify scopes
	if len(metadata.Scopes) != len(scopes) {
		t.Errorf("Scopes length = %d, want %d", len(metadata.Scopes), len(scopes))
	}
	for i, scope := range metadata.Scopes {
		if scope != scopes[i] {
			t.Errorf("Scope[%d] = %s, want %s", i, scope, scopes[i])
		}
	}
}

// TestGetRequiredScopesPathNormalization tests path normalization to prevent traversal attacks
func TestGetRequiredScopesPathNormalization(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string][]string
		requestPath string
		wantScopes  []string
		wantNil     bool
	}{
		{
			name: "double slashes normalized",
			config: map[string][]string{
				"/api/files": {"files:read"},
			},
			requestPath: "/api//files",
			wantScopes:  []string{"files:read"},
		},
		{
			name: "path traversal blocked",
			config: map[string][]string{
				"/api/admin": {"admin:access"},
			},
			requestPath: "/api/files/../admin",
			wantScopes:  []string{"admin:access"},
		},
		{
			name: "relative path normalized",
			config: map[string][]string{
				"/api/files": {"files:read"},
			},
			requestPath: "/api/./files",
			wantScopes:  []string{"files:read"},
		},
		{
			name: "multiple slashes normalized",
			config: map[string][]string{
				"/api/files/*": {"files:read", "files:write"},
			},
			requestPath: "//api///files//document.txt",
			wantScopes:  []string{"files:read", "files:write"},
		},
		{
			name: "traversal cannot bypass prefix match",
			config: map[string][]string{
				"/api/files/*": {"files:read"},
			},
			requestPath: "/api/files/../admin/users",
			wantNil:     true, // Normalizes to /api/admin/users which doesn't match /api/files/*
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer:                    "https://example.com",
					EndpointScopeRequirements: tt.config,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			scopes := handler.getRequiredScopes(req)

			if tt.wantNil {
				if scopes != nil {
					t.Errorf("Expected nil scopes, got %v", scopes)
				}
			} else {
				if len(scopes) != len(tt.wantScopes) {
					t.Errorf("Scopes length = %d, want %d", len(scopes), len(tt.wantScopes))
				}
				for i, scope := range scopes {
					if scope != tt.wantScopes[i] {
						t.Errorf("Scope[%d] = %s, want %s", i, scope, tt.wantScopes[i])
					}
				}
			}
		})
	}
}

// TestGetRequiredScopesLongestPrefixMatch tests that longest prefix wins when multiple patterns match
func TestGetRequiredScopesLongestPrefixMatch(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string][]string
		requestPath string
		wantScopes  []string
	}{
		{
			name: "longer prefix wins",
			config: map[string][]string{
				"/api/*":       {"api:access"},
				"/api/files/*": {"files:read", "files:write"},
			},
			requestPath: "/api/files/document.txt",
			wantScopes:  []string{"files:read", "files:write"},
		},
		{
			name: "shorter prefix if only match",
			config: map[string][]string{
				"/api/*": {"api:access"},
			},
			requestPath: "/api/files/document.txt",
			wantScopes:  []string{"api:access"},
		},
		{
			name: "exact match preferred over wildcard",
			config: map[string][]string{
				"/api/files":   {"files:exact"},
				"/api/files/*": {"files:wildcard"},
			},
			requestPath: "/api/files",
			wantScopes:  []string{"files:exact"},
		},
		{
			name: "three levels of wildcards",
			config: map[string][]string{
				"/api/*":             {"api:access"},
				"/api/files/*":       {"files:read"},
				"/api/files/admin/*": {"admin:access"},
			},
			requestPath: "/api/files/admin/users",
			wantScopes:  []string{"admin:access"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer:                    "https://example.com",
					EndpointScopeRequirements: tt.config,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			scopes := handler.getRequiredScopes(req)

			if len(scopes) != len(tt.wantScopes) {
				t.Errorf("Scopes length = %d, want %d", len(scopes), len(tt.wantScopes))
			}
			for i, scope := range scopes {
				if scope != tt.wantScopes[i] {
					t.Errorf("Scope[%d] = %s, want %s", i, scope, tt.wantScopes[i])
				}
			}
		})
	}
}

// TestValidateTokenScopesLongPathSanitization tests that very long paths are truncated in error messages
func TestValidateTokenScopesLongPathSanitization(t *testing.T) {
	store := memory.New()
	defer store.Stop()
	mockProvider := mock.NewProvider()

	// Configure endpoint to require scopes
	srv, err := server.New(
		mockProvider,
		store,
		store,
		store,
		&server.Config{
			Issuer: "https://example.com",
			EndpointScopeRequirements: map[string][]string{
				"/*": {"files:read"},
			},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := NewHandler(srv, nil)

	// Create a test token with insufficient scopes
	accessToken := "test_access_token"
	userID := "test_user"

	// Store user info
	userInfo := &providers.UserInfo{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: true,
	}
	if err := store.SaveUserInfo(context.Background(), userID, userInfo); err != nil {
		t.Fatalf("Failed to save user info: %v", err)
	}

	// Store token
	providerToken := &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := store.SaveToken(context.Background(), accessToken, providerToken); err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Store token metadata with insufficient scopes
	if err := store.SaveTokenMetadataWithScopesAndAudience(accessToken, userID, "test_client", "access", "", []string{"files:write"}); err != nil {
		t.Fatalf("Failed to save token metadata: %v", err)
	}

	// Create a very long path (>100 chars)
	longPath := "/api/" + strings.Repeat("verylongpathsegment/", 10) + "file.txt"
	req := httptest.NewRequest(http.MethodGet, longPath, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()

	// Create next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Apply middleware
	middleware := handler.ValidateToken(nextHandler)
	middleware.ServeHTTP(w, req)

	// Should return 403
	if w.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusForbidden)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify error description is truncated
	description := body["error_description"]
	if len(description) > 150 { // 100 for path + some buffer for the message text
		t.Errorf("Error description too long (%d chars): %s", len(description), description)
	}

	// Verify it contains the ellipsis
	if !strings.Contains(description, "...") {
		t.Errorf("Error description should contain ellipsis for truncated path: %s", description)
	}
}

// TestGetRequiredScopesMethodBased tests HTTP method-based scope requirements
func TestGetRequiredScopesMethodBased(t *testing.T) {
	tests := []struct {
		name        string
		methodScope map[string]map[string][]string
		pathScope   map[string][]string
		requestPath string
		method      string
		wantScopes  []string
		wantNil     bool
	}{
		{
			name: "exact method match",
			methodScope: map[string]map[string][]string{
				"/api/files/*": {
					"GET":  {"files:read"},
					"POST": {"files:write"},
				},
			},
			requestPath: "/api/files/doc.txt",
			method:      "GET",
			wantScopes:  []string{"files:read"},
		},
		{
			name: "POST method match",
			methodScope: map[string]map[string][]string{
				"/api/files/*": {
					"GET":  {"files:read"},
					"POST": {"files:write"},
				},
			},
			requestPath: "/api/files/doc.txt",
			method:      "POST",
			wantScopes:  []string{"files:write"},
		},
		{
			name: "wildcard method fallback",
			methodScope: map[string]map[string][]string{
				"/api/files/*": {
					"GET": {"files:read"},
					"*":   {"files:read"}, // fallback for other methods
				},
			},
			requestPath: "/api/files/doc.txt",
			method:      "DELETE",
			wantScopes:  []string{"files:read"},
		},
		{
			name: "method scope takes precedence over path scope",
			methodScope: map[string]map[string][]string{
				"/api/files/*": {
					"GET": {"files:read:method"},
				},
			},
			pathScope: map[string][]string{
				"/api/files/*": {"files:read:path"},
			},
			requestPath: "/api/files/doc.txt",
			method:      "GET",
			wantScopes:  []string{"files:read:method"},
		},
		{
			name: "falls back to path scope when method not matched",
			methodScope: map[string]map[string][]string{
				"/api/files/*": {
					"GET": {"files:read"},
				},
			},
			pathScope: map[string][]string{
				"/api/files/*": {"files:general"},
			},
			requestPath: "/api/files/doc.txt",
			method:      "DELETE",
			wantScopes:  []string{"files:general"},
		},
		{
			name: "no match returns nil",
			methodScope: map[string]map[string][]string{
				"/api/admin/*": {
					"GET": {"admin:read"},
				},
			},
			requestPath: "/api/files/doc.txt",
			method:      "GET",
			wantNil:     true,
		},
		{
			name: "exact path with method match",
			methodScope: map[string]map[string][]string{
				"/api/user/profile": {
					"GET": {"user:read"},
					"PUT": {"user:write"},
				},
			},
			requestPath: "/api/user/profile",
			method:      "PUT",
			wantScopes:  []string{"user:write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer:                          "https://example.com",
					EndpointScopeRequirements:       tt.pathScope,
					EndpointMethodScopeRequirements: tt.methodScope,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			req := httptest.NewRequest(tt.method, tt.requestPath, nil)
			scopes := handler.getRequiredScopes(req)

			if tt.wantNil {
				if scopes != nil {
					t.Errorf("Expected nil scopes, got %v", scopes)
				}
			} else {
				if len(scopes) != len(tt.wantScopes) {
					t.Errorf("Scopes length = %d, want %d", len(scopes), len(tt.wantScopes))
				}
				for i, scope := range scopes {
					if scope != tt.wantScopes[i] {
						t.Errorf("Scope[%d] = %s, want %s", i, scope, tt.wantScopes[i])
					}
				}
			}
		})
	}
}

// TestHideEndpointPathInErrors tests that endpoint paths can be hidden in error messages
func TestHideEndpointPathInErrors(t *testing.T) {
	tests := []struct {
		name             string
		hideEndpointPath bool
		wantPathInError  bool
	}{
		{
			name:             "path shown by default",
			hideEndpointPath: false,
			wantPathInError:  true,
		},
		{
			name:             "path hidden when configured",
			hideEndpointPath: true,
			wantPathInError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()
			mockProvider := mock.NewProvider()

			srv, err := server.New(
				mockProvider,
				store,
				store,
				store,
				&server.Config{
					Issuer: "https://example.com",
					EndpointScopeRequirements: map[string][]string{
						"/protected": {"files:read"},
					},
					HideEndpointPathInErrors: tt.hideEndpointPath,
				},
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			handler := NewHandler(srv, nil)

			// Create test token with insufficient scopes
			accessToken := "test_token_hide_path"
			userID := testUserID

			userInfo := &providers.UserInfo{
				ID:            userID,
				Email:         "test@example.com",
				EmailVerified: true,
			}
			if err := store.SaveUserInfo(context.Background(), userID, userInfo); err != nil {
				t.Fatalf("Failed to save user info: %v", err)
			}

			providerToken := &oauth2.Token{
				AccessToken: accessToken,
				Expiry:      time.Now().Add(1 * time.Hour),
			}
			if err := store.SaveToken(context.Background(), accessToken, providerToken); err != nil {
				t.Fatalf("Failed to save token: %v", err)
			}

			if err := store.SaveTokenMetadataWithScopesAndAudience(accessToken, userID, "test_client", "access", "", []string{}); err != nil {
				t.Fatalf("Failed to save token metadata: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)

			w := httptest.NewRecorder()

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := handler.ValidateToken(nextHandler)
			middleware.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Status = %d, want %d", w.Code, http.StatusForbidden)
			}

			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			description := body["error_description"]
			containsPath := strings.Contains(description, "/protected")

			if tt.wantPathInError && !containsPath {
				t.Errorf("Expected path in error description but not found: %s", description)
			}
			if !tt.wantPathInError && containsPath {
				t.Errorf("Expected path NOT in error description but found: %s", description)
			}

			// When hidden, should use generic message
			if !tt.wantPathInError {
				if !strings.Contains(description, "this endpoint") {
					t.Errorf("Expected generic message with 'this endpoint': %s", description)
				}
			}
		})
	}
}
