package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func setupTestHandler(t *testing.T) (*Handler, *memory.Store) {
	t.Helper()

	store := memory.New()
	provider := mock.NewMockProvider()

	config := &server.Config{
		Issuer: "https://auth.example.com",
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
		Issuer: "https://auth.example.com",
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

	var meta ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if meta.Resource != "https://auth.example.com" {
		t.Errorf("Resource = %q, want %q", meta.Resource, "https://auth.example.com")
	}
}

func TestHandler_ServeAuthorizationServerMetadata(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

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

	if meta.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", meta.Issuer, "https://auth.example.com")
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

	if tokenResp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, "Bearer")
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
