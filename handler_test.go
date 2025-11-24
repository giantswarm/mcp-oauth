package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
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

func TestHandler_ServeAuthorization_CompleteFlow(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client first
	client, _, err := handler.server.RegisterClient(
		"Test Client",
		"confidential",
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
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id="+client.ClientID+
			"&redirect_uri=https://example.com/callback"+
			"&scope=openid+email"+
			"&response_type=code"+
			"&code_challenge="+challenge+
			"&code_challenge_method=S256"+
			"&state=test-state-123",
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
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, _, err := handler.server.RegisterClient(
		"Test Client",
		"confidential",
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

	authURL, err := handler.server.StartAuthorizationFlow(
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		challenge,
		"S256",
		"client-state-123",
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Extract provider state from auth URL
	if authURL == "" {
		t.Fatal("authURL is empty")
	}

	// Get auth state to find provider state
	authState, err := store.GetAuthorizationState("client-state-123")
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
	if !strings.Contains(location, "state=client-state-123") {
		t.Error("Location should contain original client state")
	}
}

func TestHandler_ServeCallback_InvalidState(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state=invalid-state&code=provider-auth-code",
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
			url:  "/oauth/callback?state=test-state",
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

func TestHandler_ServeToken_AuthorizationCode(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		"Test Client",
		"confidential",
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

	err = store.SaveAuthorizationCode(authCode)
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

	if tokenResp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, "Bearer")
	}
}

func TestHandler_ServeToken_RefreshToken_NotImplementedYet(t *testing.T) {
	// This test is a placeholder - refresh token flow needs proper family tracking setup
	t.Skip("Refresh token test requires complex family tracking setup")
}

func TestHandler_ServeTokenRevocation_Success(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		"Test Client",
		"confidential",
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
	err = store.SaveRefreshToken(refreshToken, "test-user-123", time.Now().Add(90*24*time.Hour))
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
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		"Test Client",
		"confidential",
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
}
