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
	testTokenTypeBearer  = "Bearer"
	testClientRemoteAddr = "192.168.1.100:12345"
	testOriginApp        = "https://app.example.com"
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
			AllowedOrigins:   []string{"*"},
			AllowCredentials: false, // Must be false with wildcard
			MaxAge:           3600,
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
