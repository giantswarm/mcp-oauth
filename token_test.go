package oauth

import (
	"context"
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
	"github.com/giantswarm/mcp-oauth/storage"
)

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

	if tokenResp.TokenType != tokenTypeBearer {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, tokenTypeBearer)
	}
}

// TestHandler_writeTokenResponse_WithIDToken verifies that the id_token from the upstream
// provider is correctly forwarded in the token response per OpenID Connect Core 1.0 Section 3.1.3.3.
func TestHandler_writeTokenResponse_WithIDToken(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Create a token with id_token in the Extra field (simulating upstream provider response)
	baseToken := testutil.GenerateTestToken()
	testIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.signature" //nolint:gosec // test value
	tokenWithIDToken := baseToken.WithExtra(map[string]interface{}{
		"id_token": testIDToken,
	})

	w := httptest.NewRecorder()
	handler.writeTokenResponse(w, tokenWithIDToken, "openid email")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken != tokenWithIDToken.AccessToken {
		t.Errorf("AccessToken = %q, want %q", tokenResp.AccessToken, tokenWithIDToken.AccessToken)
	}

	if tokenResp.TokenType != tokenTypeBearer {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, tokenTypeBearer)
	}

	// Verify id_token is included in response (OIDC compliance)
	if tokenResp.IDToken != testIDToken {
		t.Errorf("IDToken = %q, want %q", tokenResp.IDToken, testIDToken)
	}
}

// TestHandler_writeTokenResponse_WithoutIDToken verifies that the response is valid
// when there is no id_token (non-OIDC flows or providers that don't return id_token).
func TestHandler_writeTokenResponse_WithoutIDToken(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Create a token without id_token
	token := testutil.GenerateTestToken()

	w := httptest.NewRecorder()
	handler.writeTokenResponse(w, token, "openid email")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	// Verify id_token is empty when not provided
	if tokenResp.IDToken != "" {
		t.Errorf("IDToken = %q, want empty string", tokenResp.IDToken)
	}

	// Verify other fields are still correct
	if tokenResp.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", tokenResp.AccessToken, token.AccessToken)
	}

	if tokenResp.Scope != "openid email" {
		t.Errorf("Scope = %q, want %q", tokenResp.Scope, "openid email")
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

func TestHandler_ServeToken_AuthorizationCode(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		ctx,
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

	if tokenResp.TokenType != tokenTypeBearer {
		t.Errorf("TokenType = %q, want %q", tokenResp.TokenType, tokenTypeBearer)
	}
}

func TestHandler_ServeToken_AuthorizationCode_BasicAuthAndFormClientIDMismatch_Rejected(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, secret, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"",
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
	formData.Set("code", "any-code")
	formData.Set("redirect_uri", "https://example.com/callback")
	formData.Set("client_id", "form-value-does-not-match")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrorCodeInvalidClient {
		t.Errorf("error = %q, want %q", errResp.Error, ErrorCodeInvalidClient)
	}
	if !strings.Contains(errResp.ErrorDescription, "does not match") {
		t.Errorf("error_description = %q, want it to contain %q", errResp.ErrorDescription, "does not match")
	}
}

func TestHandler_ServeToken_AuthorizationCode_UnknownBasicAuthClient(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", "any-code")
	formData.Set("redirect_uri", "https://example.com/callback")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-that-was-never-registered", "any-secret")
	w := httptest.NewRecorder()

	handler.ServeToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrorCodeInvalidClient {
		t.Errorf("error = %q, want %q", errResp.Error, ErrorCodeInvalidClient)
	}
}

func TestHandler_ServeToken_InvalidClient(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, _, err := handler.server.RegisterClient(
		ctx,
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

	client, secret, err := handler.server.RegisterClient(
		ctx,
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
