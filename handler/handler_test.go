package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	testClientRemoteAddr        = "192.168.1.100:12345"
	testOriginApp               = "https://app.example.com"
	testIssuer                  = "https://auth.example.com"
	testResourceMetadataURL     = `resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"`
	testResourceMetadataURLFull = "https://auth.example.com/.well-known/oauth-protected-resource"
)

func setupTestHandler(t *testing.T) (*Handler, *memory.Store) {
	t.Helper()
	return setupTestHandlerWithConfig(t, nil)
}

func setupTestHandlerWithOpts(t *testing.T, opts ...server.Option) (*Handler, *memory.Store) {
	t.Helper()
	return setupTestHandlerWithConfig(t, nil, opts...)
}

func setupTestHandlerWithConfig(t *testing.T, cfgFn func(*server.Config), opts ...server.Option) (*Handler, *memory.Store) {
	t.Helper()

	store := memory.New()
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer: testIssuer,
		// Mock provider returns no id_token; nonce echo is exercised in
		// flows_nonce_test.go with its own fixture.
		DisableNonceEchoRequirement: true,
	}
	if cfgFn != nil {
		cfgFn(config)
	}

	srv, err := server.New(provider, store, store, store, config, nil, opts...)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	return New(srv, config, nil), store
}

// decodeProtectedResourceMetadata decodes Protected Resource Metadata from the response body
func decodeProtectedResourceMetadata(t *testing.T, w *httptest.ResponseRecorder) *oauth.ProtectedResourceMetadata {
	t.Helper()
	var meta oauth.ProtectedResourceMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode Protected Resource Metadata: %v", err)
	}
	return &meta
}

func setupTestHandlerWithCORS(t *testing.T, allowedOrigins []string) (*Handler, *memory.Store) {
	t.Helper()
	return setupTestHandlerWithConfig(t, func(c *server.Config) {
		c.CORS = server.CORSConfig{
			AllowedOrigins:   allowedOrigins,
			AllowCredentials: true,
			MaxAge:           3600,
		}
	})
}

func TestNewHandler(t *testing.T) {
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

	handler := New(srv, config, nil)
	if handler == nil {
		t.Fatal("NewHandler() returned nil")
	}

	if handler.logger == nil {
		t.Error("logger should not be nil")
	}
}

func setupUserInfoTest(t *testing.T, scopes []string) (*Handler, *memory.Store, string) {
	t.Helper()
	store := memory.New()
	provider := mock.NewProvider()
	config := &server.Config{
		Issuer:                 "https://auth.example.com",
		EnableUserInfoEndpoint: true,
	}
	srv, err := server.New(provider, store, store, store, config, nil)
	require.NoError(t, err)

	const accessToken = "userinfo-access-token"
	require.NoError(t, store.SaveToken(context.Background(), accessToken, &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{
		UserID:    "mock-user-123",
		ClientID:  "test-client",
		TokenType: "access",
		Scopes:    scopes,
	}))

	return New(srv, config, nil), store, accessToken
}

func decodeUserInfoResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var claims map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&claims))
	return claims
}

func TestHandler_writeError(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	w := httptest.NewRecorder()

	handler.writeError(w, constants.ErrorCodeInvalidRequest, "test error", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp oauth.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != constants.ErrorCodeInvalidRequest {
		t.Errorf("Error = %q, want %q", errResp.Error, constants.ErrorCodeInvalidRequest)
	}

	if errResp.ErrorDescription != "test error" {
		t.Errorf("ErrorDescription = %q, want %q", errResp.ErrorDescription, "test error")
	}
}

func setupTestHandlerWithBodyLimit(t *testing.T, maxBodySize int64) (*Handler, *memory.Store) {
	t.Helper()
	return setupTestHandlerWithConfig(t, func(c *server.Config) {
		c.MaxRequestBodySize = maxBodySize
	})
}

func TestIsMaxBytesError(t *testing.T) {
	if isMaxBytesError(fmt.Errorf("generic error")) {
		t.Error("generic error should not be detected as MaxBytesError")
	}

	maxBytesErr := &http.MaxBytesError{Limit: 100}
	if !isMaxBytesError(maxBytesErr) {
		t.Error("MaxBytesError should be detected")
	}

	wrapped := fmt.Errorf("wrapped: %w", maxBytesErr)
	if !isMaxBytesError(wrapped) {
		t.Error("wrapped MaxBytesError should be detected")
	}
}

func setupTestHandlerWithAllowNoState(t *testing.T) (*Handler, *memory.Store) {
	t.Helper()
	return setupTestHandlerWithConfig(t, func(c *server.Config) {
		c.AllowNoStateParameter = true
	})
}

func assertAuthorizationErrorRedirect(t *testing.T, w *httptest.ResponseRecorder, expectedRedirect, expectedErrorCode, expectedErrorDescriptionSubstr, expectedState string) {
	t.Helper()

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
		return
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("Location header missing on error redirect")
	}

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Location header is not a valid URL: %v", err)
	}

	expected, err := url.Parse(expectedRedirect)
	if err != nil {
		t.Fatalf("expectedRedirect not parseable: %v", err)
	}
	if parsed.Scheme != expected.Scheme || parsed.Host != expected.Host || parsed.Path != expected.Path {
		t.Errorf("redirect target = %s://%s%s, want %s://%s%s",
			parsed.Scheme, parsed.Host, parsed.Path,
			expected.Scheme, expected.Host, expected.Path)
	}

	q := parsed.Query()
	if got := q.Get("error"); got != expectedErrorCode {
		t.Errorf("error query param = %q, want %q", got, expectedErrorCode)
	}
	if got := q.Get("error_description"); got == "" {
		t.Errorf("error_description query param missing")
	} else if expectedErrorDescriptionSubstr != "" && !strings.Contains(got, expectedErrorDescriptionSubstr) {
		t.Errorf("error_description = %q, want substring %q", got, expectedErrorDescriptionSubstr)
	}
	if got := q.Get("state"); got != expectedState {
		t.Errorf("state query param = %q, want %q", got, expectedState)
	}
}

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

func seedOpaqueIntrospectionToken(t *testing.T, store *memory.Store, accessToken, userID, clientID, audience string, scopes []string, expiresAt time.Time) time.Time {
	t.Helper()
	ctx := t.Context()
	issuedAt := time.Now().Truncate(time.Second)
	providerToken := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      expiresAt,
	}
	if err := store.SaveToken(ctx, accessToken, providerToken); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		TokenType: "access",
		Audience:  audience,
		Scopes:    scopes,
	}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	return issuedAt
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}
