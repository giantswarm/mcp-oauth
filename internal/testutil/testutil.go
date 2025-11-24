// Package testutil provides testing utilities and helpers for the mcp-oauth library.
package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// MockTime provides a controllable time source for deterministic testing
type MockTime struct {
	now time.Time
}

// NewMockTime creates a new mock time provider
func NewMockTime(t time.Time) *MockTime {
	return &MockTime{now: t}
}

// Now returns the current mock time
func (m *MockTime) Now() time.Time {
	return m.now
}

// Advance moves the mock time forward by the given duration
func (m *MockTime) Advance(d time.Duration) {
	m.now = m.now.Add(d)
}

// Set sets the mock time to a specific value
func (m *MockTime) Set(t time.Time) {
	m.now = t
}

// NewMockHTTPServer creates a test HTTP server with the given handler
func NewMockHTTPServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// NewMockHTTPSServer creates a test HTTPS server with the given handler
func NewMockHTTPSServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewTLSServer(handler)
}

// GenerateTestToken creates a test OAuth2 token
func GenerateTestToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  GenerateRandomString(32),
		TokenType:    "Bearer",
		RefreshToken: GenerateRandomString(32),
		Expiry:       time.Now().Add(1 * time.Hour),
	}
}

// GenerateTestTokenWithExpiry creates a test OAuth2 token with specific expiry
func GenerateTestTokenWithExpiry(expiry time.Time) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  GenerateRandomString(32),
		TokenType:    "Bearer",
		RefreshToken: GenerateRandomString(32),
		Expiry:       expiry,
	}
}

// GenerateTestUserInfo creates test user information
func GenerateTestUserInfo() *providers.UserInfo {
	return &providers.UserInfo{
		ID:            "test-user-123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		GivenName:     "Test",
		FamilyName:    "User",
		Picture:       "https://example.com/photo.jpg",
		Locale:        "en",
	}
}

// GenerateTestClient creates a test OAuth client
func GenerateTestClient() *storage.Client {
	return &storage.Client{
		ClientID:                "test-client-id",
		ClientSecretHash:        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // hash of "secret"
		ClientType:              "confidential",
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		Scopes:                  []string{"openid", "email", "profile"},
		CreatedAt:               time.Now(),
	}
}

// GenerateTestAuthorizationState creates a test authorization state
func GenerateTestAuthorizationState() *storage.AuthorizationState {
	return &storage.AuthorizationState{
		StateID:             GenerateRandomString(32),
		ClientID:            "test-client-id",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email profile",
		CodeChallenge:       "test-code-challenge",
		CodeChallengeMethod: "S256",
		ProviderState:       GenerateRandomString(32),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
}

// GenerateTestAuthorizationCode creates a test authorization code
func GenerateTestAuthorizationCode() *storage.AuthorizationCode {
	return &storage.AuthorizationCode{
		Code:                GenerateRandomString(32),
		ClientID:            "test-client-id",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email profile",
		CodeChallenge:       "test-code-challenge",
		CodeChallengeMethod: "S256",
		UserID:              "test-user-123",
		ProviderToken:       GenerateTestToken(),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
}

// GenerateRandomString generates a random base64-encoded string
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random string: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// GeneratePKCEPair generates a valid PKCE challenge and verifier pair for testing.
// Returns (challenge, verifier) where challenge is the S256 hash of the verifier.
// This is a convenience helper to reduce code duplication in PKCE tests.
func GeneratePKCEPair() (challenge, verifier string) {
	verifier = GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return challenge, verifier
}

// AssertNoError fails the test if err is not nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError fails the test if err is nil
func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// AssertEqual fails the test if got != want
func AssertEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// AssertNotEqual fails the test if got == want
func AssertNotEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got == want {
		t.Errorf("got %v, want different value", got)
	}
}

// AssertStringContains fails the test if s does not contain substr
func AssertStringContains(t *testing.T, s, substr string) {
	t.Helper()
	if len(s) == 0 {
		t.Errorf("string is empty, expected to contain %q", substr)
		return
	}
	found := false
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("string %q does not contain %q", s, substr)
	}
}

// AssertTrue fails the test if condition is false
func AssertTrue(t *testing.T, condition bool, message string) {
	t.Helper()
	if !condition {
		t.Errorf("assertion failed: %s", message)
	}
}

// AssertFalse fails the test if condition is true
func AssertFalse(t *testing.T, condition bool, message string) {
	t.Helper()
	if condition {
		t.Errorf("assertion failed: %s", message)
	}
}

// AssertNil fails the test if v is not nil
func AssertNil(t *testing.T, v interface{}) {
	t.Helper()
	if v != nil {
		t.Errorf("expected nil but got %v", v)
	}
}

// AssertNotNil fails the test if v is nil
func AssertNotNil(t *testing.T, v interface{}) {
	t.Helper()
	if v == nil {
		t.Error("expected non-nil value but got nil")
	}
}

// AssertTimeEqual asserts two times are equal within a tolerance
func AssertTimeEqual(t *testing.T, got, want time.Time, tolerance time.Duration) {
	t.Helper()
	diff := got.Sub(want)
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("time mismatch: got %v, want %v (tolerance: %v, diff: %v)", got, want, tolerance, diff)
	}
}

// HTTPRequest is a helper for making test HTTP requests
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// NewHTTPRequest creates a new HTTP request helper
func NewHTTPRequest(method, url string) *HTTPRequest {
	return &HTTPRequest{
		Method:  method,
		URL:     url,
		Headers: make(map[string]string),
	}
}

// WithHeader adds a header to the request
func (r *HTTPRequest) WithHeader(key, value string) *HTTPRequest {
	r.Headers[key] = value
	return r
}

// WithBody sets the request body
func (r *HTTPRequest) WithBody(body string) *HTTPRequest {
	r.Body = body
	return r
}

// Do executes the HTTP request
func (r *HTTPRequest) Do(handler http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(r.Method, r.URL, nil)
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}
