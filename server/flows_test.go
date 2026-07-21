package server

import (
	"context"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	testUserID    = "user-123"
	testUserEmail = "test@example.com"
	testUserName  = "Test User"
	// testPKCEVerifierLength is the length used for PKCE verifiers in tests
	// PKCE spec (RFC 7636) requires verifiers to be 43-128 characters
	testPKCEVerifierLength = 50

	testMockUserID = "mock-user-123"
)

// setupFlowTestServer builds the standard flow-test fixture: a Server backed
// by a fresh in-memory store and mock provider. Extra Options (e.g.
// WithTokenRefreshHandler) are passed through to New.
func setupFlowTestServer(t *testing.T, opts ...Option) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		ClockSkewGracePeriod: 5,
		// Mock provider returns no id_token; nonce echo is exercised in
		// nonce_test.go with its own fixture.
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, config, nil, opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv, store, provider
}

// setupValidTokenProvider returns a provider function that always validates tokens successfully
func setupValidTokenProvider() func(context.Context, string) (*providers.UserInfo, error) {
	return func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user-123",
			Email: "test@example.com",
			Name:  "Test User",
		}, nil
	}
}

// setupFlowTestServerWithNoStateParameter creates a test server with AllowNoStateParameter=true
func setupFlowTestServerWithNoStateParameter(t *testing.T) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		AllowPKCEPlain:              false,
		AllowNoStateParameter:       true,
		ClockSkewGracePeriod:        5,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv, store, provider
}

// TestPreserveRefreshToken tests the preserveRefreshToken helper function.
func TestPreserveRefreshToken(t *testing.T) {
	t.Run("new token has refresh token - use new", func(t *testing.T) {
		newToken := &oauth2.Token{AccessToken: "at", RefreshToken: "new-rt"}
		result := preserveRefreshToken(newToken, "old-rt")
		if result.RefreshToken != "new-rt" {
			t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "new-rt")
		}
	})

	t.Run("new token missing refresh token - preserve old", func(t *testing.T) {
		newToken := &oauth2.Token{AccessToken: "at"}
		result := preserveRefreshToken(newToken, "old-rt")
		if result.RefreshToken != "old-rt" {
			t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "old-rt")
		}
	})

	t.Run("new token missing refresh token and no old - stay empty", func(t *testing.T) {
		newToken := &oauth2.Token{AccessToken: "at"}
		result := preserveRefreshToken(newToken, "")
		if result.RefreshToken != "" {
			t.Errorf("RefreshToken = %q, want empty", result.RefreshToken)
		}
	})

	t.Run("nil token - returns nil", func(t *testing.T) {
		result := preserveRefreshToken(nil, "old-rt")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})
}

// TestCapTokenExpiry tests the capTokenExpiry helper function.
func TestCapTokenExpiry(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	srv.Config.AccessTokenTTL = 3600

	t.Run("provider expires sooner - caps to provider", func(t *testing.T) {
		now := time.Now()
		providerExpiry := now.Add(10 * time.Minute)
		expiry := srv.capTokenExpiry(now, providerExpiry)
		diff := expiry.Sub(providerExpiry).Abs()
		if diff > 2*time.Second {
			t.Errorf("expiry = %v, want close to %v (diff: %v)", expiry, providerExpiry, diff)
		}
	})

	t.Run("provider expires later - uses AccessTokenTTL", func(t *testing.T) {
		now := time.Now()
		providerExpiry := now.Add(2 * time.Hour)
		expiry := srv.capTokenExpiry(now, providerExpiry)
		expected := now.Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		diff := expiry.Sub(expected).Abs()
		if diff > 2*time.Second {
			t.Errorf("expiry = %v, want close to %v (diff: %v)", expiry, expected, diff)
		}
	})

	t.Run("provider expiry in the past - uses AccessTokenTTL", func(t *testing.T) {
		now := time.Now()
		providerExpiry := now.Add(-30 * time.Second)
		expiry := srv.capTokenExpiry(now, providerExpiry)
		if expiry.Before(now) {
			t.Errorf("expiry = %v, must not be in the past", expiry)
		}
		expected := now.Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		diff := expiry.Sub(expected).Abs()
		if diff > 2*time.Second {
			t.Errorf("expiry = %v, want close to %v (diff: %v)", expiry, expected, diff)
		}
	})

	t.Run("zero expiry - uses AccessTokenTTL", func(t *testing.T) {
		now := time.Now()
		expiry := srv.capTokenExpiry(now, time.Time{})
		expected := now.Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		diff := expiry.Sub(expected).Abs()
		if diff > 2*time.Second {
			t.Errorf("expiry = %v, want close to %v (diff: %v)", expiry, expected, diff)
		}
	})
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}
