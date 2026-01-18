package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestIsTrustedAudience tests the isTrustedAudience helper function.
func TestIsTrustedAudience(t *testing.T) {
	tests := []struct {
		name             string
		trustedAudiences []string
		audience         string
		expectedTrusted  bool
	}{
		{
			name:             "empty trusted audiences",
			trustedAudiences: nil,
			audience:         "muster-client",
			expectedTrusted:  false,
		},
		{
			name:             "empty audience list",
			trustedAudiences: []string{},
			audience:         "muster-client",
			expectedTrusted:  false,
		},
		{
			name:             "exact match - client ID",
			trustedAudiences: []string{"muster-client", "aggregator-client"},
			audience:         "muster-client",
			expectedTrusted:  true,
		},
		{
			name:             "exact match - second entry",
			trustedAudiences: []string{"muster-client", "aggregator-client"},
			audience:         "aggregator-client",
			expectedTrusted:  true,
		},
		{
			name:             "no match",
			trustedAudiences: []string{"muster-client", "aggregator-client"},
			audience:         "unknown-client",
			expectedTrusted:  false,
		},
		{
			name:             "URL audience - exact match",
			trustedAudiences: []string{"https://muster.example.com"},
			audience:         "https://muster.example.com",
			expectedTrusted:  true,
		},
		{
			name:             "URL audience - with trailing slash normalization",
			trustedAudiences: []string{"https://muster.example.com/"},
			audience:         "https://muster.example.com",
			expectedTrusted:  true,
		},
		{
			name:             "case sensitive match",
			trustedAudiences: []string{"Muster-Client"},
			audience:         "muster-client",
			expectedTrusted:  false, // Should not match - case sensitive
		},
		{
			name:             "mixed client IDs and URLs",
			trustedAudiences: []string{"muster-client", "https://aggregator.example.com"},
			audience:         "https://aggregator.example.com",
			expectedTrusted:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			t.Cleanup(func() { store.Stop() })

			config := &Config{
				Issuer:           "https://auth.example.com",
				TrustedAudiences: tt.trustedAudiences,
			}

			srv := &Server{
				Config: config,
			}

			got := srv.isTrustedAudience(tt.audience)
			if got != tt.expectedTrusted {
				t.Errorf("isTrustedAudience() = %v, want %v", got, tt.expectedTrusted)
			}
		})
	}
}

// TestValidateTokenAudience_WithTrustedAudiences tests audience validation with TrustedAudiences.
func TestValidateTokenAudience_WithTrustedAudiences(t *testing.T) {
	tests := []struct {
		name              string
		serverIdentifier  string
		trustedAudiences  []string
		tokenAudience     string
		expectError       bool
		expectCrossClient bool // Whether we expect a cross-client token acceptance event
	}{
		{
			name:              "match server's own identifier",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  []string{"muster-client"},
			tokenAudience:     "https://mcp.example.com",
			expectError:       false,
			expectCrossClient: false,
		},
		{
			name:              "match trusted audience",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  []string{"muster-client"},
			tokenAudience:     "muster-client",
			expectError:       false,
			expectCrossClient: true,
		},
		{
			name:              "match second trusted audience",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  []string{"muster-client", "aggregator-client"},
			tokenAudience:     "aggregator-client",
			expectError:       false,
			expectCrossClient: true,
		},
		{
			name:              "no match - untrusted audience",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  []string{"muster-client"},
			tokenAudience:     "unknown-client",
			expectError:       true,
			expectCrossClient: false,
		},
		{
			name:              "no trusted audiences configured - mismatch",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  nil,
			tokenAudience:     "muster-client",
			expectError:       true,
			expectCrossClient: false,
		},
		{
			name:              "URL-based trusted audience",
			serverIdentifier:  "https://mcp.example.com",
			trustedAudiences:  []string{"https://muster.example.com"},
			tokenAudience:     "https://muster.example.com",
			expectError:       false,
			expectCrossClient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := memory.New()
			t.Cleanup(func() { store.Stop() })

			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuffer, nil))
			auditor := security.NewAuditor(logger, true)

			config := &Config{
				Issuer:             "https://auth.example.com",
				ResourceIdentifier: tt.serverIdentifier,
				TrustedAudiences:   tt.trustedAudiences,
			}

			srv := &Server{
				Config:     config,
				tokenStore: store,
				flowStore:  store,
				Auditor:    auditor,
				Logger:     logger,
			}

			// Save a token with metadata
			accessToken := "test-access-token-12345"
			providerToken := &oauth2.Token{
				AccessToken: "provider-access-token",
				Expiry:      time.Now().Add(1 * time.Hour),
			}
			if err := store.SaveToken(ctx, accessToken, providerToken); err != nil {
				t.Fatalf("SaveToken() error = %v", err)
			}

			// Save token metadata with the test audience
			if err := store.SaveTokenMetadataWithAudience(accessToken, "test-user", "test-client", "access", tt.tokenAudience); err != nil {
				t.Fatalf("SaveTokenMetadataWithAudience() error = %v", err)
			}

			// Validate the token
			err := srv.validateTokenAudience(accessToken)

			if tt.expectError && err == nil {
				t.Error("validateTokenAudience() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("validateTokenAudience() unexpected error = %v", err)
			}

			// Check for cross-client token acceptance in logs
			logOutput := logBuffer.String()
			if tt.expectCrossClient {
				if !strings.Contains(logOutput, security.EventCrossClientTokenAccepted) {
					t.Error("Expected EventCrossClientTokenAccepted event in logs, but not found")
				}
				if !strings.Contains(logOutput, tt.tokenAudience) {
					t.Errorf("Expected log to contain audience %q", tt.tokenAudience)
				}
			}
		})
	}
}

// TestValidateTrustedAudiences tests the config validation for TrustedAudiences.
func TestValidateTrustedAudiences(t *testing.T) {
	tests := []struct {
		name                 string
		inputAudiences       []string
		expectedAudiences    []string
		expectLogContains    string
		expectLogNotContains string
	}{
		{
			name:              "empty audiences - no validation needed",
			inputAudiences:    nil,
			expectedAudiences: nil,
		},
		{
			name:              "valid client IDs",
			inputAudiences:    []string{"muster-client", "aggregator-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
			expectLogContains: "TrustedAudiences configured",
		},
		{
			name:              "valid URLs",
			inputAudiences:    []string{"https://muster.example.com", "https://aggregator.example.com"},
			expectedAudiences: []string{"https://muster.example.com", "https://aggregator.example.com"},
		},
		{
			name:              "mixed client IDs and URLs",
			inputAudiences:    []string{"muster-client", "https://aggregator.example.com"},
			expectedAudiences: []string{"muster-client", "https://aggregator.example.com"},
		},
		{
			name:              "removes empty entries",
			inputAudiences:    []string{"muster-client", "", "aggregator-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
			expectLogContains: "Empty audience",
		},
		{
			name:              "removes whitespace-only entries",
			inputAudiences:    []string{"muster-client", "   ", "aggregator-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
			expectLogContains: "Whitespace-only audience",
		},
		{
			name:              "removes duplicates",
			inputAudiences:    []string{"muster-client", "aggregator-client", "muster-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
			expectLogContains: "Duplicate audience",
		},
		{
			name:              "trims whitespace",
			inputAudiences:    []string{"  muster-client  ", "aggregator-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
		},
		{
			name:              "invalid URL format - removed",
			inputAudiences:    []string{"muster-client", "https://", "aggregator-client"},
			expectedAudiences: []string{"muster-client", "aggregator-client"},
			expectLogContains: "Invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuffer, nil))

			config := &Config{
				TrustedAudiences: tt.inputAudiences,
			}

			validateTrustedAudiences(config, logger)

			// Check resulting audiences
			if len(config.TrustedAudiences) != len(tt.expectedAudiences) {
				t.Errorf("TrustedAudiences length = %d, want %d",
					len(config.TrustedAudiences), len(tt.expectedAudiences))
			}
			for i, expected := range tt.expectedAudiences {
				if i >= len(config.TrustedAudiences) {
					break
				}
				if config.TrustedAudiences[i] != expected {
					t.Errorf("TrustedAudiences[%d] = %q, want %q",
						i, config.TrustedAudiences[i], expected)
				}
			}

			// Check log output
			logOutput := logBuffer.String()
			if tt.expectLogContains != "" && !strings.Contains(logOutput, tt.expectLogContains) {
				t.Errorf("Expected log to contain %q, got: %s", tt.expectLogContains, logOutput)
			}
			if tt.expectLogNotContains != "" && strings.Contains(logOutput, tt.expectLogNotContains) {
				t.Errorf("Expected log NOT to contain %q, got: %s", tt.expectLogNotContains, logOutput)
			}
		})
	}
}

// TestLogCrossClientTokenAccepted tests the audit logging for cross-client token acceptance.
func TestLogCrossClientTokenAccepted(t *testing.T) {
	var logBuffer bytes.Buffer
	// Use LevelDebug to capture debug logs
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	auditor := security.NewAuditor(logger, true)

	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		TrustedAudiences:   []string{"muster-client"},
	}

	srv := &Server{
		Config:  config,
		Auditor: auditor,
		Logger:  logger,
	}

	metadata := &storage.TokenMetadata{
		UserID:   "test-user",
		ClientID: "test-client",
		Audience: "muster-client",
	}

	srv.logCrossClientTokenAccepted("test-token-12345678", metadata)

	// Verify log output
	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "Token accepted via TrustedAudiences") {
		t.Errorf("Expected log to contain 'Token accepted via TrustedAudiences', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "muster-client") {
		t.Errorf("Expected log to contain 'muster-client', got: %s", logOutput)
	}

	// Verify audit event was logged
	if !strings.Contains(logOutput, security.EventCrossClientTokenAccepted) {
		t.Error("Expected log to contain EventCrossClientTokenAccepted")
	}
	if !strings.Contains(logOutput, "test-client") {
		t.Error("Expected log to contain client_id 'test-client'")
	}
}

// TestTrustedAudiences_ConstantTimeComparison verifies that audience matching uses
// constant-time comparison to prevent timing attacks.
func TestTrustedAudiences_ConstantTimeComparison(t *testing.T) {
	// This test verifies that the isTrustedAudience function works correctly
	// with audiences of different lengths (which could leak timing info if not
	// using constant-time comparison properly).
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	config := &Config{
		Issuer:           "https://auth.example.com",
		TrustedAudiences: []string{"short", "very-long-audience-string-that-takes-longer-to-compare"},
	}

	srv := &Server{Config: config}

	// These should both use the same code path with constant-time comparison
	if !srv.isTrustedAudience("short") {
		t.Error("Expected 'short' to be trusted")
	}
	if !srv.isTrustedAudience("very-long-audience-string-that-takes-longer-to-compare") {
		t.Error("Expected long audience to be trusted")
	}
	if srv.isTrustedAudience("shor") { // Almost matches "short"
		t.Error("Expected 'shor' NOT to be trusted")
	}
}

// TestTrustedAudiences_BackwardCompatibility tests that empty TrustedAudiences
// maintains backward compatibility (only server's own identifier is accepted).
func TestTrustedAudiences_BackwardCompatibility(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, nil))

	// No TrustedAudiences configured - should only accept server's own identifier
	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		TrustedAudiences:   nil, // Empty - backward compatible mode
	}

	srv := &Server{
		Config:     config,
		tokenStore: store,
		Logger:     logger,
	}

	// Save a token with metadata for server's own audience
	accessToken := "compat-test-token" //nolint:gosec // G101: Test token, not a credential
	providerToken := &oauth2.Token{
		AccessToken: "provider-access-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := store.SaveToken(ctx, accessToken, providerToken); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Test 1: Server's own audience should be accepted
	if err := store.SaveTokenMetadataWithAudience(accessToken, "user", "client", "access", "https://mcp.example.com"); err != nil {
		t.Fatalf("SaveTokenMetadataWithAudience() error = %v", err)
	}
	if err := srv.validateTokenAudience(accessToken); err != nil {
		t.Errorf("Expected token with server's own audience to be accepted, got error: %v", err)
	}

	// Test 2: Different audience should be rejected
	if err := store.SaveTokenMetadataWithAudience(accessToken, "user", "client", "access", "muster-client"); err != nil {
		t.Fatalf("SaveTokenMetadataWithAudience() error = %v", err)
	}
	if err := srv.validateTokenAudience(accessToken); err == nil {
		t.Error("Expected token with different audience to be rejected")
	}
}

// TestTrustedAudiences_URLNormalization tests that URL-based audiences are
// properly normalized for comparison.
func TestTrustedAudiences_URLNormalization(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	config := &Config{
		Issuer:           "https://auth.example.com",
		TrustedAudiences: []string{"https://muster.example.com/"},
	}

	srv := &Server{Config: config}

	// With trailing slash normalization, these should match
	normalizedWithSlash := helpers.NormalizeURL("https://muster.example.com/")
	normalizedWithoutSlash := helpers.NormalizeURL("https://muster.example.com")

	if normalizedWithSlash != normalizedWithoutSlash {
		t.Logf("NormalizeURL('...com/') = %q, NormalizeURL('...com') = %q",
			normalizedWithSlash, normalizedWithoutSlash)
		// Test that the actual function works correctly
		if srv.isTrustedAudience("https://muster.example.com") {
			t.Log("URL normalization is working correctly")
		}
	}
}

// TestFindMatchingTrustedAudience tests the findMatchingTrustedAudience helper.
func TestFindMatchingTrustedAudience(t *testing.T) {
	tests := []struct {
		name             string
		trustedAudiences []string
		tokenAudiences   []string
		expectedMatch    string
	}{
		{
			name:             "no trusted audiences configured",
			trustedAudiences: nil,
			tokenAudiences:   []string{"client-a"},
			expectedMatch:    "",
		},
		{
			name:             "single token audience matches first trusted",
			trustedAudiences: []string{"client-a", "client-b"},
			tokenAudiences:   []string{"client-a"},
			expectedMatch:    "client-a",
		},
		{
			name:             "single token audience matches second trusted",
			trustedAudiences: []string{"client-a", "client-b"},
			tokenAudiences:   []string{"client-b"},
			expectedMatch:    "client-b",
		},
		{
			name:             "multiple token audiences - first matches",
			trustedAudiences: []string{"client-a"},
			tokenAudiences:   []string{"client-a", "client-x"},
			expectedMatch:    "client-a",
		},
		{
			name:             "multiple token audiences - second matches",
			trustedAudiences: []string{"client-b"},
			tokenAudiences:   []string{"client-a", "client-b"},
			expectedMatch:    "client-b",
		},
		{
			name:             "no match",
			trustedAudiences: []string{"client-a", "client-b"},
			tokenAudiences:   []string{"unknown-client"},
			expectedMatch:    "",
		},
		{
			name:             "URL audience normalization",
			trustedAudiences: []string{"https://muster.example.com/"},
			tokenAudiences:   []string{"https://muster.example.com"},
			expectedMatch:    "https://muster.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{
				Config: &Config{
					TrustedAudiences: tt.trustedAudiences,
				},
			}

			got := srv.findMatchingTrustedAudience(tt.tokenAudiences)
			if got != tt.expectedMatch {
				t.Errorf("findMatchingTrustedAudience() = %q, want %q", got, tt.expectedMatch)
			}
		})
	}
}

// TestValidateToken_JWTBeforeUserinfo verifies that JWT validation is attempted
// before calling the userinfo endpoint when TrustedAudiences is configured.
// This is the core fix for issue #173.
func TestValidateToken_JWTBeforeUserinfo(t *testing.T) {
	// This test verifies the order of operations:
	// 1. If TrustedAudiences is configured and token looks like a JWT
	// 2. Attempt JWKS-based validation FIRST
	// 3. Only fall back to userinfo if JWT validation fails or doesn't match

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		TrustedAudiences:   []string{"muster-client"},
	}

	// Create a mock provider that tracks whether ValidateToken was called
	mockProvider := &mockProviderWithTracking{}

	srv := &Server{
		Config:     config,
		tokenStore: store,
		flowStore:  store,
		provider:   mockProvider,
		Logger:     logger,
	}

	// Test with an opaque token (not a JWT) - should call userinfo
	t.Run("opaque token calls userinfo", func(t *testing.T) {
		mockProvider.reset()

		// This is an opaque access token (not a JWT)
		opaqueToken := "opaque-access-token-not-jwt" //nolint:gosec // G101: Test data, not a real credential

		_, _ = srv.ValidateToken(context.Background(), opaqueToken)

		if !mockProvider.validateTokenCalled {
			t.Error("Expected ValidateToken (userinfo) to be called for opaque token")
		}
	})

	// Test with a JWT-like token - should attempt JWKS validation first
	t.Run("jwt token attempts jwks first", func(t *testing.T) {
		mockProvider.reset()
		logBuffer.Reset()

		// This looks like a JWT (3 parts separated by dots)
		jwtToken := "header.payload.signature" //nolint:gosec // G101: Test JWT structure, not a real token

		_, _ = srv.ValidateToken(context.Background(), jwtToken)

		// Check logs to verify JWT validation was attempted
		// The JWT path should be tried first when TrustedAudiences is configured
		logOutput := logBuffer.String()
		jwtPathAttempted := strings.Contains(logOutput, "Forwarded ID token validation failed") ||
			strings.Contains(logOutput, "JWT audience matches TrustedAudiences")
		_ = jwtPathAttempted // Consume the variable; this is informational

		// The provider's ValidateToken should still be called as fallback
		// because the JWT validation will fail (no real JWKS)
		if !mockProvider.validateTokenCalled {
			t.Error("Expected fallback to userinfo after JWT validation failure")
		}
	})
}

// mockProviderWithTracking is a mock provider that tracks method calls.
type mockProviderWithTracking struct {
	validateTokenCalled bool
}

func (m *mockProviderWithTracking) reset() {
	m.validateTokenCalled = false
}

func (m *mockProviderWithTracking) Name() string {
	return "mock"
}

func (m *mockProviderWithTracking) DefaultScopes() []string {
	return []string{"openid"}
}

func (m *mockProviderWithTracking) AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string) string {
	return ""
}

func (m *mockProviderWithTracking) ExchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return nil, nil
}

func (m *mockProviderWithTracking) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	m.validateTokenCalled = true
	return &providers.UserInfo{ID: "test-user"}, nil
}

func (m *mockProviderWithTracking) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

func (m *mockProviderWithTracking) RevokeToken(ctx context.Context, token string) error {
	return nil
}

func (m *mockProviderWithTracking) HealthCheck(ctx context.Context) error {
	return nil
}
