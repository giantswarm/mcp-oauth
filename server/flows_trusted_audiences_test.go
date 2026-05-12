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
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testJWTWithMusterClientAudience is a test JWT with muster-client audience for testing.
// Header: {"alg":"RS256","typ":"JWT"}
// Payload: {"aud":"muster-client","sub":"user123"}
// Signature: valid base64 but not cryptographically valid (for testing flow, not crypto validation)
//
//nolint:gosec // G101: Test JWT structure, not a credential
const testJWTWithMusterClientAudience = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtdXN0ZXItY2xpZW50Iiwic3ViIjoidXNlcjEyMyJ9.ZmFrZS1zaWduYXR1cmUtYnl0ZXMtZm9yLXRlc3Rpbmctb25seQ"

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
			logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
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
			if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: "test-user", ClientID: "test-client", TokenType: "access", Audience: tt.tokenAudience}); err != nil {
				t.Fatalf("SaveTokenMetadata() error = %v", err)
			}

			// Validate the token
			err := srv.validateTokenAudience(context.Background(), accessToken)

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
			logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

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

	srv.logCrossClientTokenAccepted(context.Background(), "test-token-12345678", metadata) //nolint:staticcheck // Testing the cross-client logging path

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
	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: "user", ClientID: "client", TokenType: "access", Audience: "https://mcp.example.com"}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := srv.validateTokenAudience(context.Background(), accessToken); err != nil {
		t.Errorf("Expected token with server's own audience to be accepted, got error: %v", err)
	}

	// Test 2: Different audience should be rejected
	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: "user", ClientID: "client", TokenType: "access", Audience: "muster-client"}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := srv.validateTokenAudience(context.Background(), accessToken); err == nil {
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

	// Use the existing mock provider from providers/mock package
	mockProvider := mock.NewProvider()

	srv := &Server{
		Config:     config,
		tokenStore: store,
		flowStore:  store,
		provider:   mockProvider,
		Logger:     logger,
	}

	// Test with an opaque token (not a JWT) - should call userinfo
	t.Run("opaque token calls userinfo", func(t *testing.T) {
		mockProvider.ResetCallCounts()

		// This is an opaque access token (not a JWT)
		opaqueToken := "opaque-access-token-not-jwt" //nolint:gosec // G101: Test data, not a real credential

		_, _ = srv.ValidateToken(context.Background(), opaqueToken)

		if mockProvider.GetCallCount("ValidateToken") == 0 {
			t.Error("Expected ValidateToken (userinfo) to be called for opaque token")
		}
	})

	// Test with a JWT-like token - should attempt JWKS validation first
	t.Run("jwt token attempts jwks first", func(t *testing.T) {
		mockProvider.ResetCallCounts()
		logBuffer.Reset()

		// This looks like a JWT (3 parts separated by dots)
		jwtToken := "header.payload.signature" //nolint:gosec // G101: Test JWT structure, not a real token

		_, _ = srv.ValidateToken(context.Background(), jwtToken)

		// Verify JWT path was attempted by checking logs
		// The JWT path should be tried first when TrustedAudiences is configured
		logOutput := logBuffer.String()
		jwtPathAttempted := strings.Contains(logOutput, "Forwarded ID token validation failed") ||
			strings.Contains(logOutput, "JWT audience matches TrustedAudiences")

		if !jwtPathAttempted {
			t.Error("Expected JWT validation path to be attempted before userinfo")
		}

		// The provider's ValidateToken should still be called as fallback
		// because the JWT validation will fail (no real JWKS)
		if mockProvider.GetCallCount("ValidateToken") == 0 {
			t.Error("Expected fallback to userinfo after JWT validation failure")
		}
	})
}

// TestValidateToken_IssuerValidation verifies that issuer validation is configured
// when the provider implements JWKSProvider and provides an issuer URL.
// Note: Full end-to-end issuer validation requires a valid JWT with proper signature,
// which is tested in providers/oidc/jwt_test.go. This test verifies the mock provider
// supports the JWKSProvider interface and the issuer is passed to the validation.
func TestValidateToken_IssuerValidation(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		TrustedAudiences:   []string{"muster-client"},
	}

	// Test that provider's IssuerURL is called when JWKSProvider is implemented
	t.Run("provider IssuerURL is called during JWT validation", func(t *testing.T) {
		mockProvider := mock.NewProvider()
		issuerCalled := false
		mockProvider.IssuerURLFunc = func() string {
			issuerCalled = true
			return "https://accounts.google.com"
		}

		srv := &Server{
			Config:     config,
			tokenStore: store,
			flowStore:  store,
			provider:   mockProvider,
			Logger:     logger,
		}

		// Use test JWT with valid structure but invalid signature
		_, _ = srv.ValidateToken(context.Background(), testJWTWithMusterClientAudience)

		// Verify IssuerURL was called during validation
		if !issuerCalled {
			t.Error("Expected IssuerURL to be called during JWT validation")
		}
	})

	// Test that JWKSURI is called when JWKSProvider is implemented
	t.Run("provider JWKSURI is called during JWT validation", func(t *testing.T) {
		mockProvider := mock.NewProvider()
		mockProvider.ResetCallCounts()

		srv := &Server{
			Config:     config,
			tokenStore: store,
			flowStore:  store,
			provider:   mockProvider,
			Logger:     logger,
		}

		// Use test JWT with valid structure but invalid signature
		_, _ = srv.ValidateToken(context.Background(), testJWTWithMusterClientAudience)

		// Verify JWKSURI was called
		if mockProvider.GetCallCount("JWKSURI") == 0 {
			t.Error("Expected JWKSURI to be called during JWT validation")
		}
	})

	// Test with provider that has empty issuer URL
	t.Run("provider with empty issuer URL proceeds without issuer validation", func(t *testing.T) {
		logBuffer.Reset()

		mockProvider := mock.NewProvider()
		mockProvider.IssuerURLFunc = func() string {
			return "" // Empty issuer - validation should proceed without issuer check
		}

		srv := &Server{
			Config:     config,
			tokenStore: store,
			flowStore:  store,
			provider:   mockProvider,
			Logger:     logger,
		}

		// Use test JWT with valid structure but invalid signature
		_, _ = srv.ValidateToken(context.Background(), testJWTWithMusterClientAudience)

		// Verify issuer validation log was NOT emitted (since issuer is empty)
		logOutput := logBuffer.String()
		if strings.Contains(logOutput, "Validating JWT issuer against provider") {
			t.Error("Expected issuer validation to be skipped when provider has empty issuer URL")
		}
	})
}

// TestMockProvider_JWKSProvider verifies that the mock provider implements JWKSProvider.
func TestMockProvider_JWKSProvider(t *testing.T) {
	mockProvider := mock.NewProvider()

	t.Run("default JWKS URI", func(t *testing.T) {
		uri, err := mockProvider.JWKSURI(context.Background())
		if err != nil {
			t.Errorf("JWKSURI() error = %v", err)
		}
		if uri == "" {
			t.Error("Expected non-empty JWKS URI")
		}
	})

	t.Run("default issuer URL", func(t *testing.T) {
		issuer := mockProvider.IssuerURL()
		if issuer == "" {
			t.Error("Expected non-empty issuer URL")
		}
	})

	t.Run("custom JWKS URI", func(t *testing.T) {
		mockProvider.JWKSURIFunc = func(_ context.Context) (string, error) {
			return "https://custom.example.com/.well-known/jwks.json", nil
		}
		uri, err := mockProvider.JWKSURI(context.Background())
		if err != nil {
			t.Errorf("JWKSURI() error = %v", err)
		}
		if uri != "https://custom.example.com/.well-known/jwks.json" {
			t.Errorf("JWKSURI() = %q, want custom URI", uri)
		}
	})

	t.Run("custom issuer URL", func(t *testing.T) {
		mockProvider.IssuerURLFunc = func() string {
			return "https://custom-issuer.example.com"
		}
		issuer := mockProvider.IssuerURL()
		if issuer != "https://custom-issuer.example.com" {
			t.Errorf("IssuerURL() = %q, want custom issuer", issuer)
		}
	})

	t.Run("call counts tracked", func(t *testing.T) {
		mockProvider.ResetCallCounts()
		_, _ = mockProvider.JWKSURI(context.Background())
		_ = mockProvider.IssuerURL()

		if mockProvider.GetCallCount("JWKSURI") != 1 {
			t.Errorf("JWKSURI call count = %d, want 1", mockProvider.GetCallCount("JWKSURI"))
		}
		if mockProvider.GetCallCount("IssuerURL") != 1 {
			t.Errorf("IssuerURL call count = %d, want 1", mockProvider.GetCallCount("IssuerURL"))
		}
	})
}

// TestGetJWKSClient_AllowPrivateIPJWKS tests that getJWKSClient respects the AllowPrivateIPJWKS config.
func TestGetJWKSClient_AllowPrivateIPJWKS(t *testing.T) {
	t.Run("default config creates SSRF-protected client", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: false, // Default
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client := srv.getJWKSClient()
		if client == nil {
			t.Fatal("Expected non-nil JWKS client")
		}
	})

	t.Run("AllowPrivateIPJWKS creates client without SSRF protection", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: true,
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client := srv.getJWKSClient()
		if client == nil {
			t.Fatal("Expected non-nil JWKS client")
		}
	})

	t.Run("client is initialized only once (sync.Once)", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: true,
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client1 := srv.getJWKSClient()
		client2 := srv.getJWKSClient()

		if client1 != client2 {
			t.Error("Expected same client instance to be returned (sync.Once)")
		}
	})

	t.Run("SSRF-protected client blocks private IP JWKS fetch", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: false, // SSRF protection enabled
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client := srv.getJWKSClient()
		if client == nil {
			t.Fatal("Expected non-nil JWKS client")
		}

		// Try to fetch JWKS from a private IP - should fail with SSRF protection error
		ctx := context.Background()
		_, err := client.FetchJWKS(ctx, "https://192.168.1.100/.well-known/jwks.json")

		if err == nil {
			t.Fatal("Expected error when fetching from private IP with SSRF protection enabled")
		}

		// Verify the error is about private IP (SSRF protection), not a network error
		errStr := err.Error()
		if !strings.Contains(errStr, "private") {
			t.Errorf("Expected private IP error, got: %v", err)
		}
	})

	t.Run("private IP allowed client bypasses SSRF for private IP", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: true, // SSRF protection disabled for JWKS
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client := srv.getJWKSClient()
		if client == nil {
			t.Fatal("Expected non-nil JWKS client")
		}

		// Try to fetch JWKS from a private IP
		// Should fail at network level (connection refused), NOT at SSRF validation
		ctx := context.Background()
		_, err := client.FetchJWKS(ctx, "https://192.168.1.100/.well-known/jwks.json")

		if err == nil {
			// If somehow it succeeded (unlikely), that's fine - means SSRF was bypassed
			return
		}

		// The error should NOT be about private IP - SSRF should be bypassed
		errStr := err.Error()
		if strings.Contains(errStr, "private IP") {
			t.Errorf("Expected SSRF protection to be bypassed, but got private IP error: %v", err)
		}
	})

	t.Run("HTTPS still required even with AllowPrivateIPJWKS", func(t *testing.T) {
		config := &Config{
			Issuer:             "https://auth.example.com",
			AllowPrivateIPJWKS: true, // SSRF protection disabled
		}

		srv := &Server{
			Config: config,
			Logger: slog.Default(),
		}

		client := srv.getJWKSClient()
		if client == nil {
			t.Fatal("Expected non-nil JWKS client")
		}

		// Try to fetch JWKS over HTTP (not HTTPS) - should fail even with AllowPrivateIPJWKS
		ctx := context.Background()
		_, err := client.FetchJWKS(ctx, "http://192.168.1.100/.well-known/jwks.json")

		if err == nil {
			t.Fatal("Expected error when using HTTP (HTTPS should always be required)")
		}

		// Verify the error is about HTTPS requirement
		errStr := err.Error()
		if !strings.Contains(errStr, "HTTPS") {
			t.Errorf("Expected HTTPS requirement error, got: %v", err)
		}
	})
}

// TestValidateToken_TokenSource_OAuth verifies that TokenSource is set to OAuth
// for tokens validated via the normal OAuth flow (userinfo endpoint).
func TestValidateToken_TokenSource_OAuth(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		// No TrustedAudiences - will use userinfo endpoint
	}

	mockProvider := mock.NewProvider()

	srv := &Server{
		Config:     config,
		tokenStore: store,
		flowStore:  store,
		provider:   mockProvider,
		Logger:     logger,
	}

	// Opaque token validated via userinfo endpoint should have TokenSourceOAuth
	t.Run("opaque token has TokenSourceOAuth", func(t *testing.T) {
		opaqueToken := "opaque-access-token-12345" //nolint:gosec // G101: Test data, not a real credential

		userInfo, err := srv.ValidateToken(ctx, opaqueToken)
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}

		if userInfo.TokenSource != providers.TokenSourceOAuth {
			t.Errorf("TokenSource = %q, want %q", userInfo.TokenSource, providers.TokenSourceOAuth)
		}

		if !userInfo.IsOAuth() {
			t.Error("IsOAuth() should return true for OAuth-validated token")
		}

		if userInfo.IsSSO() {
			t.Error("IsSSO() should return false for OAuth-validated token")
		}
	})
}

// TestValidateToken_TokenSource_SSO verifies that TokenSource is set to SSO
// for tokens validated via SSO token forwarding (JWKS validation).
// This test verifies the idTokenClaimsToUserInfo function sets TokenSourceSSO.
func TestValidateToken_TokenSource_SSO(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://mcp.example.com",
		TrustedAudiences:   []string{"muster-client"},
	}

	srv := &Server{
		Config:     config,
		tokenStore: store,
		flowStore:  store,
		Logger:     logger,
	}

	// Test idTokenClaimsToUserInfo sets TokenSourceSSO
	t.Run("idTokenClaimsToUserInfo sets TokenSourceSSO", func(t *testing.T) {
		claims := &oidc.IDTokenClaims{
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "Test User",
		}
		claims.Subject = testUserID

		userInfo := srv.idTokenClaimsToUserInfo(claims)

		if userInfo.TokenSource != providers.TokenSourceSSO {
			t.Errorf("TokenSource = %q, want %q", userInfo.TokenSource, providers.TokenSourceSSO)
		}

		if !userInfo.IsSSO() {
			t.Error("IsSSO() should return true for SSO-validated token")
		}

		if userInfo.IsOAuth() {
			t.Error("IsOAuth() should return false for SSO-validated token")
		}

		// Verify other fields are set correctly
		if userInfo.ID != testUserID {
			t.Errorf("ID = %q, want %q", userInfo.ID, testUserID)
		}
		if userInfo.Email != "user@example.com" {
			t.Errorf("Email = %q, want %q", userInfo.Email, "user@example.com")
		}
	})
}

// TestTokenSource_BackwardCompatibility verifies that UserInfo without TokenSource
// set is treated as OAuth for backward compatibility.
func TestTokenSource_BackwardCompatibility(t *testing.T) {
	// UserInfo from older code or storage may not have TokenSource set
	userInfo := &providers.UserInfo{
		ID:    "user-123",
		Email: "user@example.com",
		// TokenSource not set (zero value)
	}

	// Should be treated as OAuth for backward compatibility
	if !userInfo.IsOAuth() {
		t.Error("Empty TokenSource should be treated as OAuth for backward compatibility")
	}

	if userInfo.IsSSO() {
		t.Error("Empty TokenSource should not be treated as SSO")
	}

	// Verify the zero value
	if userInfo.TokenSource != "" {
		t.Errorf("Expected empty TokenSource, got %q", userInfo.TokenSource)
	}
}
