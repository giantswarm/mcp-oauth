package server

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNew(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv == nil {
		t.Fatal("New() returned nil")
	}

	if srv.config.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", srv.config.Issuer, "https://auth.example.com")
	}

	if srv.logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestNew_WithLogger(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()
	logger := slog.Default()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.logger != logger {
		t.Error("Logger should match provided logger")
	}
}

func TestNew_NilConfig(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	srv, err := New(provider, store, store, store, nil, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.config == nil {
		t.Error("Config should not be nil when nil is passed")
	}
}

func TestNew_MissingProvider(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	_, err := New(nil, store, store, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil provider should return error")
	}
}

func TestNew_MissingTokenStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	_, err := New(provider, nil, store, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil token store should return error")
	}
}

func TestNew_MissingClientStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	_, err := New(provider, store, nil, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil client store should return error")
	}
}

func TestNew_MissingFlowStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	_, err := New(provider, store, store, nil, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil flow store should return error")
	}
}

// TestServer_OptionsAreAppliedAndPropagate verifies the With* constructor
// options install dependencies on the server.
func TestServer_OptionsAreAppliedAndPropagate(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	auditor := security.NewAuditor(nil, true)
	rl := security.NewRateLimiter(10, 20, nil)
	defer rl.Stop()
	userRL := security.NewRateLimiter(5, 10, nil)
	defer userRL.Stop()
	secEventRL := security.NewRateLimiter(1, 5, nil)
	defer secEventRL.Stop()

	srv, err := New(
		provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil,
		WithAuditor(auditor),
		WithRateLimiter(rl),
		WithUserRateLimiter(userRL),
		WithSecurityEventRateLimiter(secEventRL),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.auditor != auditor {
		t.Error("WithAuditor: server Auditor not set to the option value")
	}
	if srv.rateLimiter != rl {
		t.Error("WithRateLimiter: server RateLimiter not set to the option value")
	}
	if srv.userRateLimiter != userRL {
		t.Error("WithUserRateLimiter: server UserRateLimiter not set to the option value")
	}
	if srv.securityEventRateLimiter != secEventRL {
		t.Error("WithSecurityEventRateLimiter: server SecurityEventRateLimiter not set to the option value")
	}
}

// TestServer_ProviderRevocationConfigDefaults tests that New() applies correct defaults
// P1: Configuration defaults validation
func TestServer_ProviderRevocationConfigDefaults(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	// Create server with empty config (should apply defaults)
	config := &Config{
		Issuer: "https://auth.example.com",
		// Don't set provider revocation fields - should use defaults
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify defaults were applied
	if srv.config.ProviderRevocationTimeout != 10 {
		t.Errorf("ProviderRevocationTimeout = %d, want 10 (default)", srv.config.ProviderRevocationTimeout)
	}

	if srv.config.ProviderRevocationMaxRetries != 3 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 3 (default)", srv.config.ProviderRevocationMaxRetries)
	}

	if srv.config.ProviderRevocationFailureThreshold != 0.5 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.5 (default)", srv.config.ProviderRevocationFailureThreshold)
	}
}

// TestServer_ProviderRevocationConfigCustomValues tests custom values are preserved
// P1: Configuration validation
func TestServer_ProviderRevocationConfigCustomValues(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	// Create server with custom config values
	config := &Config{
		Issuer:                             "https://auth.example.com",
		ProviderRevocationTimeout:          30,
		ProviderRevocationMaxRetries:       5,
		ProviderRevocationFailureThreshold: 0.3,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify custom values were preserved
	if srv.config.ProviderRevocationTimeout != 30 {
		t.Errorf("ProviderRevocationTimeout = %d, want 30 (custom)", srv.config.ProviderRevocationTimeout)
	}

	if srv.config.ProviderRevocationMaxRetries != 5 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 5 (custom)", srv.config.ProviderRevocationMaxRetries)
	}

	if srv.config.ProviderRevocationFailureThreshold != 0.3 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.3 (custom)", srv.config.ProviderRevocationFailureThreshold)
	}
}

// TestGenerateRandomToken_Length validates that generated tokens meet minimum length requirements
// This ensures sufficient entropy for security-critical tokens.
func TestGenerateRandomToken_Length(t *testing.T) {
	token := generateRandomToken()

	// 32 bytes base64url-encoded (no padding) = 43 characters
	if len(token) < 43 {
		t.Errorf("generateRandomToken() length = %d, want >= 43", len(token))
	}

	t.Logf("Generated token length: %d characters", len(token))
}

// TestGenerateRandomToken_Base64URLEncoding validates proper encoding
func TestGenerateRandomToken_Base64URLEncoding(t *testing.T) {
	token := generateRandomToken()

	// Verify it's valid base64url (no padding)
	// Should decode without error
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("generateRandomToken() produced invalid base64url: %v", err)
	}

	// Should decode to exactly MinTokenBytes bytes
	if len(decoded) != MinTokenBytes {
		t.Errorf("decoded token length = %d bytes, want %d", len(decoded), MinTokenBytes)
	}

	// Verify no padding characters (base64url without padding)
	if token[len(token)-1] == '=' {
		t.Error("generateRandomToken() should use base64url WITHOUT padding")
	}

	t.Logf("Token: %s", token)
	t.Logf("Decoded to %d bytes", len(decoded))
}

// TestGenerateRandomToken_Uniqueness validates that tokens are unique
func TestGenerateRandomToken_Uniqueness(t *testing.T) {
	const numTokens = 10000
	tokens := make(map[string]bool, numTokens)

	for i := 0; i < numTokens; i++ {
		token := generateRandomToken()

		if tokens[token] {
			t.Errorf("generateRandomToken() produced duplicate token: %s", token)
			break
		}

		tokens[token] = true
	}

	t.Logf("Generated %d unique tokens out of %d attempts", len(tokens), numTokens)

	if len(tokens) != numTokens {
		t.Errorf("Expected %d unique tokens, got %d", numTokens, len(tokens))
	}
}

// TestGenerateRandomToken_Entropy validates statistical randomness properties
func TestGenerateRandomToken_Entropy(t *testing.T) {
	const numSamples = 1000

	// Collect samples
	charCounts := make(map[rune]int)
	for i := 0; i < numSamples; i++ {
		token := generateRandomToken()
		for _, ch := range token {
			charCounts[ch]++
		}
	}

	// Verify we see a good distribution of characters
	// With 1000 samples * 43 chars = 43,000 characters
	// Base64 has 64 possible characters
	// We just verify we have variety (at least 50 different chars)
	if len(charCounts) < 50 {
		t.Errorf("Low character variety in tokens: %d unique chars, expected > 50", len(charCounts))
	}

	t.Logf("Token entropy check: %d unique characters observed across %d tokens", len(charCounts), numSamples)

	// Verify all characters are valid base64url (optimized with map lookup)
	validChars := make(map[rune]bool)
	for _, ch := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		validChars[ch] = true
	}

	for ch := range charCounts {
		if !validChars[ch] {
			t.Errorf("Invalid character in token: %c (U+%04X)", ch, ch)
		}
	}
}

// BenchmarkGenerateRandomToken measures token generation performance
func BenchmarkGenerateRandomToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = generateRandomToken()
	}
}

// TestExtractIDToken verifies the helper function correctly extracts id_token from oauth2.Token.
// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token enables silent re-authentication.
func TestExtractIDToken(t *testing.T) {
	tests := []struct {
		name     string
		token    *oauth2.Token
		expected string
	}{
		{
			name:     "nil token returns empty string",
			token:    nil,
			expected: "",
		},
		{
			name: "token without extras returns empty string",
			token: &oauth2.Token{
				AccessToken: "access-token-123",
			},
			expected: "",
		},
		{
			name: "token with id_token returns the id_token",
			token: (&oauth2.Token{
				AccessToken: "access-token-123",
			}).WithExtra(map[string]interface{}{
				"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", //nolint:gosec // test value
			}),
			expected: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		{
			name: "token with empty id_token returns empty string",
			token: (&oauth2.Token{
				AccessToken: "access-token-123",
			}).WithExtra(map[string]interface{}{
				"id_token": "",
			}),
			expected: "",
		},
		{
			name: "token with nil id_token returns empty string",
			token: (&oauth2.Token{
				AccessToken: "access-token-123",
			}).WithExtra(map[string]interface{}{
				"id_token": nil,
			}),
			expected: "",
		},
		{
			name: "token with non-string id_token returns empty string",
			token: (&oauth2.Token{
				AccessToken: "access-token-123",
			}).WithExtra(map[string]interface{}{
				"id_token": 12345, // wrong type
			}),
			expected: "",
		},
		{
			name: "token with other extras but no id_token returns empty string",
			token: (&oauth2.Token{
				AccessToken: "access-token-123",
			}).WithExtra(map[string]interface{}{
				"custom_field": "value",
			}),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractIDToken(tt.token)
			if result != tt.expected {
				t.Errorf("ExtractIDToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestServer_Shutdown(t *testing.T) {
	// Create a test server with all components
	store := memory.New()
	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Add rate limiters to test their shutdown
	srv.rateLimiter = security.NewRateLimiter(10, 20, nil)
	srv.userRateLimiter = security.NewRateLimiter(5, 10, nil)
	srv.securityEventRateLimiter = security.NewRateLimiter(100, 200, nil)
	srv.clientRegistrationRateLimiter = security.NewClientRegistrationRateLimiter(nil)

	// Shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// Verify idempotency - second call should also succeed without error
	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Second Shutdown() error = %v", err)
	}

	// Third call to ensure sync.Once is working correctly
	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Third Shutdown() error = %v", err)
	}
}

func TestServer_Shutdown_WithoutRateLimiters(t *testing.T) {
	// Test shutdown with no rate limiters configured
	store := memory.New()
	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Shutdown should work even without rate limiters
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() without rate limiters error = %v", err)
	}
}

func TestServer_Shutdown_ContextCancellation(t *testing.T) {
	// Test shutdown behavior when context is cancelled
	store := memory.New()
	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Shutdown should complete quickly since context is already done
	err = srv.Shutdown(ctx)
	if err == nil {
		// Note: In this case, shutdown might complete before context check,
		// so we don't strictly require an error
		t.Log("Shutdown completed despite cancelled context (expected if shutdown is fast)")
	}
}

func TestServer_ShutdownWithTimeout(t *testing.T) {
	// Create a test server
	store := memory.New()
	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Add rate limiters
	srv.rateLimiter = security.NewRateLimiter(10, 20, nil)
	srv.userRateLimiter = security.NewRateLimiter(5, 10, nil)

	// Test convenience method
	err = srv.ShutdownWithTimeout(5 * time.Second)
	if err != nil {
		t.Errorf("ShutdownWithTimeout() error = %v", err)
	}

	// Verify idempotency
	err = srv.ShutdownWithTimeout(5 * time.Second)
	if err != nil {
		t.Errorf("Second ShutdownWithTimeout() error = %v", err)
	}
}

func TestServer_ShutdownWithTimeout_ShortTimeout(t *testing.T) {
	// Test with a very short timeout to ensure timeout handling works
	store := memory.New()
	provider := mock.NewProvider()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Use a reasonable timeout - shutdown should complete quickly
	err = srv.ShutdownWithTimeout(1 * time.Second)
	if err != nil {
		t.Logf("ShutdownWithTimeout() with short timeout: %v (may timeout on slow systems)", err)
	}
}

func TestIsAudienceScope(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{
			name:     "valid audience scope",
			scope:    "audience:server:client_id:k8s-auth",
			expected: true,
		},
		{
			name:     "valid audience scope with hyphens",
			scope:    "audience:server:client_id:dex-k8s-authenticator",
			expected: true,
		},
		{
			name:     "valid audience scope with underscores",
			scope:    "audience:server:client_id:api_gateway_v2",
			expected: true,
		},
		{
			name:     "not an audience scope - openid",
			scope:    "openid",
			expected: false,
		},
		{
			name:     "not an audience scope - profile",
			scope:    "profile",
			expected: false,
		},
		{
			name:     "not an audience scope - email",
			scope:    "email",
			expected: false,
		},
		{
			name:     "not an audience scope - groups",
			scope:    "groups",
			expected: false,
		},
		{
			name:     "not an audience scope - offline_access",
			scope:    "offline_access",
			expected: false,
		},
		{
			name:     "empty string",
			scope:    "",
			expected: false,
		},
		{
			name:     "prefix only without client id",
			scope:    "audience:server:client_id:",
			expected: false,
		},
		{
			name:     "partial prefix match",
			scope:    "audience:server:",
			expected: false,
		},
		{
			name:     "similar but not matching prefix",
			scope:    "audience:client:server_id:test",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAudienceScope(tt.scope)
			if result != tt.expected {
				t.Errorf("isAudienceScope(%q) = %v, want %v", tt.scope, result, tt.expected)
			}
		})
	}
}

func TestLogMandatoryAudienceScopes(t *testing.T) {
	t.Run("logs when audience scopes are present", func(t *testing.T) {
		store := memory.New()
		defer store.Stop()

		provider := mock.NewProvider()
		provider.DefaultScopesFunc = func() []string {
			return []string{
				"openid",
				"profile",
				"audience:server:client_id:k8s-auth",
				"audience:server:client_id:api-gateway",
			}
		}

		// Create server - it will log during initialization
		config := &Config{
			Issuer: "https://auth.example.com",
		}

		srv, err := New(provider, store, store, store, config, slog.Default())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		// Verify server was created successfully
		// The logging happens at startup - we're just verifying no errors
		if srv == nil {
			t.Fatal("Server should not be nil")
		}
	})

	t.Run("no log when no audience scopes", func(t *testing.T) {
		store := memory.New()
		defer store.Stop()

		provider := mock.NewProvider()
		provider.DefaultScopesFunc = func() []string {
			return []string{"openid", "profile", "email"}
		}

		config := &Config{
			Issuer: "https://auth.example.com",
		}

		srv, err := New(provider, store, store, store, config, slog.Default())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if srv == nil {
			t.Fatal("Server should not be nil")
		}
	})

	t.Run("handles empty default scopes", func(t *testing.T) {
		store := memory.New()
		defer store.Stop()

		provider := mock.NewProvider()
		provider.DefaultScopesFunc = func() []string {
			return nil
		}

		config := &Config{
			Issuer: "https://auth.example.com",
		}

		srv, err := New(provider, store, store, store, config, slog.Default())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if srv == nil {
			t.Fatal("Server should not be nil")
		}
	})
}
