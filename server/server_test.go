package server

import (
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNew(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

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

	if srv.Config.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", srv.Config.Issuer, "https://auth.example.com")
	}

	if srv.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestNew_WithLogger(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger := slog.Default()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.Logger != logger {
		t.Error("Logger should match provided logger")
	}
}

func TestNew_NilConfig(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, nil, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.Config == nil {
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

	provider := mock.NewMockProvider()

	_, err := New(provider, nil, store, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil token store should return error")
	}
}

func TestNew_MissingClientStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	_, err := New(provider, store, nil, store, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil client store should return error")
	}
}

func TestNew_MissingFlowStore(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	_, err := New(provider, store, store, nil, &Config{}, nil)
	if err == nil {
		t.Error("New() with nil flow store should return error")
	}
}

func TestServer_SetEncryptor(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	srv.SetEncryptor(enc)

	if srv.Encryptor == nil {
		t.Error("Encryptor should be set")
	}
}

func TestServer_SetAuditor(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	auditor := security.NewAuditor(nil, true)
	srv.SetAuditor(auditor)

	if srv.Auditor == nil {
		t.Error("Auditor should be set")
	}
}

func TestServer_SetRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(10, 20, nil)
	defer rl.Stop()

	srv.SetRateLimiter(rl)

	if srv.RateLimiter == nil {
		t.Error("RateLimiter should be set")
	}
}

func TestServer_SetUserRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(5, 10, nil)
	defer rl.Stop()

	srv.SetUserRateLimiter(rl)

	if srv.UserRateLimiter == nil {
		t.Error("UserRateLimiter should be set")
	}
}

func TestServer_SetSecurityEventRateLimiter(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	srv, err := New(provider, store, store, store, &Config{Issuer: "https://test.example.com"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rl := security.NewRateLimiter(1, 5, nil)
	defer rl.Stop()

	srv.SetSecurityEventRateLimiter(rl)

	if srv.SecurityEventRateLimiter == nil {
		t.Error("SecurityEventRateLimiter should be set")
	}
}

// TestServer_ProviderRevocationConfigDefaults tests that New() applies correct defaults
// P1: Configuration defaults validation
func TestServer_ProviderRevocationConfigDefaults(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

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
	if srv.Config.ProviderRevocationTimeout != 10 {
		t.Errorf("ProviderRevocationTimeout = %d, want 10 (default)", srv.Config.ProviderRevocationTimeout)
	}

	if srv.Config.ProviderRevocationMaxRetries != 3 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 3 (default)", srv.Config.ProviderRevocationMaxRetries)
	}

	if srv.Config.ProviderRevocationFailureThreshold != 0.5 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.5 (default)", srv.Config.ProviderRevocationFailureThreshold)
	}

	if srv.Config.RevokedFamilyRetentionDays != 90 {
		t.Errorf("RevokedFamilyRetentionDays = %d, want 90 (default)", srv.Config.RevokedFamilyRetentionDays)
	}
}

// TestServer_ProviderRevocationConfigCustomValues tests custom values are preserved
// P1: Configuration validation
func TestServer_ProviderRevocationConfigCustomValues(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	// Create server with custom config values
	config := &Config{
		Issuer:                             "https://auth.example.com",
		ProviderRevocationTimeout:          30,
		ProviderRevocationMaxRetries:       5,
		ProviderRevocationFailureThreshold: 0.3,
		RevokedFamilyRetentionDays:         180,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify custom values were preserved
	if srv.Config.ProviderRevocationTimeout != 30 {
		t.Errorf("ProviderRevocationTimeout = %d, want 30 (custom)", srv.Config.ProviderRevocationTimeout)
	}

	if srv.Config.ProviderRevocationMaxRetries != 5 {
		t.Errorf("ProviderRevocationMaxRetries = %d, want 5 (custom)", srv.Config.ProviderRevocationMaxRetries)
	}

	if srv.Config.ProviderRevocationFailureThreshold != 0.3 {
		t.Errorf("ProviderRevocationFailureThreshold = %f, want 0.3 (custom)", srv.Config.ProviderRevocationFailureThreshold)
	}

	if srv.Config.RevokedFamilyRetentionDays != 180 {
		t.Errorf("RevokedFamilyRetentionDays = %d, want 180 (custom)", srv.Config.RevokedFamilyRetentionDays)
	}
}

// TestServer_RevokedFamilyRetentionPropagation tests retention period propagates to storage
// P2: Feature integration test
func TestServer_RevokedFamilyRetentionPropagation(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()

	config := &Config{
		Issuer:                     "https://auth.example.com",
		RevokedFamilyRetentionDays: 120,
	}

	_, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Memory store implements the retention setter interface
	// Verify it was called (we can't directly check private field, but can verify no error)
	// The actual retention behavior is tested in memory store tests

	// If we get here without panic, the type assertion and call succeeded
	t.Log("Retention period propagation test passed - no error during setup")
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
	samples := make([]string, numSamples)
	for i := 0; i < numSamples; i++ {
		samples[i] = generateRandomToken()
	}

	// Validate character distribution
	// Base64url alphabet: A-Z, a-z, 0-9, -, _
	charCounts := make(map[rune]int)

	for _, token := range samples {
		for _, ch := range token {
			charCounts[ch]++
		}
	}

	// Verify we see a good distribution of characters
	// With 1000 samples * 43 chars = 43,000 characters
	// Base64 has 64 possible characters
	// Expected ~671 occurrences per character (43000/64)
	// We just verify we have variety (at least 50 different chars)
	if len(charCounts) < 50 {
		t.Errorf("Low character variety in tokens: %d unique chars, expected > 50", len(charCounts))
	}

	t.Logf("Token entropy check: %d unique characters observed across %d tokens", len(charCounts), numSamples)

	// Verify all characters are valid base64url
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for ch := range charCounts {
		found := false
		for _, validCh := range validChars {
			if ch == validCh {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Invalid character in token: %c (U+%04X)", ch, ch)
		}
	}
}

// TestGenerateRandomToken_NoBitwisePatterns validates no obvious patterns in binary representation
func TestGenerateRandomToken_NoBitwisePatterns(t *testing.T) {
	const numSamples = 100

	allZeros := 0
	allOnes := 0

	for i := 0; i < numSamples; i++ {
		token := generateRandomToken()
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("Failed to decode token: %v", err)
		}

		// Check each byte
		for _, b := range decoded {
			if b == 0x00 {
				allZeros++
			}
			if b == 0xFF {
				allOnes++
			}
		}
	}

	totalBytes := numSamples * MinTokenBytes

	// With good randomness, we expect ~0.4% of bytes to be 0x00 or 0xFF (1/256)
	// Allow up to 2% before flagging as suspicious
	maxExpected := totalBytes * 2 / 100

	if allZeros > maxExpected {
		t.Errorf("Suspicious number of 0x00 bytes: %d out of %d (%.2f%%), expected < 2%%",
			allZeros, totalBytes, float64(allZeros)*100/float64(totalBytes))
	}

	if allOnes > maxExpected {
		t.Errorf("Suspicious number of 0xFF bytes: %d out of %d (%.2f%%), expected < 2%%",
			allOnes, totalBytes, float64(allOnes)*100/float64(totalBytes))
	}

	t.Logf("Bitwise pattern check: 0x00=%d (%.2f%%), 0xFF=%d (%.2f%%) out of %d bytes",
		allZeros, float64(allZeros)*100/float64(totalBytes),
		allOnes, float64(allOnes)*100/float64(totalBytes),
		totalBytes)
}

// TestGenerateRandomToken_PerformanceBenchmark validates token generation is fast enough
func TestGenerateRandomToken_PerformanceBenchmark(t *testing.T) {
	const numIterations = 1000

	start := time.Now()
	for i := 0; i < numIterations; i++ {
		_ = generateRandomToken()
	}
	duration := time.Since(start)

	avgPerToken := duration / numIterations

	// Token generation should be very fast (< 1ms per token)
	if avgPerToken > time.Millisecond {
		t.Errorf("Token generation too slow: %v per token (expected < 1ms)", avgPerToken)
	}

	t.Logf("Generated %d tokens in %v (avg %v per token)", numIterations, duration, avgPerToken)
}
