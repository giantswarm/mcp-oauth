package oauth

import (
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	config := Config{}

	// Test that zero values are sensible
	if config.Resource != "" {
		t.Errorf("Resource should be empty by default, got %q", config.Resource)
	}

	if config.CleanupInterval != 0 {
		t.Errorf("CleanupInterval should be 0 by default, got %v", config.CleanupInterval)
	}

	if config.Logger != nil {
		t.Error("Logger should be nil by default")
	}

	if config.HTTPClient != nil {
		t.Error("HTTPClient should be nil by default")
	}
}

func TestGoogleAuthConfig(t *testing.T) {
	config := GoogleAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}

	if config.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", config.ClientID, "test-client-id")
	}

	if config.ClientSecret != "test-client-secret" {
		t.Errorf("ClientSecret = %q, want %q", config.ClientSecret, "test-client-secret")
	}

	if config.RedirectURL != "https://example.com/callback" {
		t.Errorf("RedirectURL = %q, want %q", config.RedirectURL, "https://example.com/callback")
	}
}

func TestRateLimitConfig(t *testing.T) {
	config := RateLimitConfig{
		Rate:            10,
		Burst:           20,
		CleanupInterval: 5 * time.Minute,
		UserRate:        5,
		UserBurst:       10,
		TrustProxy:      true,
	}

	if config.Rate != 10 {
		t.Errorf("Rate = %d, want %d", config.Rate, 10)
	}

	if config.Burst != 20 {
		t.Errorf("Burst = %d, want %d", config.Burst, 20)
	}

	if config.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, want %v", config.CleanupInterval, 5*time.Minute)
	}

	if config.UserRate != 5 {
		t.Errorf("UserRate = %d, want %d", config.UserRate, 5)
	}

	if config.UserBurst != 10 {
		t.Errorf("UserBurst = %d, want %d", config.UserBurst, 10)
	}

	if !config.TrustProxy {
		t.Error("TrustProxy should be true")
	}
}

func TestSecurityConfig_Defaults(t *testing.T) {
	config := SecurityConfig{}

	// Test secure defaults
	if config.AllowInsecureAuthWithoutState {
		t.Error("AllowInsecureAuthWithoutState should be false by default")
	}

	if config.DisableRefreshTokenRotation {
		t.Error("DisableRefreshTokenRotation should be false by default")
	}

	if config.AllowPublicClientRegistration {
		t.Error("AllowPublicClientRegistration should be false by default")
	}

	if config.AllowCustomRedirectSchemes {
		t.Error("AllowCustomRedirectSchemes should be false by default")
	}

	if config.EnableAuditLogging {
		t.Error("EnableAuditLogging should be false by default")
	}
}

func TestSecurityConfig_CustomSettings(t *testing.T) {
	encKey := make([]byte, 32)
	config := SecurityConfig{
		AllowInsecureAuthWithoutState: true,
		DisableRefreshTokenRotation:   true,
		AllowPublicClientRegistration: true,
		RegistrationAccessToken:       "test-token",
		RefreshTokenTTL:               90 * 24 * time.Hour,
		MaxClientsPerIP:               10,
		AllowCustomRedirectSchemes:    true,
		AllowedCustomSchemes:          []string{"myapp://"},
		EncryptionKey:                 encKey,
		EnableAuditLogging:            true,
	}

	if !config.AllowInsecureAuthWithoutState {
		t.Error("AllowInsecureAuthWithoutState should be true")
	}

	if !config.DisableRefreshTokenRotation {
		t.Error("DisableRefreshTokenRotation should be true")
	}

	if !config.AllowPublicClientRegistration {
		t.Error("AllowPublicClientRegistration should be true")
	}

	if config.RegistrationAccessToken != "test-token" {
		t.Errorf("RegistrationAccessToken = %q, want %q", config.RegistrationAccessToken, "test-token")
	}

	if config.RefreshTokenTTL != 90*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", config.RefreshTokenTTL, 90*24*time.Hour)
	}

	if config.MaxClientsPerIP != 10 {
		t.Errorf("MaxClientsPerIP = %d, want %d", config.MaxClientsPerIP, 10)
	}

	if !config.AllowCustomRedirectSchemes {
		t.Error("AllowCustomRedirectSchemes should be true")
	}

	if len(config.AllowedCustomSchemes) != 1 || config.AllowedCustomSchemes[0] != "myapp://" {
		t.Errorf("AllowedCustomSchemes = %v, want %v", config.AllowedCustomSchemes, []string{"myapp://"})
	}

	if config.EncryptionKey == nil || len(config.EncryptionKey) != 32 {
		t.Error("EncryptionKey should be set and be 32 bytes")
	}

	if !config.EnableAuditLogging {
		t.Error("EnableAuditLogging should be true")
	}
}

func TestConfig_WithCustomLogger(t *testing.T) {
	logger := slog.Default()
	config := Config{
		Logger: logger,
	}

	if config.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestConfig_WithCustomHTTPClient(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	config := Config{
		HTTPClient: client,
	}

	if config.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}

	if config.HTTPClient.Timeout != 10*time.Second {
		t.Errorf("HTTPClient.Timeout = %v, want %v", config.HTTPClient.Timeout, 10*time.Second)
	}
}

func TestConfig_CompleteConfiguration(t *testing.T) {
	encKey := make([]byte, 32)
	config := Config{
		Resource:        "https://api.example.com",
		SupportedScopes: []string{"openid", "email", "profile"},
		GoogleAuth: GoogleAuthConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/callback",
		},
		RateLimit: RateLimitConfig{
			Rate:            10,
			Burst:           20,
			CleanupInterval: 5 * time.Minute,
			UserRate:        5,
			UserBurst:       10,
			TrustProxy:      false,
		},
		Security: SecurityConfig{
			AllowInsecureAuthWithoutState: false,
			DisableRefreshTokenRotation:   false,
			AllowPublicClientRegistration: false,
			RegistrationAccessToken:       "secure-token",
			RefreshTokenTTL:               90 * 24 * time.Hour,
			MaxClientsPerIP:               10,
			AllowCustomRedirectSchemes:    false,
			EncryptionKey:                 encKey,
			EnableAuditLogging:            true,
		},
		CleanupInterval: 1 * time.Minute,
		Logger:          slog.Default(),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Verify all fields are set correctly
	if config.Resource != "https://api.example.com" {
		t.Errorf("Resource = %q, want %q", config.Resource, "https://api.example.com")
	}

	if len(config.SupportedScopes) != 3 {
		t.Errorf("len(SupportedScopes) = %d, want %d", len(config.SupportedScopes), 3)
	}

	if config.GoogleAuth.ClientID != "test-client-id" {
		t.Errorf("GoogleAuth.ClientID = %q, want %q", config.GoogleAuth.ClientID, "test-client-id")
	}

	if config.RateLimit.Rate != 10 {
		t.Errorf("RateLimit.Rate = %d, want %d", config.RateLimit.Rate, 10)
	}

	if config.Security.MaxClientsPerIP != 10 {
		t.Errorf("Security.MaxClientsPerIP = %d, want %d", config.Security.MaxClientsPerIP, 10)
	}

	if config.CleanupInterval != 1*time.Minute {
		t.Errorf("CleanupInterval = %v, want %v", config.CleanupInterval, 1*time.Minute)
	}

	if config.Logger == nil {
		t.Error("Logger should not be nil")
	}

	if config.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}
}
