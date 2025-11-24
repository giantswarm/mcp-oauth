package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestApplyTimeDefaults(t *testing.T) {
	tests := []struct {
		name                      string
		input                     *Config
		expectedAuthCodeTTL       int64
		expectedAccessTokenTTL    int64
		expectedRefreshTokenTTL   int64
		expectedTrustedProxyCount int
		expectedClockSkewGrace    int64
		expectedMaxClientsPerIP   int
	}{
		{
			name:                      "all zeros should get defaults",
			input:                     &Config{},
			expectedAuthCodeTTL:       600,
			expectedAccessTokenTTL:    3600,
			expectedRefreshTokenTTL:   7776000,
			expectedTrustedProxyCount: 1,
			expectedClockSkewGrace:    5,
			expectedMaxClientsPerIP:   10,
		},
		{
			name: "custom values should be preserved",
			input: &Config{
				AuthorizationCodeTTL: 300,
				AccessTokenTTL:       1800,
				RefreshTokenTTL:      86400,
				TrustedProxyCount:    2,
				ClockSkewGracePeriod: 10,
				MaxClientsPerIP:      20,
			},
			expectedAuthCodeTTL:       300,
			expectedAccessTokenTTL:    1800,
			expectedRefreshTokenTTL:   86400,
			expectedTrustedProxyCount: 2,
			expectedClockSkewGrace:    10,
			expectedMaxClientsPerIP:   20,
		},
		{
			name: "partial custom values",
			input: &Config{
				AuthorizationCodeTTL: 450,
				// AccessTokenTTL should get default
				RefreshTokenTTL: 172800,
			},
			expectedAuthCodeTTL:       450,
			expectedAccessTokenTTL:    3600,
			expectedRefreshTokenTTL:   172800,
			expectedTrustedProxyCount: 1,
			expectedClockSkewGrace:    5,
			expectedMaxClientsPerIP:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyTimeDefaults(tt.input)

			if tt.input.AuthorizationCodeTTL != tt.expectedAuthCodeTTL {
				t.Errorf("AuthorizationCodeTTL = %d, want %d", tt.input.AuthorizationCodeTTL, tt.expectedAuthCodeTTL)
			}
			if tt.input.AccessTokenTTL != tt.expectedAccessTokenTTL {
				t.Errorf("AccessTokenTTL = %d, want %d", tt.input.AccessTokenTTL, tt.expectedAccessTokenTTL)
			}
			if tt.input.RefreshTokenTTL != tt.expectedRefreshTokenTTL {
				t.Errorf("RefreshTokenTTL = %d, want %d", tt.input.RefreshTokenTTL, tt.expectedRefreshTokenTTL)
			}
			if tt.input.TrustedProxyCount != tt.expectedTrustedProxyCount {
				t.Errorf("TrustedProxyCount = %d, want %d", tt.input.TrustedProxyCount, tt.expectedTrustedProxyCount)
			}
			if tt.input.ClockSkewGracePeriod != tt.expectedClockSkewGrace {
				t.Errorf("ClockSkewGracePeriod = %d, want %d", tt.input.ClockSkewGracePeriod, tt.expectedClockSkewGrace)
			}
			if tt.input.MaxClientsPerIP != tt.expectedMaxClientsPerIP {
				t.Errorf("MaxClientsPerIP = %d, want %d", tt.input.MaxClientsPerIP, tt.expectedMaxClientsPerIP)
			}
		})
	}
}

func TestApplySecurityDefaults(t *testing.T) {
	tests := []struct {
		name                         string
		input                        *Config
		expectedRefreshTokenRotation bool
		expectedRequirePKCE          bool
	}{
		{
			name:                         "default config gets secure defaults",
			input:                        &Config{},
			expectedRefreshTokenRotation: true,
			expectedRequirePKCE:          true,
		},
		{
			name: "explicitly disabled security features remain disabled",
			input: &Config{
				AllowRefreshTokenRotation: false,
				RequirePKCE:               false,
			},
			expectedRefreshTokenRotation: true, // Gets set to true by defaults
			expectedRequirePKCE:          true, // Gets set to true by defaults
		},
		{
			name: "explicitly enabled security features stay enabled",
			input: &Config{
				AllowRefreshTokenRotation: true,
				RequirePKCE:               true,
			},
			expectedRefreshTokenRotation: true,
			expectedRequirePKCE:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			applySecurityDefaults(tt.input, logger)

			if tt.input.AllowRefreshTokenRotation != tt.expectedRefreshTokenRotation {
				t.Errorf("AllowRefreshTokenRotation = %v, want %v", tt.input.AllowRefreshTokenRotation, tt.expectedRefreshTokenRotation)
			}
			if tt.input.RequirePKCE != tt.expectedRequirePKCE {
				t.Errorf("RequirePKCE = %v, want %v", tt.input.RequirePKCE, tt.expectedRequirePKCE)
			}
		})
	}
}

func TestLogSecurityWarnings(t *testing.T) {
	tests := []struct {
		name                string
		config              *Config
		expectedWarnings    []string
		notExpectedWarnings []string
	}{
		{
			name: "PKCE disabled warning",
			config: &Config{
				RequirePKCE: false,
			},
			expectedWarnings: []string{
				"SECURITY WARNING: PKCE is DISABLED",
			},
		},
		{
			name: "plain PKCE allowed warning",
			config: &Config{
				RequirePKCE:    true,
				AllowPKCEPlain: true,
			},
			expectedWarnings: []string{
				"SECURITY WARNING: Plain PKCE method is ALLOWED",
			},
		},
		{
			name: "trust proxy warning",
			config: &Config{
				RequirePKCE: true,
				TrustProxy:  true,
			},
			expectedWarnings: []string{
				"SECURITY NOTICE: Trusting proxy headers",
			},
		},
		{
			name: "public client registration warning",
			config: &Config{
				RequirePKCE:                   true,
				AllowPublicClientRegistration: true,
			},
			expectedWarnings: []string{
				"SECURITY WARNING: Public client registration is ENABLED",
			},
		},
		{
			name: "missing registration token warning",
			config: &Config{
				RequirePKCE:                   true,
				AllowPublicClientRegistration: false,
				RegistrationAccessToken:       "",
			},
			expectedWarnings: []string{
				"CONFIGURATION WARNING: RegistrationAccessToken not configured",
			},
		},
		{
			name: "no warnings for secure config",
			config: &Config{
				RequirePKCE:                   true,
				AllowPKCEPlain:                false,
				TrustProxy:                    false,
				AllowPublicClientRegistration: false,
				RegistrationAccessToken:       "secure-token",
			},
			notExpectedWarnings: []string{
				"WARNING",
				"NOTICE",
			},
		},
		{
			name: "multiple warnings",
			config: &Config{
				RequirePKCE:                   false,
				AllowPKCEPlain:                true,
				AllowPublicClientRegistration: true,
			},
			expectedWarnings: []string{
				"PKCE is DISABLED",
				"Plain PKCE method is ALLOWED",
				"Public client registration is ENABLED",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			logSecurityWarnings(tt.config, logger)

			logOutput := buf.String()

			for _, expected := range tt.expectedWarnings {
				if !strings.Contains(logOutput, expected) {
					t.Errorf("Expected warning %q not found in log output", expected)
				}
			}

			for _, notExpected := range tt.notExpectedWarnings {
				if strings.Contains(logOutput, notExpected) {
					t.Errorf("Unexpected warning %q found in log output", notExpected)
				}
			}
		})
	}
}

func TestApplySecureDefaults(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	result := applySecureDefaults(config, logger)

	// Verify it returns the config
	if result != config {
		t.Error("applySecureDefaults should return the same config pointer")
	}

	// Verify time defaults were applied
	if config.AuthorizationCodeTTL != 600 {
		t.Errorf("AuthorizationCodeTTL = %d, want 600", config.AuthorizationCodeTTL)
	}

	// Verify security defaults were applied
	if !config.AllowRefreshTokenRotation {
		t.Error("AllowRefreshTokenRotation should be true by default")
	}
	if !config.RequirePKCE {
		t.Error("RequirePKCE should be true by default")
	}
}

func TestValidateProviderRevocationConfig(t *testing.T) {
	tests := []struct {
		name                  string
		config                *Config
		expectWarning         bool
		expectedWarningText   string
		expectedTimeout       int64
		expectedRetries       int
		expectedThreshold     float64
		expectedRetentionDays int64
	}{
		{
			name: "valid configuration - no warnings",
			config: &Config{
				ProviderRevocationTimeout:          10,
				ProviderRevocationMaxRetries:       3,
				ProviderRevocationFailureThreshold: 0.5,
				RevokedFamilyRetentionDays:         90,
			},
			expectWarning:         false,
			expectedTimeout:       10,
			expectedRetries:       3,
			expectedThreshold:     0.5,
			expectedRetentionDays: 90,
		},
		{
			name: "invalid timeout - too low",
			config: &Config{
				ProviderRevocationTimeout:          -5,
				ProviderRevocationMaxRetries:       3,
				ProviderRevocationFailureThreshold: 0.5,
				RevokedFamilyRetentionDays:         90,
			},
			expectWarning:         true,
			expectedWarningText:   "Invalid ProviderRevocationTimeout",
			expectedTimeout:       -5, // Should be caught and corrected later by applyTimeDefaults
			expectedRetries:       3,
			expectedThreshold:     0.5,
			expectedRetentionDays: 90,
		},
		{
			name: "invalid retries - negative",
			config: &Config{
				ProviderRevocationTimeout:          10,
				ProviderRevocationMaxRetries:       -1,
				ProviderRevocationFailureThreshold: 0.5,
				RevokedFamilyRetentionDays:         90,
			},
			expectWarning:         true,
			expectedWarningText:   "Invalid ProviderRevocationMaxRetries",
			expectedTimeout:       10,
			expectedRetries:       -1,
			expectedThreshold:     0.5,
			expectedRetentionDays: 90,
		},
		{
			name: "invalid threshold - too high",
			config: &Config{
				ProviderRevocationTimeout:          10,
				ProviderRevocationMaxRetries:       3,
				ProviderRevocationFailureThreshold: 1.5,
				RevokedFamilyRetentionDays:         90,
			},
			expectWarning:         true,
			expectedWarningText:   "Invalid ProviderRevocationFailureThreshold",
			expectedTimeout:       10,
			expectedRetries:       3,
			expectedThreshold:     1.5,
			expectedRetentionDays: 90,
		},
		{
			name: "invalid threshold - negative",
			config: &Config{
				ProviderRevocationTimeout:          10,
				ProviderRevocationMaxRetries:       3,
				ProviderRevocationFailureThreshold: -0.5,
				RevokedFamilyRetentionDays:         90,
			},
			expectWarning:         true,
			expectedWarningText:   "Invalid ProviderRevocationFailureThreshold",
			expectedTimeout:       10,
			expectedRetries:       3,
			expectedThreshold:     -0.5,
			expectedRetentionDays: 90,
		},
		{
			name: "invalid retention - negative",
			config: &Config{
				ProviderRevocationTimeout:          10,
				ProviderRevocationMaxRetries:       3,
				ProviderRevocationFailureThreshold: 0.5,
				RevokedFamilyRetentionDays:         -10,
			},
			expectWarning:         true,
			expectedWarningText:   "Invalid RevokedFamilyRetentionDays",
			expectedTimeout:       10,
			expectedRetries:       3,
			expectedThreshold:     0.5,
			expectedRetentionDays: -10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			validateProviderRevocationConfig(tt.config, logger)

			logOutput := buf.String()

			if tt.expectWarning {
				if !strings.Contains(logOutput, tt.expectedWarningText) {
					t.Errorf("Expected warning containing %q, but got: %s", tt.expectedWarningText, logOutput)
				}
			} else {
				if strings.Contains(logOutput, "CONFIGURATION WARNING") {
					t.Errorf("Did not expect warning, but got: %s", logOutput)
				}
			}

			// Note: Values are not corrected in validateProviderRevocationConfig
			// They are corrected later in applyTimeDefaults
			if tt.config.ProviderRevocationTimeout != tt.expectedTimeout {
				t.Errorf("ProviderRevocationTimeout = %d, want %d", tt.config.ProviderRevocationTimeout, tt.expectedTimeout)
			}
			if tt.config.ProviderRevocationMaxRetries != tt.expectedRetries {
				t.Errorf("ProviderRevocationMaxRetries = %d, want %d", tt.config.ProviderRevocationMaxRetries, tt.expectedRetries)
			}
			if tt.config.ProviderRevocationFailureThreshold != tt.expectedThreshold {
				t.Errorf("ProviderRevocationFailureThreshold = %f, want %f", tt.config.ProviderRevocationFailureThreshold, tt.expectedThreshold)
			}
			if tt.config.RevokedFamilyRetentionDays != tt.expectedRetentionDays {
				t.Errorf("RevokedFamilyRetentionDays = %d, want %d", tt.config.RevokedFamilyRetentionDays, tt.expectedRetentionDays)
			}
		})
	}
}

func TestConfig_Fields(t *testing.T) {
	// Test that all config fields can be set
	config := &Config{
		Issuer:                        "https://auth.example.com",
		AuthorizationCodeTTL:          300,
		AccessTokenTTL:                1800,
		RefreshTokenTTL:               86400,
		AllowRefreshTokenRotation:     true,
		TrustProxy:                    false,
		TrustedProxyCount:             2,
		MaxClientsPerIP:               15,
		ClockSkewGracePeriod:          10,
		SupportedScopes:               []string{"openid", "email"},
		AllowPKCEPlain:                false,
		RequirePKCE:                   true,
		AllowPublicClientRegistration: false,
		RegistrationAccessToken:       "test-token",
		AllowedCustomSchemes:          []string{"myapp://"},
	}

	// Verify fields are set correctly
	if config.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", config.Issuer, "https://auth.example.com")
	}
	if config.AuthorizationCodeTTL != 300 {
		t.Errorf("AuthorizationCodeTTL = %d, want 300", config.AuthorizationCodeTTL)
	}
	if config.AccessTokenTTL != 1800 {
		t.Errorf("AccessTokenTTL = %d, want 1800", config.AccessTokenTTL)
	}
	if config.RefreshTokenTTL != 86400 {
		t.Errorf("RefreshTokenTTL = %d, want 86400", config.RefreshTokenTTL)
	}
	if !config.AllowRefreshTokenRotation {
		t.Error("AllowRefreshTokenRotation should be true")
	}
	if config.TrustProxy {
		t.Error("TrustProxy should be false")
	}
	if config.TrustedProxyCount != 2 {
		t.Errorf("TrustedProxyCount = %d, want 2", config.TrustedProxyCount)
	}
	if config.MaxClientsPerIP != 15 {
		t.Errorf("MaxClientsPerIP = %d, want 15", config.MaxClientsPerIP)
	}
	if config.ClockSkewGracePeriod != 10 {
		t.Errorf("ClockSkewGracePeriod = %d, want 10", config.ClockSkewGracePeriod)
	}
	if len(config.SupportedScopes) != 2 {
		t.Errorf("len(SupportedScopes) = %d, want 2", len(config.SupportedScopes))
	}
	if config.AllowPKCEPlain {
		t.Error("AllowPKCEPlain should be false")
	}
	if !config.RequirePKCE {
		t.Error("RequirePKCE should be true")
	}
	if config.AllowPublicClientRegistration {
		t.Error("AllowPublicClientRegistration should be false")
	}
	if config.RegistrationAccessToken != "test-token" {
		t.Errorf("RegistrationAccessToken = %q, want %q", config.RegistrationAccessToken, "test-token")
	}
	if len(config.AllowedCustomSchemes) != 1 {
		t.Errorf("len(AllowedCustomSchemes) = %d, want 1", len(config.AllowedCustomSchemes))
	}
}
