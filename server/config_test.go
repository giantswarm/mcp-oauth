package server

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
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
				ProductionMode:                true, // Secure default: production mode enabled
				AllowLocalhostRedirectURIs:    true, // RFC 8252 native app support
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

func TestConfig_EndpointHelpers(t *testing.T) {
	tests := []struct {
		name           string
		issuer         string
		wantAuth       string
		wantToken      string
		wantReg        string
		wantRevoke     string
		wantIntrospect string
	}{
		{
			name:           "standard HTTPS issuer",
			issuer:         "https://auth.example.com",
			wantAuth:       "https://auth.example.com/oauth/authorize",
			wantToken:      "https://auth.example.com/oauth/token",
			wantReg:        "https://auth.example.com/oauth/register",
			wantRevoke:     "https://auth.example.com/oauth/revoke",
			wantIntrospect: "https://auth.example.com/oauth/introspect",
		},
		{
			name:           "issuer with port",
			issuer:         "https://auth.example.com:8443",
			wantAuth:       "https://auth.example.com:8443/oauth/authorize",
			wantToken:      "https://auth.example.com:8443/oauth/token",
			wantReg:        "https://auth.example.com:8443/oauth/register",
			wantRevoke:     "https://auth.example.com:8443/oauth/revoke",
			wantIntrospect: "https://auth.example.com:8443/oauth/introspect",
		},
		{
			name:           "localhost development",
			issuer:         "http://localhost:3000",
			wantAuth:       "http://localhost:3000/oauth/authorize",
			wantToken:      "http://localhost:3000/oauth/token",
			wantReg:        "http://localhost:3000/oauth/register",
			wantRevoke:     "http://localhost:3000/oauth/revoke",
			wantIntrospect: "http://localhost:3000/oauth/introspect",
		},
		{
			name:           "issuer with trailing slash",
			issuer:         "https://auth.example.com/",
			wantAuth:       "https://auth.example.com//oauth/authorize",
			wantToken:      "https://auth.example.com//oauth/token",
			wantReg:        "https://auth.example.com//oauth/register",
			wantRevoke:     "https://auth.example.com//oauth/revoke",
			wantIntrospect: "https://auth.example.com//oauth/introspect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Issuer: tt.issuer,
			}

			if got := config.AuthorizationEndpoint(); got != tt.wantAuth {
				t.Errorf("AuthorizationEndpoint() = %q, want %q", got, tt.wantAuth)
			}

			if got := config.TokenEndpoint(); got != tt.wantToken {
				t.Errorf("TokenEndpoint() = %q, want %q", got, tt.wantToken)
			}

			if got := config.RegistrationEndpoint(); got != tt.wantReg {
				t.Errorf("RegistrationEndpoint() = %q, want %q", got, tt.wantReg)
			}

			if got := config.RevocationEndpoint(); got != tt.wantRevoke {
				t.Errorf("RevocationEndpoint() = %q, want %q", got, tt.wantRevoke)
			}

			if got := config.IntrospectionEndpoint(); got != tt.wantIntrospect {
				t.Errorf("IntrospectionEndpoint() = %q, want %q", got, tt.wantIntrospect)
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

// CORS validation tests

func TestValidateCORSConfig_Disabled(t *testing.T) {
	// CORS disabled (no origins) should not panic or warn
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins:   []string{}, // Empty = disabled
			AllowCredentials: true,
		},
	}

	// Should not panic
	validateCORSConfig(config, logger)

	logOutput := buf.String()
	if strings.Contains(logOutput, "CORS") {
		t.Error("Should not log CORS warnings when CORS is disabled")
	}
}

func TestValidateCORSConfig_WildcardWithCredentials(t *testing.T) {
	// Wildcard with credentials should panic (violates CORS spec)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowCredentials: true,
		},
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("Expected panic for wildcard with credentials, but got none")
		}
		panicMsg := r.(string)
		if !strings.Contains(panicMsg, "wildcard") || !strings.Contains(panicMsg, "AllowCredentials") {
			t.Errorf("Panic message should mention wildcard and credentials, got: %s", panicMsg)
		}
	}()

	validateCORSConfig(config, logger)
}

func TestValidateCORSConfig_WildcardWithoutCredentials(t *testing.T) {
	// Wildcard with AllowWildcardOrigin=true should warn but not panic
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins:      []string{"*"},
			AllowWildcardOrigin: true, // Must explicitly opt-in
			AllowCredentials:    false,
		},
	}

	// Should not panic
	validateCORSConfig(config, logger)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "Wildcard origin") {
		t.Error("Should log warning for wildcard origin")
	}
}

func TestValidateCORSConfig_WildcardWithoutOptIn(t *testing.T) {
	// Wildcard without AllowWildcardOrigin=true should panic
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins:      []string{"*"},
			AllowWildcardOrigin: false, // Not opted-in
			AllowCredentials:    false,
		},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for wildcard without AllowWildcardOrigin=true")
		} else {
			msg, ok := r.(string)
			if !ok || !strings.Contains(msg, "AllowWildcardOrigin=true") {
				t.Errorf("Unexpected panic message: %v", r)
			}
		}
	}()

	validateCORSConfig(config, logger)
}

func TestValidateCORSConfig_InvalidOriginFormat(t *testing.T) {
	tests := []struct {
		name          string
		origin        string
		expectedError string
	}{
		{
			name:          "no scheme",
			origin:        "example.com",
			expectedError: "invalid origin format",
		},
		{
			name:          "no host",
			origin:        "https://",
			expectedError: "invalid origin format",
		},
		{
			name:          "not a url",
			origin:        "not-a-url",
			expectedError: "invalid origin format",
		},
		{
			name:          "trailing slash",
			origin:        "https://app.example.com/",
			expectedError: "should not have trailing slash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			config := &Config{
				CORS: CORSConfig{
					AllowedOrigins:   []string{tt.origin},
					AllowCredentials: false,
				},
			}

			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("Expected panic for invalid origin %q, but got none", tt.origin)
					return
				}
				panicMsg := r.(string)
				if !strings.Contains(panicMsg, tt.expectedError) {
					t.Errorf("Expected panic containing %q, got: %s", tt.expectedError, panicMsg)
				}
			}()

			validateCORSConfig(config, logger)
		})
	}
}

func TestValidateCORSConfig_HTTPOriginRejected(t *testing.T) {
	// HTTP origin (non-localhost) should be rejected when AllowInsecureHTTP=false
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		AllowInsecureHTTP: false,
		CORS: CORSConfig{
			AllowedOrigins:   []string{"http://app.example.com"},
			AllowCredentials: false,
		},
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("Expected panic for HTTP origin without AllowInsecureHTTP, but got none")
			return
		}
		panicMsg := r.(string)
		if !strings.Contains(panicMsg, "HTTP origin") {
			t.Errorf("Expected panic about HTTP origin, got: %s", panicMsg)
		}
	}()

	validateCORSConfig(config, logger)
}

func TestValidateCORSConfig_HTTPLocalhostAllowed(t *testing.T) {
	// HTTP localhost should be allowed for development
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	localhostOrigins := []string{
		"http://localhost:3000",
		"http://127.0.0.1:8080",
		"http://localhost",
	}

	for _, origin := range localhostOrigins {
		t.Run(origin, func(t *testing.T) {
			config := &Config{
				AllowInsecureHTTP: false,
				CORS: CORSConfig{
					AllowedOrigins:   []string{origin},
					AllowCredentials: false,
				},
			}

			// Should not panic
			validateCORSConfig(config, logger)

			logOutput := buf.String()
			if !strings.Contains(logOutput, "localhost/development") {
				t.Error("Should log warning for HTTP localhost")
			}
		})
	}
}

func TestValidateCORSConfig_HTTPAllowedWithFlag(t *testing.T) {
	// HTTP origin should be allowed when AllowInsecureHTTP=true
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		AllowInsecureHTTP: true,
		CORS: CORSConfig{
			AllowedOrigins:   []string{"http://app.example.com"},
			AllowCredentials: false,
		},
	}

	// Should not panic
	validateCORSConfig(config, logger)
}

func TestValidateCORSConfig_ValidOrigins(t *testing.T) {
	// Valid origins should pass without panic
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins: []string{
				"https://app.example.com",
				"https://dashboard.example.com:8443",
				"https://api.example.com",
			},
			AllowCredentials: true,
		},
	}

	// Should not panic
	validateCORSConfig(config, logger)

	logOutput := buf.String()
	// Check that no warnings or errors were logged (only debug message)
	if strings.Contains(logOutput, "WARNING") || strings.Contains(logOutput, "ERROR") {
		t.Errorf("Should not log warnings or errors for valid config, got: %s", logOutput)
	}
}

func TestValidateCORSConfig_MultipleOrigins(t *testing.T) {
	// Multiple valid origins should all be validated
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		CORS: CORSConfig{
			AllowedOrigins: []string{
				"https://app1.example.com",
				"https://app2.example.com",
				"https://app3.example.com",
			},
			AllowCredentials: true,
			MaxAge:           7200,
		},
	}

	// Should not panic
	validateCORSConfig(config, logger)

	// Check that validation succeeded by checking for debug log
	logOutput := buf.String()
	if !strings.Contains(logOutput, "CORS configuration validated") || !strings.Contains(logOutput, "allowed_origins_count=3") {
		t.Errorf("Should log correct origin count in debug message, got: %s", logOutput)
	}
}

// WWW-Authenticate validation tests

func TestValidateWWWAuthenticateConfig_EmptyScopes(t *testing.T) {
	// No scopes should not generate warnings
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		Issuer:                         "https://auth.example.com",
		DisableWWWAuthenticateMetadata: false,
		DefaultChallengeScopes:         []string{}, // Empty
	}

	validateWWWAuthenticateConfig(config, logger)

	logOutput := buf.String()
	if strings.Contains(logOutput, "WARNING") {
		t.Errorf("Should not log warnings for empty scopes, got: %s", logOutput)
	}
}

func TestValidateWWWAuthenticateConfig_ValidScopes(t *testing.T) {
	// Valid scopes should not generate warnings
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:                         "https://auth.example.com",
		DisableWWWAuthenticateMetadata: false,
		DefaultChallengeScopes:         []string{"mcp:access", "files:read", "user:profile"},
	}

	validateWWWAuthenticateConfig(config, logger)

	logOutput := buf.String()
	// Should only have debug log, no warnings
	if strings.Contains(logOutput, "WARNING") {
		t.Errorf("Should not log warnings for valid scopes, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "WWW-Authenticate metadata enabled") {
		t.Errorf("Should log debug message for enabled metadata, got: %s", logOutput)
	}
}

func TestValidateWWWAuthenticateConfig_TooManyScopes(t *testing.T) {
	// More than 50 scopes should generate warning
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Create 51 scopes
	scopes := make([]string, 51)
	for i := 0; i < 51; i++ {
		scopes[i] = "scope:" + string(rune('a'+i%26))
	}

	config := &Config{
		Issuer:                         "https://auth.example.com",
		DisableWWWAuthenticateMetadata: false,
		DefaultChallengeScopes:         scopes,
	}

	validateWWWAuthenticateConfig(config, logger)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "Very large DefaultChallengeScopes configured") {
		t.Errorf("Should log warning for too many scopes, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "count=51") {
		t.Errorf("Should log actual scope count, got: %s", logOutput)
	}
}

func TestValidateWWWAuthenticateConfig_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name          string
		scopes        []string
		expectedError string
	}{
		{
			name:          "double quote in scope",
			scopes:        []string{`files:"read"`, "user:profile"},
			expectedError: "Invalid character in DefaultChallengeScopes",
		},
		{
			name:          "comma in scope",
			scopes:        []string{"files:read,write", "user:profile"},
			expectedError: "Invalid character in DefaultChallengeScopes",
		},
		{
			name:          "backslash in scope",
			scopes:        []string{`files:\read`, "user:profile"},
			expectedError: "Invalid character in DefaultChallengeScopes",
		},
		{
			name:          "multiple invalid characters",
			scopes:        []string{`files:"read\write,delete"`, "user:profile"},
			expectedError: "Invalid character in DefaultChallengeScopes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			config := &Config{
				Issuer:                         "https://auth.example.com",
				DisableWWWAuthenticateMetadata: false,
				DefaultChallengeScopes:         tt.scopes,
			}

			validateWWWAuthenticateConfig(config, logger)

			logOutput := buf.String()
			if !strings.Contains(logOutput, tt.expectedError) {
				t.Errorf("Expected warning containing %q, got: %s", tt.expectedError, logOutput)
			}
		})
	}
}

func TestValidateWWWAuthenticateConfig_DisabledMetadata(t *testing.T) {
	// Disabled metadata should not generate logs even with scopes
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &Config{
		Issuer:                         "https://auth.example.com",
		DisableWWWAuthenticateMetadata: true,
		DefaultChallengeScopes:         []string{"mcp:access", "files:read"},
	}

	validateWWWAuthenticateConfig(config, logger)

	logOutput := buf.String()
	// Should not log anything when metadata is disabled
	if strings.Contains(logOutput, "WWW-Authenticate metadata enabled") {
		t.Errorf("Should not log debug message when metadata is disabled, got: %s", logOutput)
	}
}

func TestValidateWWWAuthenticateConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		expectWarn bool
		warnSubstr string
	}{
		{
			name:       "exactly 50 scopes - should not warn",
			scopes:     make([]string, 50),
			expectWarn: false,
		},
		{
			name:       "51 scopes - should warn",
			scopes:     make([]string, 51),
			expectWarn: true,
			warnSubstr: "Very large DefaultChallengeScopes",
		},
		{
			name:       "valid characters: colon, hyphen, underscore, slash",
			scopes:     []string{"mcp:access", "files-read", "user_profile", "api/v1"},
			expectWarn: false,
		},
		{
			name:       "empty scope string",
			scopes:     []string{"", "files:read"},
			expectWarn: false, // Empty is technically valid (though not useful)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			// Initialize test scopes
			for i := range tt.scopes {
				if tt.scopes[i] == "" {
					continue
				}
				if tt.scopes[i] != "mcp:access" && tt.scopes[i] != "files-read" &&
					tt.scopes[i] != "user_profile" && tt.scopes[i] != "api/v1" && tt.scopes[i] != "files:read" {
					tt.scopes[i] = "scope" + string(rune('a'+i%26))
				}
			}

			config := &Config{
				Issuer:                         "https://auth.example.com",
				DisableWWWAuthenticateMetadata: false,
				DefaultChallengeScopes:         tt.scopes,
			}

			validateWWWAuthenticateConfig(config, logger)

			logOutput := buf.String()
			hasWarning := strings.Contains(logOutput, "WARNING")

			if tt.expectWarn && !hasWarning {
				t.Errorf("Expected warning but got none. Log: %s", logOutput)
			}
			if !tt.expectWarn && hasWarning {
				t.Errorf("Did not expect warning but got one. Log: %s", logOutput)
			}
			if tt.expectWarn && tt.warnSubstr != "" && !strings.Contains(logOutput, tt.warnSubstr) {
				t.Errorf("Expected warning containing %q, got: %s", tt.warnSubstr, logOutput)
			}
		})
	}
}

func TestConfig_ProtectedResourceMetadataEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{
			name:   "standard HTTPS issuer",
			issuer: "https://auth.example.com",
			want:   "https://auth.example.com/.well-known/oauth-protected-resource",
		},
		{
			name:   "issuer with port",
			issuer: "https://auth.example.com:8443",
			want:   "https://auth.example.com:8443/.well-known/oauth-protected-resource",
		},
		{
			name:   "localhost development",
			issuer: "http://localhost:3000",
			want:   "http://localhost:3000/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Issuer: tt.issuer,
			}

			if got := config.ProtectedResourceMetadataEndpoint(); got != tt.want {
				t.Errorf("ProtectedResourceMetadataEndpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Scope format validation tests (RFC 6749 Section 3.3)

func TestValidateScopeFormat(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantError bool
		errSubstr string
	}{
		{
			name:      "valid simple scope",
			scope:     "read",
			wantError: false,
		},
		{
			name:      "valid scope with colon",
			scope:     "files:read",
			wantError: false,
		},
		{
			name:      "valid scope with hyphen",
			scope:     "files-read",
			wantError: false,
		},
		{
			name:      "valid scope with underscore",
			scope:     "files_read",
			wantError: false,
		},
		{
			name:      "valid scope with slash",
			scope:     "api/v1",
			wantError: false,
		},
		{
			name:      "valid scope with dot",
			scope:     "files.read",
			wantError: false,
		},
		{
			name:      "valid scope with multiple special chars",
			scope:     "mcp:files-read_v1/api",
			wantError: false,
		},
		{
			name:      "empty scope",
			scope:     "",
			wantError: true,
			errSubstr: "cannot be empty",
		},
		{
			name:      "scope with space",
			scope:     "files read",
			wantError: true,
			errSubstr: "cannot contain space",
		},
		{
			name:      "scope with double quote",
			scope:     `files:"read"`,
			wantError: true,
			errSubstr: "cannot contain double-quote",
		},
		{
			name:      "scope with backslash",
			scope:     `files:\read`,
			wantError: true,
			errSubstr: "cannot contain backslash",
		},
		{
			name:      "scope with non-printable char",
			scope:     "files\x00read",
			wantError: true,
			errSubstr: "invalid character",
		},
		{
			name:      "scope with control char",
			scope:     "files\x1fread",
			wantError: true,
			errSubstr: "invalid character",
		},
		{
			name:      "scope with DEL char",
			scope:     "files\x7fread",
			wantError: true,
			errSubstr: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScopeFormat(tt.scope)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error for scope %q, got nil", tt.scope)
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing %q, got: %s", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for scope %q: %s", tt.scope, err)
				}
			}
		})
	}
}

func TestValidateEndpointScopeRequirements(t *testing.T) {
	tests := []struct {
		name          string
		pathScopes    map[string][]string
		methodScopes  map[string]map[string][]string
		expectWarning bool
		warnSubstr    string
	}{
		{
			name: "valid path scopes",
			pathScopes: map[string][]string{
				"/api/files/*": {"files:read", "files:write"},
			},
			expectWarning: false,
		},
		{
			name: "valid method scopes",
			methodScopes: map[string]map[string][]string{
				"/api/files/*": {
					"GET":  {"files:read"},
					"POST": {"files:write"},
				},
			},
			expectWarning: false,
		},
		{
			name: "invalid scope in path scopes",
			pathScopes: map[string][]string{
				"/api/files/*": {"files:read", "files write"}, // space is invalid
			},
			expectWarning: true,
			warnSubstr:    "Invalid scope format",
		},
		{
			name: "invalid scope in method scopes",
			methodScopes: map[string]map[string][]string{
				"/api/files/*": {
					"GET": {"files:read", `files:"write"`}, // double quote is invalid
				},
			},
			expectWarning: true,
			warnSubstr:    "Invalid scope format",
		},
		{
			name: "lowercase method warning",
			methodScopes: map[string]map[string][]string{
				"/api/files/*": {
					"get": {"files:read"}, // lowercase
				},
			},
			expectWarning: true,
			warnSubstr:    "should be uppercase",
		},
		{
			name: "wildcard method is valid",
			methodScopes: map[string]map[string][]string{
				"/api/files/*": {
					"*": {"files:read"},
				},
			},
			expectWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			config := &Config{
				EndpointScopeRequirements:       tt.pathScopes,
				EndpointMethodScopeRequirements: tt.methodScopes,
			}

			validateEndpointScopeRequirements(config, logger)

			logOutput := buf.String()
			hasWarning := strings.Contains(logOutput, "Invalid scope format") ||
				strings.Contains(logOutput, "should be uppercase")

			if tt.expectWarning && !hasWarning {
				t.Errorf("Expected warning but got none. Log: %s", logOutput)
			}
			if !tt.expectWarning && hasWarning {
				t.Errorf("Did not expect warning but got one. Log: %s", logOutput)
			}
			if tt.expectWarning && tt.warnSubstr != "" && !strings.Contains(logOutput, tt.warnSubstr) {
				t.Errorf("Expected warning containing %q, got: %s", tt.warnSubstr, logOutput)
			}
		})
	}
}

// TestValidateInterstitialConfig tests interstitial configuration validation
func TestValidateInterstitialConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		wantPanic   bool
		panicSubstr string
	}{
		{
			name:      "nil interstitial config",
			config:    &Config{Issuer: "https://example.com"},
			wantPanic: false,
		},
		{
			name: "valid branding config",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						LogoURL:            "https://cdn.example.com/logo.svg",
						LogoAlt:            "Example Logo",
						Title:              "Welcome",
						PrimaryColor:       "#4F46E5",
						BackgroundGradient: "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)",
					},
				},
			},
			wantPanic: false,
		},
		{
			name: "HTTP logo URL without AllowInsecureHTTP",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						LogoURL: "http://cdn.example.com/logo.svg",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "LogoURL must use HTTPS",
		},
		{
			name: "HTTP logo URL with AllowInsecureHTTP",
			config: &Config{
				Issuer:            "http://localhost:8080",
				AllowInsecureHTTP: true,
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						LogoURL: "http://localhost:8080/logo.svg",
					},
				},
			},
			wantPanic: false,
		},
		{
			name: "invalid logo URL",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						LogoURL: "://invalid-url",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "invalid LogoURL",
		},
		{
			name: "CustomCSS with style tag injection",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						CustomCSS: ".container { color: red; }</style><script>alert('xss')</script>",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "</style>",
		},
		{
			name: "CustomCSS with expression() injection",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						CustomCSS: ".container { width: expression(alert('xss')); }",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "expression(",
		},
		{
			name: "CustomCSS with javascript: injection",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						CustomCSS: ".container { background: url(javascript:alert('xss')); }",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "javascript:",
		},
		{
			name: "invalid primary color with expression",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						PrimaryColor: "expression(alert('xss'))",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "invalid PrimaryColor",
		},
		{
			name: "invalid background with javascript URL",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						BackgroundGradient: "url(javascript:alert('xss'))",
					},
				},
			},
			wantPanic:   true,
			panicSubstr: "invalid BackgroundGradient",
		},
		{
			name: "valid hex color",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						PrimaryColor: "#FF5733",
					},
				},
			},
			wantPanic: false,
		},
		{
			name: "valid rgb color",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						PrimaryColor: "rgb(255, 87, 51)",
					},
				},
			},
			wantPanic: false,
		},
		{
			name: "valid named color",
			config: &Config{
				Issuer: "https://example.com",
				Interstitial: &InterstitialConfig{
					Branding: &InterstitialBranding{
						PrimaryColor: "indigo",
					},
				},
			},
			wantPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if tt.wantPanic {
					if r == nil {
						t.Error("Expected panic but got none")
					} else {
						panicMsg := fmt.Sprintf("%v", r)
						if tt.panicSubstr != "" && !strings.Contains(panicMsg, tt.panicSubstr) {
							t.Errorf("Panic message should contain %q, got: %s", tt.panicSubstr, panicMsg)
						}
					}
				} else {
					if r != nil {
						t.Errorf("Did not expect panic but got: %v", r)
					}
				}
			}()

			logger := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
			validateInterstitialConfig(tt.config, logger)
		})
	}
}

func TestDNSValidationTimeoutBounds(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
		expectWarning   bool
		warningSubstr   string
	}{
		{
			name:            "zero timeout gets default",
			timeout:         0,
			expectedTimeout: 2 * time.Second,
			expectWarning:   false,
		},
		{
			name:            "valid timeout preserved",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
			expectWarning:   false,
		},
		{
			name:            "timeout at maximum is preserved",
			timeout:         30 * time.Second,
			expectedTimeout: 30 * time.Second,
			expectWarning:   false,
		},
		{
			name:            "timeout exceeding maximum is capped",
			timeout:         60 * time.Second,
			expectedTimeout: 30 * time.Second,
			expectWarning:   true,
			warningSubstr:   "exceeds maximum",
		},
		{
			name:            "very large timeout is capped",
			timeout:         5 * time.Minute,
			expectedTimeout: 30 * time.Second,
			expectWarning:   true,
			warningSubstr:   "exceeds maximum",
		},
		{
			name:            "negative timeout gets default",
			timeout:         -1 * time.Second,
			expectedTimeout: 2 * time.Second,
			expectWarning:   true,
			warningSubstr:   "cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			config := &Config{
				Issuer:               "https://auth.example.com",
				DNSValidationTimeout: tt.timeout,
			}

			applySecurityDefaults(config, logger)

			if config.DNSValidationTimeout != tt.expectedTimeout {
				t.Errorf("DNSValidationTimeout = %v, want %v", config.DNSValidationTimeout, tt.expectedTimeout)
			}

			logOutput := buf.String()
			if tt.expectWarning {
				if tt.warningSubstr != "" && !strings.Contains(logOutput, tt.warningSubstr) {
					t.Errorf("Expected warning containing %q, got: %s", tt.warningSubstr, logOutput)
				}
			}
		})
	}
}

func TestValidateTrustedPublicRegistrationSchemes(t *testing.T) {
	tests := []struct {
		name                   string
		inputSchemes           []string
		disableStrictMatching  bool
		expectedSchemes        []string
		expectSecurityLog      bool
		expectedStrictMatching bool
	}{
		{
			name:                   "empty schemes - no change",
			inputSchemes:           nil,
			expectedSchemes:        nil,
			expectSecurityLog:      false,
			expectedStrictMatching: false, // Not set when no schemes
		},
		{
			name:                   "valid custom schemes - preserved",
			inputSchemes:           []string{"cursor", "vscode"},
			expectedSchemes:        []string{"cursor", "vscode"},
			expectSecurityLog:      false,
			expectedStrictMatching: true, // Auto-enabled
		},
		{
			name:                   "http scheme - filtered out",
			inputSchemes:           []string{"cursor", "http", "vscode"},
			expectedSchemes:        []string{"cursor", "vscode"},
			expectSecurityLog:      true,
			expectedStrictMatching: true,
		},
		{
			name:                   "https scheme - filtered out",
			inputSchemes:           []string{"https", "cursor"},
			expectedSchemes:        []string{"cursor"},
			expectSecurityLog:      true,
			expectedStrictMatching: true,
		},
		{
			name:                   "both http and https - filtered out",
			inputSchemes:           []string{"http", "https"},
			expectedSchemes:        []string{},
			expectSecurityLog:      true,
			expectedStrictMatching: false, // No schemes left
		},
		{
			name:                   "dangerous schemes - filtered out",
			inputSchemes:           []string{"cursor", "javascript", "data"},
			expectedSchemes:        []string{"cursor"},
			expectSecurityLog:      true,
			expectedStrictMatching: true,
		},
		{
			name:                   "mixed case schemes - normalized to lowercase",
			inputSchemes:           []string{"Cursor", "VSCODE"},
			expectedSchemes:        []string{"cursor", "vscode"},
			expectSecurityLog:      false,
			expectedStrictMatching: true,
		},
		{
			name:                  "disable strict matching - stays disabled",
			inputSchemes:          []string{"cursor"},
			disableStrictMatching: true,
			expectedSchemes:       []string{"cursor"},
			expectSecurityLog:     false,
			// Note: DisableStrictSchemeMatching keeps it disabled
			expectedStrictMatching: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			config := &Config{
				Issuer:                           "https://auth.example.com",
				TrustedPublicRegistrationSchemes: tt.inputSchemes,
				DisableStrictSchemeMatching:      tt.disableStrictMatching,
			}

			// Apply full configuration pipeline
			applySecureDefaults(config, logger)

			// Verify schemes are filtered correctly
			if len(config.TrustedPublicRegistrationSchemes) != len(tt.expectedSchemes) {
				t.Errorf("TrustedPublicRegistrationSchemes length = %d, want %d",
					len(config.TrustedPublicRegistrationSchemes), len(tt.expectedSchemes))
			}

			for i, expected := range tt.expectedSchemes {
				if i < len(config.TrustedPublicRegistrationSchemes) {
					if config.TrustedPublicRegistrationSchemes[i] != expected {
						t.Errorf("TrustedPublicRegistrationSchemes[%d] = %q, want %q",
							i, config.TrustedPublicRegistrationSchemes[i], expected)
					}
				}
			}

			// Verify StrictSchemeMatching is set correctly
			if config.StrictSchemeMatching != tt.expectedStrictMatching {
				t.Errorf("StrictSchemeMatching = %v, want %v",
					config.StrictSchemeMatching, tt.expectedStrictMatching)
			}

			// Verify security log messages
			logOutput := buf.String()
			if tt.expectSecurityLog {
				if !strings.Contains(logOutput, "SECURITY") && !strings.Contains(logOutput, "Removing") {
					t.Errorf("Expected security log message, got: %s", logOutput)
				}
			}
		})
	}
}
