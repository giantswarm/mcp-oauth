package oauth

import (
	"testing"
	"time"
)

func TestTimeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant time.Duration
		expected time.Duration
	}{
		{"DefaultRefreshTokenTTL", DefaultRefreshTokenTTL, 90 * 24 * time.Hour},
		{"DefaultAuthorizationCodeTTL", DefaultAuthorizationCodeTTL, 10 * time.Minute},
		{"DefaultAccessTokenTTL", DefaultAccessTokenTTL, 1 * time.Hour},
		{"DefaultCleanupInterval", DefaultCleanupInterval, 1 * time.Minute},
		{"DefaultRateLimitCleanupInterval", DefaultRateLimitCleanupInterval, 5 * time.Minute},
		{"InactiveLimiterCleanupWindow", InactiveLimiterCleanupWindow, 10 * time.Minute},
		{"TokenRefreshThreshold", TokenRefreshThreshold, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestIntegerConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant int
		expected int
	}{
		{"TokenExpiringThreshold", TokenExpiringThreshold, 60},
		{"ClockSkewGrace", ClockSkewGrace, 5},
		{"DefaultMaxClientsPerIP", DefaultMaxClientsPerIP, 10},
		{"DefaultRateLimitRate", DefaultRateLimitRate, 10},
		{"DefaultRateLimitBurst", DefaultRateLimitBurst, 20},
		{"MinCodeVerifierLength", MinCodeVerifierLength, 43},
		{"MaxCodeVerifierLength", MaxCodeVerifierLength, 128},
		{"ClientIDTokenLength", ClientIDTokenLength, 32},
		{"ClientSecretTokenLength", ClientSecretTokenLength, 48},
		{"AccessTokenLength", AccessTokenLength, 48},
		{"RefreshTokenLength", RefreshTokenLength, 48},
		{"StateTokenLength", StateTokenLength, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestStringConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"DefaultTokenEndpointAuthMethod", DefaultTokenEndpointAuthMethod, "client_secret_basic"},
		{"ClientTypeConfidential", ClientTypeConfidential, "confidential"},
		{"ClientTypePublic", ClientTypePublic, "public"},
		{"PKCEMethodS256", PKCEMethodS256, "S256"},
		{"PKCEMethodPlain", PKCEMethodPlain, "plain"},
		{"SchemeHTTP", SchemeHTTP, "http"},
		{"SchemeHTTPS", SchemeHTTPS, "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestSliceConstants(t *testing.T) {
	t.Run("AllowedHTTPSchemes", func(t *testing.T) {
		expected := []string{"http", "https"}
		if len(AllowedHTTPSchemes) != len(expected) {
			t.Errorf("len(AllowedHTTPSchemes) = %d, want %d", len(AllowedHTTPSchemes), len(expected))
		}
		for i, scheme := range AllowedHTTPSchemes {
			if scheme != expected[i] {
				t.Errorf("AllowedHTTPSchemes[%d] = %q, want %q", i, scheme, expected[i])
			}
		}
	})

	t.Run("DangerousSchemes", func(t *testing.T) {
		expected := []string{"javascript", "data", "file", "vbscript", "about"}
		if len(DangerousSchemes) != len(expected) {
			t.Errorf("len(DangerousSchemes) = %d, want %d", len(DangerousSchemes), len(expected))
		}
	})

	t.Run("LoopbackAddresses", func(t *testing.T) {
		expected := []string{"localhost", "127.0.0.1", "::1", "[::1]"}
		if len(LoopbackAddresses) != len(expected) {
			t.Errorf("len(LoopbackAddresses) = %d, want %d", len(LoopbackAddresses), len(expected))
		}
	})

	t.Run("DefaultGrantTypes", func(t *testing.T) {
		expected := []string{"authorization_code", "refresh_token"}
		if len(DefaultGrantTypes) != len(expected) {
			t.Errorf("len(DefaultGrantTypes) = %d, want %d", len(DefaultGrantTypes), len(expected))
		}
	})

	t.Run("DefaultResponseTypes", func(t *testing.T) {
		expected := []string{"code"}
		if len(DefaultResponseTypes) != len(expected) {
			t.Errorf("len(DefaultResponseTypes) = %d, want %d", len(DefaultResponseTypes), len(expected))
		}
	})

	t.Run("SupportedCodeChallengeMethods", func(t *testing.T) {
		expected := []string{PKCEMethodS256}
		if len(SupportedCodeChallengeMethods) != len(expected) {
			t.Errorf("len(SupportedCodeChallengeMethods) = %d, want %d", len(SupportedCodeChallengeMethods), len(expected))
		}
		if SupportedCodeChallengeMethods[0] != PKCEMethodS256 {
			t.Errorf("SupportedCodeChallengeMethods[0] = %q, want %q", SupportedCodeChallengeMethods[0], PKCEMethodS256)
		}
	})

	t.Run("SupportedTokenAuthMethods", func(t *testing.T) {
		expected := []string{"client_secret_basic", "client_secret_post", "none"}
		if len(SupportedTokenAuthMethods) != len(expected) {
			t.Errorf("len(SupportedTokenAuthMethods) = %d, want %d", len(SupportedTokenAuthMethods), len(expected))
		}
	})
}

func TestPKCELengthConstraints(t *testing.T) {
	// Verify PKCE length constraints match RFC 7636
	if MinCodeVerifierLength < 43 {
		t.Errorf("MinCodeVerifierLength = %d, should be at least 43 per RFC 7636", MinCodeVerifierLength)
	}

	if MaxCodeVerifierLength > 128 {
		t.Errorf("MaxCodeVerifierLength = %d, should be at most 128 per RFC 7636", MaxCodeVerifierLength)
	}

	if MinCodeVerifierLength > MaxCodeVerifierLength {
		t.Errorf("MinCodeVerifierLength (%d) > MaxCodeVerifierLength (%d)", MinCodeVerifierLength, MaxCodeVerifierLength)
	}
}

func TestSecurityConstants(t *testing.T) {
	// Verify only S256 is supported (OAuth 2.1 requirement)
	if len(SupportedCodeChallengeMethods) != 1 || SupportedCodeChallengeMethods[0] != "S256" {
		t.Error("Only S256 PKCE method should be supported (OAuth 2.1)")
	}

	// Verify dangerous schemes are properly defined
	dangerous := map[string]bool{
		"javascript": false,
		"data":       false,
		"file":       false,
		"vbscript":   false,
		"about":      false,
	}

	for _, scheme := range DangerousSchemes {
		if _, ok := dangerous[scheme]; ok {
			dangerous[scheme] = true
		}
	}

	for scheme, found := range dangerous {
		if !found {
			t.Errorf("Dangerous scheme %q not found in DangerousSchemes", scheme)
		}
	}
}

func TestTokenLengthSecurity(t *testing.T) {
	// Verify token lengths provide adequate security (at least 256 bits of entropy)
	minSecureLength := 32 // 32 bytes = 256 bits

	if ClientIDTokenLength < minSecureLength {
		t.Errorf("ClientIDTokenLength = %d, should be at least %d for security", ClientIDTokenLength, minSecureLength)
	}

	if ClientSecretTokenLength < minSecureLength {
		t.Errorf("ClientSecretTokenLength = %d, should be at least %d for security", ClientSecretTokenLength, minSecureLength)
	}

	if AccessTokenLength < minSecureLength {
		t.Errorf("AccessTokenLength = %d, should be at least %d for security", AccessTokenLength, minSecureLength)
	}

	if RefreshTokenLength < minSecureLength {
		t.Errorf("RefreshTokenLength = %d, should be at least %d for security", RefreshTokenLength, minSecureLength)
	}

	if StateTokenLength < minSecureLength {
		t.Errorf("StateTokenLength = %d, should be at least %d for security", StateTokenLength, minSecureLength)
	}
}
