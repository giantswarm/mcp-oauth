package server

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newTestServerWithSecurityConfig creates a test server with specific redirect URI security settings.
// Note: This creates a server with a mock DNS resolver to avoid real DNS lookups in tests.
// The mock resolver returns a public IP (93.184.216.34) for all hostnames by default.
//
// Parameters control security features via explicit Disable* fields (secure by default pattern):
// - productionMode=false sets DisableProductionMode=true (allows HTTP on non-loopback)
// - dnsValidation=false sets DisableDNSValidation=true (disables DNS checks)
func newTestServerWithSecurityConfig(productionMode, allowLocalhost, allowPrivateIP, allowLinkLocal, dnsValidation bool) *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := memory.New()
	provider := mock.NewMockProvider()

	// Create mock DNS resolver that returns public IPs by default
	// This prevents tests from depending on real DNS resolution
	mockResolver := newMockDNSResolver()

	config := &Config{
		Issuer: "https://auth.example.com",
		// Use Disable* fields to opt-out of secure defaults
		DisableProductionMode:              !productionMode,
		DisableDNSValidation:               !dnsValidation,
		DisableDNSValidationStrict:         !dnsValidation, // Match strict to validation setting
		DisableAuthorizationTimeValidation: true,           // Disable for simpler testing
		// Allow* flags for specific relaxations
		AllowLocalhostRedirectURIs: allowLocalhost,
		AllowPrivateIPRedirectURIs: allowPrivateIP,
		AllowLinkLocalRedirectURIs: allowLinkLocal,
		// Always set these explicitly for tests
		BlockedRedirectSchemes: []string{"javascript", "data", "file", "vbscript", "about", "ftp", "blob", "ms-appx", "ms-appx-web"},
		DNSResolver:            mockResolver, // Use mock resolver to avoid real DNS
	}

	server, err := New(provider, store, store, store, config, logger)
	if err != nil {
		panic(err)
	}
	return server
}

func TestValidateRedirectURIForRegistration_BlockedSchemes(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		wantErr     bool
		errCategory string
	}{
		{
			name:        "javascript scheme blocked",
			redirectURI: "javascript:alert('xss')",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "data scheme blocked",
			redirectURI: "data:text/html,<script>alert('xss')</script>",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "file scheme blocked",
			redirectURI: "file:///etc/passwd",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "vbscript scheme blocked",
			redirectURI: "vbscript:MsgBox('xss')",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "about scheme blocked",
			redirectURI: "about:blank",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "ftp scheme blocked",
			redirectURI: "ftp://files.example.com/path",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "blob scheme blocked",
			redirectURI: "blob:https://example.com/uuid",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "ms-appx scheme blocked",
			redirectURI: "ms-appx://package/path",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "ms-appx-web scheme blocked",
			redirectURI: "ms-appx-web://package/path",
			wantErr:     true,
			errCategory: RedirectURIErrorCategoryBlockedScheme,
		},
		{
			name:        "HTTPS allowed",
			redirectURI: "https://app.example.com/callback",
			wantErr:     false,
		},
		{
			name:        "custom scheme myapp allowed",
			redirectURI: "myapp://callback",
			wantErr:     false,
		},
	}

	server := newTestServerWithSecurityConfig(true, true, false, false, false)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.ValidateRedirectURIForRegistration(ctx, tt.redirectURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURIForRegistration() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errCategory != "" {
				category := GetRedirectURIErrorCategory(err)
				if category != tt.errCategory {
					t.Errorf("Error category = %v, want %v", category, tt.errCategory)
				}
			}
		})
	}
}

func TestValidateRedirectURIForRegistration_ProductionMode(t *testing.T) {
	ctx := context.Background()

	// Note: ProductionMode is now ALWAYS true by default (secure by default).
	// There is no "development mode" that allows HTTP on non-loopback.
	// HTTP on loopback is controlled by AllowLocalhostRedirectURIs.

	t.Run("HTTP on non-loopback blocked (secure by default)", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		err := server.ValidateRedirectURIForRegistration(ctx, "http://app.example.com/callback")
		if err == nil {
			t.Error("Expected error for HTTP on non-loopback")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryHTTPNotAllowed {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryHTTPNotAllowed, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("HTTP on loopback allowed when AllowLocalhostRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		err := server.ValidateRedirectURIForRegistration(ctx, "http://localhost:8080/callback")
		if err != nil {
			t.Errorf("Expected no error for HTTP on localhost, got %v", err)
		}
	})

	t.Run("HTTPS always allowed", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		err := server.ValidateRedirectURIForRegistration(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for HTTPS, got %v", err)
		}
	})
}

func TestValidateRedirectURIForRegistration_Loopback(t *testing.T) {
	ctx := context.Background()

	loopbackURIs := []string{
		"http://localhost/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:3000/callback",
		"http://127.0.0.100/callback", // Full 127.0.0.0/8 range
		"http://[::1]/callback",       // IPv6 loopback
		"http://[::1]:8080/callback",  // IPv6 loopback with port
		"https://localhost/callback",  // HTTPS on localhost
		"https://127.0.0.1/callback",  // HTTPS on loopback IP
	}

	t.Run("Loopback allowed when AllowLocalhostRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		for _, uri := range loopbackURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected loopback URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})

	t.Run("Loopback blocked when AllowLocalhostRedirectURIs=false", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, false, false, false, false)
		for _, uri := range loopbackURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected loopback URI %s to be blocked", uri)
			}
		}
	})
}

func TestValidateRedirectURIForRegistration_PrivateIPs(t *testing.T) {
	ctx := context.Background()

	privateIPURIs := []string{
		"https://10.0.0.1/callback", // RFC 1918 Class A
		"https://10.255.255.255/callback",
		"https://172.16.0.1/callback", // RFC 1918 Class B
		"https://172.31.255.255/callback",
		"https://192.168.0.1/callback", // RFC 1918 Class C
		"https://192.168.255.255/callback",
	}

	t.Run("Private IPs blocked when AllowPrivateIPRedirectURIs=false", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		for _, uri := range privateIPURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected private IP URI %s to be blocked", uri)
			}
			if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryPrivateIP {
				t.Errorf("Expected category %s, got %s for %s", RedirectURIErrorCategoryPrivateIP, GetRedirectURIErrorCategory(err), uri)
			}
		}
	})

	t.Run("Private IPs allowed when AllowPrivateIPRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, true, false, false)
		for _, uri := range privateIPURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected private IP URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})
}

func TestValidateRedirectURIForRegistration_LinkLocalIPs(t *testing.T) {
	ctx := context.Background()

	linkLocalURIs := []string{
		"https://169.254.0.1/callback",     // IPv4 link-local
		"https://169.254.169.254/callback", // AWS/GCP/Azure metadata service!
		"https://[fe80::1]/callback",       // IPv6 link-local
	}

	t.Run("Link-local IPs blocked when AllowLinkLocalRedirectURIs=false", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		for _, uri := range linkLocalURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected link-local URI %s to be blocked", uri)
			}
			if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryLinkLocal {
				t.Errorf("Expected category %s, got %s for %s", RedirectURIErrorCategoryLinkLocal, GetRedirectURIErrorCategory(err), uri)
			}
		}
	})

	t.Run("Link-local IPs allowed when AllowLinkLocalRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, true, false)
		for _, uri := range linkLocalURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected link-local URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})
}

func TestValidateRedirectURIForRegistration_Fragments(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	t.Run("Fragment in URI blocked", func(t *testing.T) {
		err := server.ValidateRedirectURIForRegistration(ctx, "https://app.example.com/callback#fragment")
		if err == nil {
			t.Error("Expected error for URI with fragment")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryFragment {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryFragment, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("URI without fragment allowed", func(t *testing.T) {
		err := server.ValidateRedirectURIForRegistration(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for URI without fragment, got %v", err)
		}
	})
}

func TestValidateRedirectURIForRegistration_InvalidFormat(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	t.Run("Invalid URI format blocked", func(t *testing.T) {
		err := server.ValidateRedirectURIForRegistration(ctx, "://invalid")
		if err == nil {
			t.Error("Expected error for invalid URI format")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryInvalidFormat {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryInvalidFormat, GetRedirectURIErrorCategory(err))
		}
	})
}

func TestValidateRedirectURIsForRegistration_Multiple(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	t.Run("Multiple valid URIs allowed", func(t *testing.T) {
		uris := []string{
			"https://app.example.com/callback",
			"http://localhost:8080/callback",
			"myapp://callback",
		}
		err := server.ValidateRedirectURIsForRegistration(ctx, uris)
		if err != nil {
			t.Errorf("Expected no error for valid URIs, got %v", err)
		}
	})

	t.Run("Mixed valid and invalid URIs rejected", func(t *testing.T) {
		uris := []string{
			"https://app.example.com/callback",
			"javascript:alert('xss')", // Invalid
			"http://localhost:8080/callback",
		}
		err := server.ValidateRedirectURIsForRegistration(ctx, uris)
		if err == nil {
			t.Error("Expected error for mixed valid/invalid URIs")
		}
	})

	t.Run("Empty URI list rejected", func(t *testing.T) {
		err := server.ValidateRedirectURIsForRegistration(ctx, []string{})
		if err == nil {
			t.Error("Expected error for empty URI list")
		}
	})
}

func TestValidateRedirectURIForRegistration_CustomSchemes(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	validCustomSchemes := []string{
		"myapp://callback",
		"com.example.app://oauth/callback",
		"cursor://auth",
		"vscode://auth/callback",
	}

	for _, uri := range validCustomSchemes {
		t.Run("Valid custom scheme: "+uri, func(t *testing.T) {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected custom scheme URI %s to be allowed, got error: %v", uri, err)
			}
		})
	}
}

func TestValidateRedirectURIForRegistration_PublicIPs(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	publicIPURIs := []string{
		"https://8.8.8.8/callback",     // Google DNS (public)
		"https://1.1.1.1/callback",     // Cloudflare DNS (public)
		"https://203.0.113.1/callback", // TEST-NET-3 (documentation)
	}

	for _, uri := range publicIPURIs {
		t.Run("Public IP allowed: "+uri, func(t *testing.T) {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected public IP URI %s to be allowed, got error: %v", uri, err)
			}
		})
	}
}

func TestValidateRedirectURIForRegistration_UnspecifiedAddresses(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(true, true, false, false, false)

	unspecifiedURIs := []string{
		"https://0.0.0.0/callback", // IPv4 unspecified
		"https://0.0.0.0:8080/callback",
		"https://[::]/callback",      // IPv6 unspecified
		"https://[::]:8080/callback", // IPv6 unspecified with port
	}

	for _, uri := range unspecifiedURIs {
		t.Run("Unspecified address blocked: "+uri, func(t *testing.T) {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected unspecified address URI %s to be blocked", uri)
			}
			if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryUnspecifiedAddr {
				t.Errorf("Expected category %s, got %s for %s", RedirectURIErrorCategoryUnspecifiedAddr, GetRedirectURIErrorCategory(err), uri)
			}
		})
	}
}

func TestValidateRedirectURIForRegistration_IPv6EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("IPv6 loopback variations", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)

		// Note: net.IP.IsLoopback() correctly recognizes ::1 as loopback.
		// The full form 0:0:0:0:0:0:0:1 also works with net.ParseIP().
		loopbackIPv6URIs := []string{
			"http://[::1]/callback",
			"http://[::1]:8080/callback",
			"https://[::1]/callback",
		}

		for _, uri := range loopbackIPv6URIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected IPv6 loopback URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})

	t.Run("IPv6 link-local blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)

		// Note: Zone IDs (fe80::1%eth0) cannot be parsed by net.ParseIP,
		// so they are treated as hostnames and pass validation when DNS validation is disabled.
		// Only pure IPv6 link-local addresses are properly blocked.
		linkLocalIPv6URIs := []string{
			"https://[fe80::1]/callback",
			"https://[fe80::1234:5678:abcd:ef01]/callback",
		}

		for _, uri := range linkLocalIPv6URIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected IPv6 link-local URI %s to be blocked", uri)
			}
		}
	})

	t.Run("IPv6 private addresses blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)

		// fc00::/7 is the IPv6 Unique Local Address (ULA) range
		privateIPv6URIs := []string{
			"https://[fc00::1]/callback",
			"https://[fd00::1]/callback",
			"https://[fd12:3456:789a::1]/callback",
		}

		for _, uri := range privateIPv6URIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err == nil {
				t.Errorf("Expected IPv6 private URI %s to be blocked", uri)
			}
			if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryPrivateIP {
				t.Errorf("Expected category %s, got %s for %s", RedirectURIErrorCategoryPrivateIP, GetRedirectURIErrorCategory(err), uri)
			}
		}
	})

	t.Run("IPv6 public addresses allowed", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)

		// 2001:4860:4860::8888 is Google's public IPv6 DNS
		publicIPv6URIs := []string{
			"https://[2001:4860:4860::8888]/callback",
			"https://[2606:4700:4700::1111]/callback", // Cloudflare IPv6 DNS
			"https://[2001:db8::1]/callback",          // Documentation prefix (TEST)
		}

		for _, uri := range publicIPv6URIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected IPv6 public URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})

	t.Run("IPv6 unspecified always blocked", func(t *testing.T) {
		// Even with all permissions enabled, unspecified addresses should be blocked
		server := newTestServerWithSecurityConfig(false, true, true, true, false)

		err := server.ValidateRedirectURIForRegistration(ctx, "https://[::]/callback")
		if err == nil {
			t.Error("Expected IPv6 unspecified address to be blocked even with permissive config")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryUnspecifiedAddr {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryUnspecifiedAddr, GetRedirectURIErrorCategory(err))
		}
	})
}

func TestSanitizeURIForLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes query parameters",
			input:    "https://example.com/callback?code=secret&state=abc",
			expected: "https://example.com/callback",
		},
		{
			name:     "removes fragment",
			input:    "https://example.com/callback#token=secret",
			expected: "https://example.com/callback",
		},
		{
			name:     "removes userinfo",
			input:    "https://user:password@example.com/callback",
			expected: "https://example.com/callback",
		},
		{
			name:     "truncates very long URIs",
			input:    "https://example.com/" + string(make([]byte, 200)),
			expected: "https://example.com/",
		},
		{
			name:     "handles invalid URI gracefully",
			input:    "://invalid",
			expected: "://invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeURIForLogging(tt.input)
			if result != tt.expected && len(result) > 100 {
				// For truncated URIs, just check it was truncated
				if len(result) > 115 { // 100 + "...[truncated]"
					t.Errorf("Expected truncated result, got length %d", len(result))
				}
			} else if result != tt.expected {
				t.Errorf("sanitizeURIForLogging(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsRedirectURISecurityError(t *testing.T) {
	t.Run("returns true for RedirectURISecurityError", func(t *testing.T) {
		err := &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryBlockedScheme,
			ClientMessage: "test error",
		}
		if !IsRedirectURISecurityError(err) {
			t.Error("Expected IsRedirectURISecurityError to return true")
		}
	})

	t.Run("returns false for other errors", func(t *testing.T) {
		err := context.DeadlineExceeded
		if IsRedirectURISecurityError(err) {
			t.Error("Expected IsRedirectURISecurityError to return false for non-security error")
		}
	})
}

func TestConfigDefaults(t *testing.T) {
	t.Run("AllowLocalhostRedirectURIs can be set to false", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, false, false, false, false)
		// AllowLocalhostRedirectURIs should respect the explicit false setting
		// (secure by default - only allow if explicitly enabled)
		if server.Config.AllowLocalhostRedirectURIs {
			t.Error("Expected AllowLocalhostRedirectURIs to be false when explicitly set")
		}
	})

	t.Run("BlockedRedirectSchemes has defaults", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		if len(server.Config.BlockedRedirectSchemes) == 0 {
			t.Error("Expected BlockedRedirectSchemes to have default values")
		}

		// Check for expected blocked schemes
		expected := []string{"javascript", "data", "file"}
		for _, scheme := range expected {
			found := false
			for _, blocked := range server.Config.BlockedRedirectSchemes {
				if blocked == scheme {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected %s to be in BlockedRedirectSchemes", scheme)
			}
		}
	})
}

func TestValidateRedirectURIAtAuthorizationTime(t *testing.T) {
	ctx := context.Background()

	t.Run("Skipped when disabled", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		// ValidateRedirectURIAtAuthorization defaults to false
		server.Config.ValidateRedirectURIAtAuthorization = false

		// Should return nil even for invalid URIs when disabled
		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "javascript:alert('xss')")
		if err != nil {
			t.Errorf("Expected no error when validation disabled, got %v", err)
		}
	})

	t.Run("Validates when enabled", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		server.Config.ValidateRedirectURIAtAuthorization = true

		// Should fail for blocked schemes
		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "javascript:alert('xss')")
		if err == nil {
			t.Error("Expected error for javascript: scheme when validation enabled")
		}

		// Should pass for valid URIs
		err = server.ValidateRedirectURIAtAuthorizationTime(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for valid URI, got %v", err)
		}
	})

	t.Run("Validates private IPs at authorization time", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		server.Config.ValidateRedirectURIAtAuthorization = true

		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "https://10.0.0.1/callback")
		if err == nil {
			t.Error("Expected error for private IP when validation enabled")
		}
	})
}

func TestHighSecurityRedirectURIConfig(t *testing.T) {
	config := HighSecurityRedirectURIConfig()

	t.Run("ProductionMode enabled", func(t *testing.T) {
		if !config.ProductionMode {
			t.Error("Expected ProductionMode to be true")
		}
	})

	t.Run("AllowLocalhostRedirectURIs enabled for RFC 8252", func(t *testing.T) {
		if !config.AllowLocalhostRedirectURIs {
			t.Error("Expected AllowLocalhostRedirectURIs to be true for native app support")
		}
	})

	t.Run("Private IPs blocked", func(t *testing.T) {
		if config.AllowPrivateIPRedirectURIs {
			t.Error("Expected AllowPrivateIPRedirectURIs to be false")
		}
	})

	t.Run("Link-local blocked", func(t *testing.T) {
		if config.AllowLinkLocalRedirectURIs {
			t.Error("Expected AllowLinkLocalRedirectURIs to be false")
		}
	})

	t.Run("DNS validation enabled with strict mode", func(t *testing.T) {
		if !config.DNSValidation {
			t.Error("Expected DNSValidation to be true")
		}
		if !config.DNSValidationStrict {
			t.Error("Expected DNSValidationStrict to be true")
		}
	})

	t.Run("Authorization-time validation enabled", func(t *testing.T) {
		if !config.ValidateRedirectURIAtAuthorization {
			t.Error("Expected ValidateRedirectURIAtAuthorization to be true")
		}
	})
}

func TestDNSValidationStrict(t *testing.T) {
	// Note: DNSValidationStrict now defaults to true (secure by default)
	t.Run("Strict mode config defaults to true (secure by default)", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		if !server.Config.DNSValidationStrict {
			t.Error("Expected DNSValidationStrict to default to true (secure by default)")
		}
	})

	t.Run("Strict mode is set via test helper", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		if !server.Config.DNSValidationStrict {
			t.Error("Expected DNSValidationStrict to be true when DNSValidation is enabled")
		}
	})
}

// mockDNSResolver implements DNSResolver for testing.
type mockDNSResolver struct {
	// results maps hostname to resolved IPs
	results map[string][]net.IP
	// errors maps hostname to error
	errors map[string]error
}

func newMockDNSResolver() *mockDNSResolver {
	return &mockDNSResolver{
		results: make(map[string][]net.IP),
		errors:  make(map[string]error),
	}
}

func (m *mockDNSResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if err, ok := m.errors[host]; ok {
		return nil, err
	}
	if ips, ok := m.results[host]; ok {
		return ips, nil
	}
	// Default: return a public IP if not configured
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

func (m *mockDNSResolver) setResult(host string, ips ...net.IP) {
	m.results[host] = ips
}

func (m *mockDNSResolver) setError(host string, err error) {
	m.errors[host] = err
}

func TestDNSValidationWithMockResolver(t *testing.T) {
	ctx := context.Background()

	t.Run("DNS resolves to private IP - blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		resolver.setResult("evil.example.com", net.ParseIP("10.0.0.1"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://evil.example.com/callback")
		if err == nil {
			t.Error("Expected error for hostname resolving to private IP")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSPrivateIP {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSPrivateIP, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("DNS resolves to private IP - allowed when AllowPrivateIPRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, true, false, true)
		resolver := newMockDNSResolver()
		resolver.setResult("internal.example.com", net.ParseIP("192.168.1.100"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://internal.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error when private IPs allowed, got %v", err)
		}
	})

	t.Run("DNS resolves to link-local IP - blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		// AWS metadata service IP
		resolver.setResult("metadata.attacker.com", net.ParseIP("169.254.169.254"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://metadata.attacker.com/callback")
		if err == nil {
			t.Error("Expected error for hostname resolving to link-local IP (metadata service)")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSLinkLocal {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSLinkLocal, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("DNS resolves to public IP - allowed", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		resolver.setResult("app.example.com", net.ParseIP("93.184.216.34"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for public IP, got %v", err)
		}
	})

	t.Run("DNS resolution fails - strict mode blocks", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		server.Config.DNSValidationStrict = true
		resolver := newMockDNSResolver()
		resolver.setError("unreachable.example.com", &net.DNSError{
			Err:  "no such host",
			Name: "unreachable.example.com",
		})
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://unreachable.example.com/callback")
		if err == nil {
			t.Error("Expected error in strict mode when DNS fails")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSFailure {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSFailure, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("DNS resolution fails - permissive mode allows", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		server.Config.DNSValidationStrict = false // Permissive (default)
		resolver := newMockDNSResolver()
		resolver.setError("flaky.example.com", &net.DNSError{
			Err:         "temporary failure",
			Name:        "flaky.example.com",
			IsTemporary: true,
		})
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://flaky.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error in permissive mode when DNS fails, got %v", err)
		}
	})

	t.Run("DNS resolves to multiple IPs - one private blocks all", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		// Mixed public and private IPs
		resolver.setResult("mixed.example.com",
			net.ParseIP("93.184.216.34"), // Public
			net.ParseIP("10.0.0.1"),      // Private - should block
		)
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://mixed.example.com/callback")
		if err == nil {
			t.Error("Expected error when any resolved IP is private")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSPrivateIP {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSPrivateIP, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("DNS resolves to IPv6 private (ULA) - blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		// IPv6 Unique Local Address (fc00::/7)
		resolver.setResult("ipv6internal.example.com", net.ParseIP("fd00::1"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://ipv6internal.example.com/callback")
		if err == nil {
			t.Error("Expected error for hostname resolving to IPv6 private address")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSPrivateIP {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSPrivateIP, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("DNS resolves to IPv6 link-local - blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		resolver := newMockDNSResolver()
		resolver.setResult("ipv6linklocal.example.com", net.ParseIP("fe80::1"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://ipv6linklocal.example.com/callback")
		if err == nil {
			t.Error("Expected error for hostname resolving to IPv6 link-local address")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSLinkLocal {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSLinkLocal, GetRedirectURIErrorCategory(err))
		}
	})
}

func TestAuthorizationTimeValidationWithMockDNS(t *testing.T) {
	ctx := context.Background()

	t.Run("DNS rebinding attack detected at authorization time", func(t *testing.T) {
		// Simulates a DNS rebinding attack:
		// 1. At registration time: evil.com -> 93.184.216.34 (public, allowed)
		// 2. At authorization time: evil.com -> 10.0.0.1 (private, blocked)

		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		server.Config.ValidateRedirectURIAtAuthorization = true
		resolver := newMockDNSResolver()
		// Now the attacker has changed DNS to point to internal network
		resolver.setResult("evil.example.com", net.ParseIP("10.0.0.1"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "https://evil.example.com/callback")
		if err == nil {
			t.Error("Expected DNS rebinding attack to be detected at authorization time")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryDNSPrivateIP {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryDNSPrivateIP, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("Valid redirect URI passes authorization-time validation", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, true)
		server.Config.ValidateRedirectURIAtAuthorization = true
		resolver := newMockDNSResolver()
		resolver.setResult("app.example.com", net.ParseIP("93.184.216.34"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for valid redirect URI, got %v", err)
		}
	})
}
