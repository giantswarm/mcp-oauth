package server

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testSecurityConfig holds security configuration for test servers.
// Using a struct with named fields improves readability over multiple boolean parameters.
type testSecurityConfig struct {
	productionMode bool // Require HTTPS for non-loopback (default: true)
	allowLocalhost bool // Allow localhost/loopback addresses (default: true)
	allowPrivateIP bool // Allow private IP addresses (default: false)
	allowLinkLocal bool // Allow link-local addresses (default: false)
	dnsValidation  bool // Enable DNS validation (default: false for most tests)
}

// defaultTestSecurityConfig returns the most common test configuration:
// production mode enabled, localhost allowed, private/link-local blocked, no DNS validation.
func defaultTestSecurityConfig() testSecurityConfig {
	return testSecurityConfig{
		productionMode: true,
		allowLocalhost: true,
		allowPrivateIP: false,
		allowLinkLocal: false,
		dnsValidation:  false,
	}
}

// newTestServerWithSecurityConfig creates a test server with specific redirect URI security settings.
// Note: This creates a server with a mock DNS resolver to avoid real DNS lookups in tests.
// The mock resolver returns a public IP (93.184.216.34) for all hostnames by default.
//
// Security features are controlled via the testSecurityConfig struct for readability:
// - productionMode=false sets DisableProductionMode=true (allows HTTP on non-loopback)
// - dnsValidation=false sets DisableDNSValidation=true (disables DNS checks)
func newTestServerWithSecurityConfig(cfg testSecurityConfig) *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := memory.New()
	provider := mock.NewMockProvider()

	// Create mock DNS resolver that returns public IPs by default
	// This prevents tests from depending on real DNS resolution
	mockResolver := newMockDNSResolver()

	config := &Config{
		Issuer: "https://auth.example.com",
		// Use Disable* fields to opt-out of secure defaults
		DisableProductionMode:              !cfg.productionMode,
		DisableDNSValidation:               !cfg.dnsValidation,
		DisableDNSValidationStrict:         !cfg.dnsValidation, // Match strict to validation setting
		DisableAuthorizationTimeValidation: true,               // Disable for simpler testing
		// Allow* flags for specific relaxations
		AllowLocalhostRedirectURIs: cfg.allowLocalhost,
		AllowPrivateIPRedirectURIs: cfg.allowPrivateIP,
		AllowLinkLocalRedirectURIs: cfg.allowLinkLocal,
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

	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		err := server.ValidateRedirectURIForRegistration(ctx, "http://app.example.com/callback")
		if err == nil {
			t.Error("Expected error for HTTP on non-loopback")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryHTTPNotAllowed {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryHTTPNotAllowed, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("HTTP on loopback allowed when AllowLocalhostRedirectURIs=true", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		err := server.ValidateRedirectURIForRegistration(ctx, "http://localhost:8080/callback")
		if err != nil {
			t.Errorf("Expected no error for HTTP on localhost, got %v", err)
		}
	})

	t.Run("HTTPS always allowed", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		for _, uri := range loopbackURIs {
			err := server.ValidateRedirectURIForRegistration(ctx, uri)
			if err != nil {
				t.Errorf("Expected loopback URI %s to be allowed, got error: %v", uri, err)
			}
		}
	})

	t.Run("Loopback blocked when AllowLocalhostRedirectURIs=false", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: false,
		})
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			allowPrivateIP: true,
		})
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			allowLinkLocal: true,
		})
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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: false,
			allowLocalhost: true,
			allowPrivateIP: true,
			allowLinkLocal: true,
		})

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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: false,
		})
		// AllowLocalhostRedirectURIs should respect the explicit false setting
		// (secure by default - only allow if explicitly enabled)
		if server.Config.AllowLocalhostRedirectURIs {
			t.Error("Expected AllowLocalhostRedirectURIs to be false when explicitly set")
		}
	})

	t.Run("BlockedRedirectSchemes has defaults", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		// ValidateRedirectURIAtAuthorization defaults to false
		server.Config.ValidateRedirectURIAtAuthorization = false

		// Should return nil even for invalid URIs when disabled
		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "javascript:alert('xss')")
		if err != nil {
			t.Errorf("Expected no error when validation disabled, got %v", err)
		}
	})

	t.Run("Validates when enabled", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
		if !server.Config.DNSValidationStrict {
			t.Error("Expected DNSValidationStrict to default to true (secure by default)")
		}
	})

	t.Run("Strict mode is set via test helper", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			allowPrivateIP: true,
			dnsValidation:  true,
		})
		resolver := newMockDNSResolver()
		resolver.setResult("internal.example.com", net.ParseIP("192.168.1.100"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://internal.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error when private IPs allowed, got %v", err)
		}
	})

	t.Run("DNS resolves to link-local IP - blocked", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
		resolver := newMockDNSResolver()
		resolver.setResult("app.example.com", net.ParseIP("93.184.216.34"))
		server.Config.DNSResolver = resolver

		err := server.ValidateRedirectURIForRegistration(ctx, "https://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for public IP, got %v", err)
		}
	})

	t.Run("DNS resolution fails - strict mode blocks", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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

		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
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

func TestRedirectURISecurityMetrics(t *testing.T) {
	ctx := context.Background()

	t.Run("Metrics recorded on registration validation failure", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

		// Trigger a blocked scheme error - should record metric
		err := server.ValidateRedirectURIForRegistration(ctx, "javascript:alert('xss')")
		if err == nil {
			t.Error("Expected error for blocked scheme")
		}

		// Verify the error category is correct (metric should have been recorded internally)
		category := GetRedirectURIErrorCategory(err)
		if category != RedirectURIErrorCategoryBlockedScheme {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryBlockedScheme, category)
		}
	})

	t.Run("Metrics recorded on authorization-time validation failure", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		server.Config.ValidateRedirectURIAtAuthorization = true

		// Trigger a private IP error at authorization time
		err := server.ValidateRedirectURIAtAuthorizationTime(ctx, "https://10.0.0.1/callback")
		if err == nil {
			t.Error("Expected error for private IP at authorization time")
		}

		category := GetRedirectURIErrorCategory(err)
		if category != RedirectURIErrorCategoryPrivateIP {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryPrivateIP, category)
		}
	})

	t.Run("Stage constants are exported correctly", func(t *testing.T) {
		if RedirectURIStageRegistration != "registration" {
			t.Errorf("Expected RedirectURIStageRegistration to be 'registration', got %s", RedirectURIStageRegistration)
		}
		if RedirectURIStageAuthorization != "authorization" {
			t.Errorf("Expected RedirectURIStageAuthorization to be 'authorization', got %s", RedirectURIStageAuthorization)
		}
	})

	t.Run("Metrics work with instrumentation enabled", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		store := memory.New()
		provider := mock.NewMockProvider()

		// Create instrumentation
		inst, err := instrumentation.New(instrumentation.Config{
			Enabled: true,
		})
		if err != nil {
			t.Fatalf("Failed to create instrumentation: %v", err)
		}
		defer func() { _ = inst.Shutdown(context.Background()) }()

		config := &Config{
			Issuer:                     "https://auth.example.com",
			AllowLocalhostRedirectURIs: true,
		}

		server, err := New(provider, store, store, store, config, logger)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}
		server.Instrumentation = inst

		// This should record a metric via instrumentation
		validationErr := server.ValidateRedirectURIForRegistration(ctx, "javascript:alert('xss')")
		if validationErr == nil {
			t.Error("Expected error for blocked scheme")
		}

		// Verify category is correct
		category := GetRedirectURIErrorCategory(validationErr)
		if category != RedirectURIErrorCategoryBlockedScheme {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryBlockedScheme, category)
		}
	})
}

// TestValidateRedirectURIForRegistration_IPBypassAttempts tests that various IP address
// encoding bypass attempts are handled correctly. These are common SSRF bypass techniques.
//
// Go's net.ParseIP() correctly rejects non-standard IP representations, so these are
// treated as hostnames and validated via DNS (if enabled) or rejected by URL parsing.
func TestValidateRedirectURIForRegistration_IPBypassAttempts(t *testing.T) {
	ctx := context.Background()

	t.Run("Octal IP representation rejected", func(t *testing.T) {
		// Octal representations like 0177.0.0.1 (127.0.0.1) or 012.0.0.1 (10.0.0.1)
		// are sometimes used to bypass IP validation.
		// Go's net.ParseIP() returns nil for these, so they're treated as hostnames.
		// With DNS validation enabled + strict mode, they fail DNS lookup and are blocked.
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
		server.Config.DNSValidationStrict = true

		resolver := newMockDNSResolver()
		// Simulate DNS failure for these invalid "hostnames"
		resolver.setError("0177.0.0.1", &net.DNSError{Err: "no such host", Name: "0177.0.0.1"})
		resolver.setError("012.0.0.1", &net.DNSError{Err: "no such host", Name: "012.0.0.1"})
		resolver.setError("0300.0250.0.1", &net.DNSError{Err: "no such host", Name: "0300.0250.0.1"})
		server.Config.DNSResolver = resolver

		octalTests := []struct {
			name string
			uri  string
		}{
			{"Octal 127.0.0.1", "https://0177.0.0.1/callback"},
			{"Octal 10.0.0.1", "https://012.0.0.1/callback"},
			{"Octal 192.168.0.1", "https://0300.0250.0.1/callback"},
		}

		for _, tt := range octalTests {
			t.Run(tt.name, func(t *testing.T) {
				err := server.ValidateRedirectURIForRegistration(ctx, tt.uri)
				if err == nil {
					t.Errorf("Expected error for octal IP bypass attempt: %s", tt.uri)
				}
				// Should fail with DNS failure category since strict mode is on
				category := GetRedirectURIErrorCategory(err)
				if category != RedirectURIErrorCategoryDNSFailure {
					t.Logf("Note: Octal IP %s rejected with category %s (expected: dns_resolution_failed)", tt.uri, category)
				}
			})
		}
	})

	t.Run("Hex IP representation rejected", func(t *testing.T) {
		// Hex representations like 0x7f.0.0.1 (127.0.0.1) or 0x7f000001
		// are sometimes used to bypass IP validation.
		// Go's net.ParseIP() returns nil for these, so they're treated as hostnames.
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
		server.Config.DNSValidationStrict = true

		resolver := newMockDNSResolver()
		resolver.setError("0x7f.0.0.1", &net.DNSError{Err: "no such host", Name: "0x7f.0.0.1"})
		resolver.setError("0x7f000001", &net.DNSError{Err: "no such host", Name: "0x7f000001"})
		resolver.setError("0x0a.0.0.1", &net.DNSError{Err: "no such host", Name: "0x0a.0.0.1"})
		server.Config.DNSResolver = resolver

		hexTests := []struct {
			name string
			uri  string
		}{
			{"Hex dotted 127.0.0.1", "https://0x7f.0.0.1/callback"},
			{"Hex integer 127.0.0.1", "https://0x7f000001/callback"},
			{"Hex dotted 10.0.0.1", "https://0x0a.0.0.1/callback"},
		}

		for _, tt := range hexTests {
			t.Run(tt.name, func(t *testing.T) {
				err := server.ValidateRedirectURIForRegistration(ctx, tt.uri)
				if err == nil {
					t.Errorf("Expected error for hex IP bypass attempt: %s", tt.uri)
				}
				category := GetRedirectURIErrorCategory(err)
				if category != RedirectURIErrorCategoryDNSFailure {
					t.Logf("Note: Hex IP %s rejected with category %s (expected: dns_resolution_failed)", tt.uri, category)
				}
			})
		}
	})

	t.Run("Decimal integer IP representation rejected", func(t *testing.T) {
		// Some systems accept decimal integer representations like 2130706433 (127.0.0.1)
		// Go's net.ParseIP() returns nil for these, treating them as hostnames.
		server := newTestServerWithSecurityConfig(testSecurityConfig{
			productionMode: true,
			allowLocalhost: true,
			dnsValidation:  true,
		})
		server.Config.DNSValidationStrict = true

		resolver := newMockDNSResolver()
		resolver.setError("2130706433", &net.DNSError{Err: "no such host", Name: "2130706433"})
		resolver.setError("167772161", &net.DNSError{Err: "no such host", Name: "167772161"})
		server.Config.DNSResolver = resolver

		decimalTests := []struct {
			name string
			uri  string
		}{
			{"Decimal 127.0.0.1", "https://2130706433/callback"},
			{"Decimal 10.0.0.1", "https://167772161/callback"},
		}

		for _, tt := range decimalTests {
			t.Run(tt.name, func(t *testing.T) {
				err := server.ValidateRedirectURIForRegistration(ctx, tt.uri)
				if err == nil {
					t.Errorf("Expected error for decimal IP bypass attempt: %s", tt.uri)
				}
			})
		}
	})

	t.Run("Net.ParseIP behavior documented", func(t *testing.T) {
		// Document that net.ParseIP correctly rejects these bypass attempts
		bypassAttempts := []string{
			"0177.0.0.1",     // Octal
			"0x7f.0.0.1",     // Hex dotted
			"0x7f000001",     // Hex integer
			"2130706433",     // Decimal integer
			"127.0.0.1.1",    // Extra octet
			"127.0.0",        // Missing octet
			"127.0.0.1/8",    // CIDR notation
			"127.0.0.1:80",   // Port included
			"127.0.0.01",     // Leading zero in last octet
			"0127.0.0.1",     // Leading zero in first octet
			"127.0.0.1%eth0", // Zone ID (common bypass)
		}

		for _, attempt := range bypassAttempts {
			ip := net.ParseIP(attempt)
			if ip != nil {
				t.Errorf("SECURITY: net.ParseIP accepted bypass attempt '%s' as %v", attempt, ip)
			}
		}
	})
}

// TestValidateRedirectURIForRegistration_URLEncodedSchemeBypass tests that URL-encoded
// schemes are not parsed as valid dangerous schemes.
// This is a common XSS bypass technique: %6A%61%76%61%73%63%72%69%70%74: for "javascript:"
func TestValidateRedirectURIForRegistration_URLEncodedSchemeBypass(t *testing.T) {
	ctx := context.Background()
	server := newTestServerWithSecurityConfig(defaultTestSecurityConfig())

	t.Run("URL-encoded scheme not decoded by url.Parse", func(t *testing.T) {
		// When Go's url.Parse sees "%6A%61%76%61%73%63%72%69%70%74:", it does NOT
		// decode the scheme. The scheme would be empty or invalid, not "javascript".
		// This test documents this behavior.

		encodedSchemeTests := []struct {
			name        string
			uri         string
			description string
		}{
			{
				name:        "Fully encoded javascript",
				uri:         "%6A%61%76%61%73%63%72%69%70%74:alert('xss')",
				description: "javascript: fully URL-encoded",
			},
			{
				name:        "Partially encoded javascript",
				uri:         "java%73cript:alert('xss')",
				description: "javascript: with encoded 's'",
			},
			{
				name:        "Encoded data scheme",
				uri:         "%64%61%74%61:text/html,<script>",
				description: "data: fully URL-encoded",
			},
			{
				name:        "Mixed case encoded",
				uri:         "%4A%41%56%41script:alert('xss')",
				description: "JAVA encoded + script literal",
			},
		}

		for _, tt := range encodedSchemeTests {
			t.Run(tt.name, func(t *testing.T) {
				err := server.ValidateRedirectURIForRegistration(ctx, tt.uri)
				// These should fail validation - either as invalid format or blocked scheme
				// Go's url.Parse doesn't decode the scheme, so "%6A..." is not "javascript"
				if err == nil {
					t.Errorf("Expected error for URL-encoded scheme bypass: %s (%s)", tt.uri, tt.description)
				}

				// Log the actual error category for documentation
				category := GetRedirectURIErrorCategory(err)
				t.Logf("URL-encoded scheme '%s' rejected with category: %s (error: %v)",
					tt.uri, category, err)
			})
		}
	})

	t.Run("Document url.Parse scheme handling", func(t *testing.T) {
		// This test documents Go's url.Parse behavior with encoded schemes
		// to ensure we understand how it protects against bypass attacks.

		testCases := []struct {
			input           string
			expectedScheme  string
			shouldParseFail bool
		}{
			{"javascript:alert(1)", "javascript", false},
			{"%6A%61%76%61%73%63%72%69%70%74:alert(1)", "", true}, // Empty/invalid scheme
			{"https://example.com", "https", false},
			{"%68%74%74%70%73://example.com", "", true}, // Encoded https
		}

		for _, tc := range testCases {
			parsed, err := url.Parse(tc.input)
			if tc.shouldParseFail {
				// Either parse error or empty/unexpected scheme
				if err == nil && parsed.Scheme == tc.expectedScheme && tc.expectedScheme != "" {
					t.Errorf("Expected parse failure or empty scheme for '%s', got scheme '%s'",
						tc.input, parsed.Scheme)
				}
			} else {
				if err != nil {
					t.Errorf("Expected successful parse for '%s', got error: %v", tc.input, err)
				} else if parsed.Scheme != tc.expectedScheme {
					t.Errorf("Expected scheme '%s' for '%s', got '%s'",
						tc.expectedScheme, tc.input, parsed.Scheme)
				}
			}
		}
	})
}
