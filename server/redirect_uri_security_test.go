package server

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newTestServerWithSecurityConfig creates a test server with specific redirect URI security settings.
func newTestServerWithSecurityConfig(productionMode, allowLocalhost, allowPrivateIP, allowLinkLocal, dnsValidation bool) *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := memory.New()
	provider := mock.NewMockProvider()

	config := &Config{
		Issuer:                     "https://auth.example.com",
		ProductionMode:             productionMode,
		AllowLocalhostRedirectURIs: allowLocalhost,
		AllowPrivateIPRedirectURIs: allowPrivateIP,
		AllowLinkLocalRedirectURIs: allowLinkLocal,
		DNSValidation:              dnsValidation,
		BlockedRedirectSchemes:     []string{"javascript", "data", "file", "vbscript", "about", "ftp"},
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

	t.Run("HTTP on non-loopback blocked in production mode", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(true, true, false, false, false)
		err := server.ValidateRedirectURIForRegistration(ctx, "http://app.example.com/callback")
		if err == nil {
			t.Error("Expected error for HTTP on non-loopback in production mode")
		}
		if GetRedirectURIErrorCategory(err) != RedirectURIErrorCategoryHTTPNotAllowed {
			t.Errorf("Expected category %s, got %s", RedirectURIErrorCategoryHTTPNotAllowed, GetRedirectURIErrorCategory(err))
		}
	})

	t.Run("HTTP on non-loopback allowed in development mode", func(t *testing.T) {
		server := newTestServerWithSecurityConfig(false, true, false, false, false)
		err := server.ValidateRedirectURIForRegistration(ctx, "http://app.example.com/callback")
		if err != nil {
			t.Errorf("Expected no error for HTTP in development mode, got %v", err)
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
