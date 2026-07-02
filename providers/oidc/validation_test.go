package oidc

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{
			name:    "valid HTTPS URL",
			url:     "https://dex.example.com",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with port",
			url:     "https://dex.example.com:8443",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with path",
			url:     "https://dex.example.com/auth",
			wantErr: false,
		},

		// SECURITY: HTTP rejection
		{
			name:    "reject HTTP (not HTTPS)",
			url:     "http://dex.example.com",
			wantErr: true,
			errMsg:  "must use HTTPS",
		},

		// SECURITY: Loopback addresses
		{
			name:    "reject IPv4 loopback",
			url:     "https://127.0.0.1",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "reject IPv6 loopback",
			url:     "https://[::1]",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "reject localhost",
			url:     "https://localhost",
			wantErr: false, // localhost is hostname, not IP (DNS would resolve)
		},

		// SECURITY: Private IP ranges
		{
			name:    "reject private IP 10.0.0.0/8",
			url:     "https://10.0.0.1",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 172.16.0.0/12",
			url:     "https://172.16.0.1",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 192.168.0.0/16",
			url:     "https://192.168.1.1",
			wantErr: true,
			errMsg:  "private IP",
		},

		// SECURITY: Link-local addresses (AWS metadata service)
		{
			name:    "reject link-local IPv4 (metadata service)",
			url:     "https://169.254.169.254",
			wantErr: true,
			errMsg:  "link-local",
		},
		{
			name:    "reject link-local IPv6",
			url:     "https://[fe80::1]",
			wantErr: true,
			errMsg:  "link-local",
		},

		// Malformed URLs
		{
			name:    "reject malformed URL",
			url:     "not a url",
			wantErr: true,
			errMsg:  "must use HTTPS",
		},
		{
			name:    "reject empty hostname",
			url:     "https://",
			wantErr: true,
			errMsg:  "must have a hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIssuerURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateIssuerURL() expected error for %q, got nil", tt.url)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateIssuerURL() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateIssuerURL() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateConnectorID(t *testing.T) {
	tests := []struct {
		name        string
		connectorID string
		wantErr     bool
		errMsg      string
	}{
		// Valid cases
		{
			name:        "empty connector ID (optional)",
			connectorID: "",
			wantErr:     false,
		},
		{
			name:        "valid lowercase",
			connectorID: "github",
			wantErr:     false,
		},
		{
			name:        "valid with hyphen",
			connectorID: "github-enterprise",
			wantErr:     false,
		},
		{
			name:        "valid with underscore",
			connectorID: "github_enterprise",
			wantErr:     false,
		},
		{
			name:        "valid mixed case",
			connectorID: "GitHub",
			wantErr:     false,
		},
		{
			name:        "valid with numbers",
			connectorID: "ldap01",
			wantErr:     false,
		},

		// Invalid cases
		{
			name:        "reject special characters",
			connectorID: "github@enterprise",
			wantErr:     true,
			errMsg:      "invalid characters",
		},
		{
			name:        "reject spaces",
			connectorID: "github enterprise",
			wantErr:     true,
			errMsg:      "invalid characters",
		},
		{
			name:        "reject dots",
			connectorID: "github.com",
			wantErr:     true,
			errMsg:      "invalid characters",
		},
		{
			name:        "reject slashes",
			connectorID: "github/enterprise",
			wantErr:     true,
			errMsg:      "invalid characters",
		},

		// SECURITY: Length limit
		{
			name:        "reject too long (65 chars)",
			connectorID: strings.Repeat("a", 65),
			wantErr:     true,
			errMsg:      "exceeds maximum length",
		},
		{
			name:        "accept max length (64 chars)",
			connectorID: strings.Repeat("a", 64),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConnectorID(tt.connectorID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateConnectorID() expected error for %q, got nil", tt.connectorID)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateConnectorID() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateConnectorID() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{
			name:    "valid single scope",
			scopes:  []string{"openid"},
			wantErr: false,
		},
		{
			name:    "valid multiple scopes",
			scopes:  []string{"openid", "profile", "email"},
			wantErr: false,
		},
		{
			name:    "valid with URL scope",
			scopes:  []string{"https://www.googleapis.com/auth/gmail.readonly"},
			wantErr: false,
		},
		{
			name:    "empty array",
			scopes:  []string{},
			wantErr: false,
		},

		// Invalid cases
		{
			name:    "reject empty scope",
			scopes:  []string{"openid", "", "profile"},
			wantErr: true,
			errMsg:  "is empty",
		},

		// SECURITY: Length limits
		{
			name:    "reject too many scopes",
			scopes:  make([]string, 51),
			wantErr: true,
			errMsg:  "exceeds maximum of 50 items",
		},
		{
			name:    "reject scope too long",
			scopes:  []string{strings.Repeat("a", 257)},
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
		{
			name:    "accept max scope length",
			scopes:  []string{strings.Repeat("a", 256)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill empty scopes array with valid values for testing
			if len(tt.scopes) > 5 && tt.scopes[0] == "" {
				for i := range tt.scopes {
					tt.scopes[i] = "scope"
				}
			}

			err := ValidateScopes(tt.scopes)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateScopes() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateScopes() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateScopes() unexpected error = %v", err)
			}
		})
	}
}

// enterpriseGroupCount represents a realistic enterprise Active Directory group count
// from issue #218 where users had 303 groups and were blocked by the previous limit of 100.
const enterpriseGroupCount = 303

func TestValidateGroups(t *testing.T) {
	tests := []struct {
		name          string
		groups        []string
		maxGroups     int
		wantLen       int
		wantTruncated bool
		wantErr       bool
		errMsg        string
	}{
		{
			name:      "single group",
			groups:    []string{"admin"},
			maxGroups: 0,
			wantLen:   1,
		},
		{
			name:      "multiple groups",
			groups:    []string{"admin", "developers", "users"},
			maxGroups: 0,
			wantLen:   3,
		},
		{
			name:      "nil groups",
			groups:    nil,
			maxGroups: 0,
			wantLen:   0,
		},
		{
			name:      "empty groups",
			groups:    []string{},
			maxGroups: 0,
			wantLen:   0,
		},
		{
			name:      "enterprise group count within default limit",
			groups:    makeGroups(enterpriseGroupCount),
			maxGroups: 0,
			wantLen:   enterpriseGroupCount,
		},
		{
			name:      "exactly at default limit",
			groups:    makeGroups(DefaultMaxGroups),
			maxGroups: 0,
			wantLen:   DefaultMaxGroups,
		},
		{
			name:          "truncates beyond default limit",
			groups:        makeGroups(DefaultMaxGroups + 10),
			maxGroups:     0,
			wantLen:       DefaultMaxGroups,
			wantTruncated: true,
		},
		{
			name:          "truncates to custom limit",
			groups:        makeGroups(enterpriseGroupCount),
			maxGroups:     100,
			wantLen:       100,
			wantTruncated: true,
		},
		{
			name:      "exactly at custom limit",
			groups:    makeGroups(100),
			maxGroups: 100,
			wantLen:   100,
		},
		{
			name:          "negative maxGroups uses default",
			groups:        makeGroups(DefaultMaxGroups + 1),
			maxGroups:     -1,
			wantLen:       DefaultMaxGroups,
			wantTruncated: true,
		},
		{
			name:    "rejects oversized group name",
			groups:  []string{"ok", strings.Repeat("x", DefaultMaxGroupNameLength+1)},
			wantErr: true,
			errMsg:  "exceeds maximum length of 256 characters",
		},
		{
			name:      "accepts max group name length",
			groups:    []string{strings.Repeat("a", DefaultMaxGroupNameLength)},
			maxGroups: 0,
			wantLen:   1,
		},
		{
			name:      "oversized group name rejected even beyond truncation boundary",
			groups:    append(makeGroups(10), strings.Repeat("x", DefaultMaxGroupNameLength+1)),
			maxGroups: 5,
			wantErr:   true,
			errMsg:    "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, truncated, err := ValidateGroups(tt.groups, tt.maxGroups)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateGroups() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateGroups() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateGroups() unexpected error: %v", err)
			}
			if truncated != tt.wantTruncated {
				t.Errorf("ValidateGroups() truncated = %v, want %v", truncated, tt.wantTruncated)
			}
			if len(result) != tt.wantLen {
				t.Errorf("ValidateGroups() returned %d groups, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func makeGroups(n int) []string {
	groups := make([]string, n)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d", i)
	}
	return groups
}

// TestValidateExternalURL tests the generic external URL validation with SSRF protection.
// This is used for JWKS URIs and other external endpoints.
func TestValidateExternalURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		context string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{
			name:    "valid HTTPS URL",
			url:     "https://provider.example.com/.well-known/jwks",
			context: "JWKS URI",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with port",
			url:     "https://provider.example.com:8443/jwks",
			context: "JWKS URI",
			wantErr: false,
		},

		// SECURITY: HTTP rejection
		{
			name:    "reject HTTP (not HTTPS)",
			url:     "http://provider.example.com/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "must use HTTPS",
		},

		// SECURITY: Loopback addresses (SSRF protection)
		{
			name:    "reject IPv4 loopback",
			url:     "https://127.0.0.1/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "reject IPv6 loopback",
			url:     "https://[::1]/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "loopback",
		},

		// SECURITY: Private IP ranges (SSRF protection)
		{
			name:    "reject private IP 10.0.0.0/8",
			url:     "https://10.0.0.1/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 172.16.0.0/12",
			url:     "https://172.16.0.1/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 192.168.0.0/16",
			url:     "https://192.168.1.1/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "private IP",
		},

		// SECURITY: Link-local addresses (AWS/cloud metadata service protection)
		{
			name:    "reject link-local IPv4 (metadata service)",
			url:     "https://169.254.169.254/latest/meta-data/",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "link-local",
		},
		{
			name:    "reject link-local IPv6",
			url:     "https://[fe80::1]/jwks",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "link-local",
		},

		// Empty/malformed URLs
		{
			name:    "reject empty hostname",
			url:     "https://",
			context: "JWKS URI",
			wantErr: true,
			errMsg:  "must have a hostname",
		},

		// Verify context is used in error messages
		{
			name:    "error message includes context",
			url:     "http://example.com",
			context: "custom endpoint",
			wantErr: true,
			errMsg:  "custom endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExternalURL(tt.url, tt.context)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateExternalURL() expected error for %q, got nil", tt.url)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateExternalURL() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateExternalURL() unexpected error = %v", err)
			}
		})
	}
}

// TestIsPrivateOrRestrictedIP tests the IP validation helper.
func TestIsPrivateOrRestrictedIP(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		restricted bool
	}{
		// Public IPs - should NOT be restricted
		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 Google DNS", "8.8.4.4", false},
		{"public IPv4 Cloudflare", "1.1.1.1", false},

		// Loopback - should be restricted
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback alt", "127.0.0.2", true},
		{"IPv6 loopback", "::1", true},

		// Private 10.0.0.0/8 - should be restricted
		{"private 10.x", "10.0.0.1", true},
		{"private 10.x high", "10.255.255.255", true},

		// Private 172.16.0.0/12 - should be restricted
		{"private 172.16.x", "172.16.0.1", true},
		{"private 172.31.x", "172.31.255.255", true},

		// Private 192.168.0.0/16 - should be restricted
		{"private 192.168.x", "192.168.0.1", true},
		{"private 192.168.x high", "192.168.255.255", true},

		// Link-local IPv4 (169.254.0.0/16) - should be restricted (AWS/cloud metadata)
		{"link-local metadata", "169.254.169.254", true},
		{"link-local other", "169.254.1.1", true},

		// Link-local IPv6 - should be restricted
		{"link-local IPv6", "fe80::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			got := isPrivateOrRestrictedIP(ip)
			if got != tt.restricted {
				t.Errorf("isPrivateOrRestrictedIP(%s) = %v, want %v", tt.ip, got, tt.restricted)
			}
		})
	}
}

// TestSSRFSafeDialContext tests the DNS rebinding protection.
func TestSSRFSafeDialContext(t *testing.T) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dialFunc := SSRFSafeDialContext(dialer)

	t.Run("rejects loopback after DNS resolution", func(t *testing.T) {
		// localhost should be rejected because it resolves to 127.0.0.1
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "localhost:443")
		if err == nil {
			t.Error("Expected error for localhost (resolves to loopback)")
		}
		if !strings.Contains(err.Error(), "restricted IP") {
			t.Errorf("Expected 'restricted IP' error, got: %v", err)
		}
	})

	t.Run("handles invalid address format", func(t *testing.T) {
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "invalid-no-port")
		if err == nil {
			t.Error("Expected error for invalid address format")
		}
	})
}

// TestNewSSRFSafeHTTPClient tests the SSRF-safe HTTP client creation.
func TestNewSSRFSafeHTTPClient(t *testing.T) {
	t.Run("creates client with default timeout", func(t *testing.T) {
		client := NewSSRFSafeHTTPClient(0)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != DefaultHTTPTimeout {
			t.Errorf("Expected timeout %v, got %v", DefaultHTTPTimeout, client.Timeout)
		}
	})

	t.Run("creates client with custom timeout", func(t *testing.T) {
		client := NewSSRFSafeHTTPClient(30 * time.Second)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", client.Timeout)
		}
	})

	t.Run("client has custom transport", func(t *testing.T) {
		client := NewSSRFSafeHTTPClient(0)
		if client.Transport == nil {
			t.Error("Expected client to have custom transport for DNS rebinding protection")
		}
	})
}

// TestNewPrivateIPAllowedHTTPClient tests the HTTP client creation that allows private IPs.
func TestNewPrivateIPAllowedHTTPClient(t *testing.T) {
	t.Run("creates client with default timeout", func(t *testing.T) {
		client := NewPrivateIPAllowedHTTPClient(0, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != DefaultHTTPTimeout {
			t.Errorf("Expected timeout %v, got %v", DefaultHTTPTimeout, client.Timeout)
		}
	})

	t.Run("creates client with custom timeout", func(t *testing.T) {
		client := NewPrivateIPAllowedHTTPClient(30*time.Second, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", client.Timeout)
		}
	})

	t.Run("client has standard transport without SSRF protection", func(t *testing.T) {
		client := NewPrivateIPAllowedHTTPClient(0, nil)
		if client.Transport == nil {
			t.Error("Expected client to have transport configured")
		}
	})
}

// TestPrivateIPAllowedHTTPClient_RedirectPinning verifies the private-IP-allowed
// client follows a same-host redirect but refuses one that changes the host or
// port (the SSRF pivot the host pin closes).
func TestPrivateIPAllowedHTTPClient_RedirectPinning(t *testing.T) {
	client := NewPrivateIPAllowedHTTPClient(5*time.Second, nil)

	t.Run("follows same-host redirect", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/keys/final", http.StatusFound)
		})
		mux.HandleFunc("/keys/final", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		resp, err := client.Get(srv.URL + "/keys")
		if err != nil {
			t.Fatalf("same-host redirect must be followed, got error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 after same-host redirect, got %d", resp.StatusCode)
		}
	})

	t.Run("refuses cross-host redirect", func(t *testing.T) {
		internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(internal.Close)

		entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/latest/meta-data", http.StatusFound)
		}))
		t.Cleanup(entry.Close)

		_, err := client.Get(entry.URL + "/keys")
		if err == nil {
			t.Fatal("cross-host redirect must be refused")
		}
		if !strings.Contains(err.Error(), "cross-host redirect") {
			t.Errorf("expected a cross-host redirect error, got: %v", err)
		}
	})
}

func TestHostScopedPrivateIPDialContext(t *testing.T) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	t.Run("allows loopback for listed host", func(t *testing.T) {
		// localhost is in the allowlist — private-IP resolution is permitted.
		// The dial will fail (nothing listening) but NOT with a restricted-IP error.
		dialFunc := HostScopedPrivateIPDialContext(dialer, []string{"localhost"})
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "localhost:19999")
		if err == nil {
			t.Skip("unexpected successful connection on port 19999")
		}
		if strings.Contains(err.Error(), "restricted IP") {
			t.Errorf("allowed host should not be blocked by restricted-IP guard, got: %v", err)
		}
	})

	t.Run("blocks loopback for unlisted host", func(t *testing.T) {
		// localhost is NOT in the allowlist — SSRF guard fires.
		dialFunc := HostScopedPrivateIPDialContext(dialer, []string{"other.internal"})
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "localhost:443")
		if err == nil {
			t.Fatal("expected restricted-IP error for unlisted loopback host")
		}
		if !strings.Contains(err.Error(), "restricted IP") {
			t.Errorf("expected 'restricted IP' error, got: %v", err)
		}
	})

	t.Run("blocks loopback with empty allowlist", func(t *testing.T) {
		dialFunc := HostScopedPrivateIPDialContext(dialer, nil)
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "localhost:443")
		if err == nil {
			t.Fatal("expected restricted-IP error with empty allowlist")
		}
		if !strings.Contains(err.Error(), "restricted IP") {
			t.Errorf("expected 'restricted IP' error, got: %v", err)
		}
	})

	t.Run("handles invalid address format", func(t *testing.T) {
		dialFunc := HostScopedPrivateIPDialContext(dialer, []string{"localhost"})
		ctx := context.Background()
		_, err := dialFunc(ctx, "tcp", "no-port")
		if err == nil {
			t.Fatal("expected error for missing port")
		}
	})
}

func TestNewHostScopedPrivateIPHTTPClient(t *testing.T) {
	t.Run("creates client with default timeout", func(t *testing.T) {
		client := NewHostScopedPrivateIPHTTPClient([]string{"internal.svc"}, 0, nil)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if client.Timeout != DefaultHTTPTimeout {
			t.Errorf("expected timeout %v, got %v", DefaultHTTPTimeout, client.Timeout)
		}
	})

	t.Run("creates client with custom timeout", func(t *testing.T) {
		client := NewHostScopedPrivateIPHTTPClient([]string{"internal.svc"}, 15*time.Second, nil)
		if client.Timeout != 15*time.Second {
			t.Errorf("expected 15s timeout, got %v", client.Timeout)
		}
	})

	t.Run("allows connection to listed loopback host", func(t *testing.T) {
		// httptest.NewServer listens on 127.0.0.1; extract its hostname.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)

		host := srv.Listener.Addr().(*net.TCPAddr).IP.String()
		client := NewHostScopedPrivateIPHTTPClient([]string{host}, 5*time.Second, nil)
		resp, err := client.Get(srv.URL + "/ok")
		if err != nil {
			t.Fatalf("expected successful request to listed loopback host, got: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("blocks unlisted loopback host via SSRF guard", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)

		// Client allows a different host — the test server's IP is blocked.
		client := NewHostScopedPrivateIPHTTPClient([]string{"other.internal"}, 5*time.Second, nil)
		_, err := client.Get(srv.URL + "/ok")
		if err == nil {
			t.Fatal("expected SSRF-guard error for unlisted loopback host")
		}
		if !strings.Contains(err.Error(), "restricted IP") {
			t.Errorf("expected 'restricted IP' error, got: %v", err)
		}
	})
}

// TestHostScopedPrivateIPHTTPClient_RedirectPinning verifies the host-scoped
// private-IP client keeps the cross-host redirect guard: it follows a same-host
// redirect but refuses one that changes the port, even when the listed host is
// allowed to dial private IPs. This is the AllowPrivateIPJWKSHosts analogue of
// TestPrivateIPAllowedHTTPClient_RedirectPinning — with the dial guard opened
// for the listed host, the redirect guard is the remaining defense against a
// discovery/JWKS endpoint 302-ing the fetch to a different internal target.
func TestHostScopedPrivateIPHTTPClient_RedirectPinning(t *testing.T) {
	t.Run("follows same-host redirect", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/keys/final", http.StatusFound)
		})
		mux.HandleFunc("/keys/final", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		host := srv.Listener.Addr().(*net.TCPAddr).IP.String()
		client := NewHostScopedPrivateIPHTTPClient([]string{host}, 5*time.Second, nil)
		resp, err := client.Get(srv.URL + "/keys")
		if err != nil {
			t.Fatalf("same-host redirect must be followed, got error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 after same-host redirect, got %d", resp.StatusCode)
		}
	})

	t.Run("refuses cross-host redirect", func(t *testing.T) {
		// Both servers listen on 127.0.0.1 (only the port differs) and that host
		// is in the allowlist, so the dial guard permits both — isolating the
		// assertion to the redirect guard, which pins the port as well as the host.
		internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(internal.Close)

		entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/latest/meta-data", http.StatusFound)
		}))
		t.Cleanup(entry.Close)

		host := entry.Listener.Addr().(*net.TCPAddr).IP.String()
		client := NewHostScopedPrivateIPHTTPClient([]string{host}, 5*time.Second, nil)
		_, err := client.Get(entry.URL + "/keys")
		if err == nil {
			t.Fatal("cross-host redirect must be refused")
		}
		if !strings.Contains(err.Error(), "cross-host redirect") {
			t.Errorf("expected a cross-host redirect error, got: %v", err)
		}
	})
}

// TestHostScopedPrivateIPHTTPClient_TrustsExplicitCA verifies the host-scoped
// private-IP client verifies against an explicitly provided RootCAs pool (the
// AllowPrivateIPJWKSHosts analogue of the permissive CA-trust path). With a nil
// pool the internal-CA server would be rejected by the system pool.
//
// Parallel-safe: CA trust is an argument, no global http.DefaultTransport swap.
func TestHostScopedPrivateIPHTTPClient_TrustsExplicitCA(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	host := srv.Listener.Addr().(*net.TCPAddr).IP.String()
	client := NewHostScopedPrivateIPHTTPClient([]string{host}, 5*time.Second, pool)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected TLS handshake to succeed with explicit CA pool, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestPrivateIPAllowedHTTPClient_CATrust verifies that TLS verification on the
// permissive client is driven solely by the explicit rootCAs argument: nil uses
// the system pool (an untrusted self-signed server is rejected — the client
// never sets InsecureSkipVerify), and an explicit pool trusts a server whose
// certificate chains to it. Replaces the former DefaultTransport-leak test now
// that CA trust is explicit config rather than a global read (#495).
//
// Parallel-safe: no global http.DefaultTransport swap.
func TestPrivateIPAllowedHTTPClient_CATrust(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Run("nil pool uses system pool and rejects untrusted cert", func(t *testing.T) {
		t.Parallel()
		client := NewPrivateIPAllowedHTTPClient(5*time.Second, nil)
		resp, err := client.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("handshake to an untrusted self-signed server must fail with a nil (system) pool")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
			t.Errorf("expected a certificate verification error, got: %v", err)
		}
	})

	t.Run("explicit pool trusts a cert chaining to it", func(t *testing.T) {
		t.Parallel()
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		client := NewPrivateIPAllowedHTTPClient(5*time.Second, pool)
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("expected handshake to succeed with explicit CA pool, got: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}
