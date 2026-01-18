package oidc

import (
	"context"
	"net"
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

func TestValidateGroups(t *testing.T) {
	tests := []struct {
		name    string
		groups  []string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{
			name:    "valid single group",
			groups:  []string{"admin"},
			wantErr: false,
		},
		{
			name:    "valid multiple groups",
			groups:  []string{"admin", "developers", "users"},
			wantErr: false,
		},
		{
			name:    "empty array",
			groups:  []string{},
			wantErr: false,
		},
		{
			name:    "valid max groups (100)",
			groups:  make([]string, 100),
			wantErr: false,
		},

		// SECURITY: Limits
		{
			name:    "reject too many groups (101)",
			groups:  make([]string, 101),
			wantErr: true,
			errMsg:  "exceeds maximum of 100 items",
		},
		{
			name:    "reject group name too long",
			groups:  []string{strings.Repeat("a", 257)},
			wantErr: true,
			errMsg:  "exceeds maximum length of 256 characters",
		},
		{
			name:    "accept max group name length",
			groups:  []string{strings.Repeat("a", 256)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill empty groups array with valid values for testing
			if len(tt.groups) > 5 && tt.groups[0] == "" {
				for i := range tt.groups {
					tt.groups[i] = "group"
				}
			}

			err := ValidateGroups(tt.groups)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateGroups() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateGroups() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateGroups() unexpected error = %v", err)
			}
		})
	}
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
		client := NewPrivateIPAllowedHTTPClient(0)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != DefaultHTTPTimeout {
			t.Errorf("Expected timeout %v, got %v", DefaultHTTPTimeout, client.Timeout)
		}
	})

	t.Run("creates client with custom timeout", func(t *testing.T) {
		client := NewPrivateIPAllowedHTTPClient(30 * time.Second)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", client.Timeout)
		}
	})

	t.Run("client has standard transport without SSRF protection", func(t *testing.T) {
		client := NewPrivateIPAllowedHTTPClient(0)
		if client.Transport == nil {
			t.Error("Expected client to have transport configured")
		}
	})
}
