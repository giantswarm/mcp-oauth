package oidc

import (
	"strings"
	"testing"
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
			} else {
				if err != nil {
					t.Errorf("ValidateIssuerURL() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ValidateConnectorID() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ValidateScopes() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ValidateGroups() unexpected error = %v", err)
				}
			}
		})
	}
}
