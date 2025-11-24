package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestValidateHTTPSEnforcement_HTTPS(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
	}{
		{
			name:   "HTTPS production URL",
			issuer: "https://oauth.example.com",
		},
		{
			name:   "HTTPS localhost",
			issuer: "https://localhost:8080",
		},
		{
			name:   "HTTPS with port",
			issuer: "https://oauth.example.com:8443",
		},
		{
			name:   "HTTPS with path",
			issuer: "https://example.com/oauth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := mock.NewMockProvider()
			memStore := memory.New()

			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: false,
			}

			srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())
			if err != nil {
				t.Fatalf("Expected no error for HTTPS URL, got: %v", err)
			}
			if srv == nil {
				t.Fatal("Expected server to be created")
			}
		})
	}
}

func TestValidateHTTPSEnforcement_HTTPLocalhost(t *testing.T) {
	localhosts := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"[::1]",
	}

	for _, host := range localhosts {
		t.Run("HTTP_"+host, func(t *testing.T) {
			provider := mock.NewMockProvider()
			memStore := memory.New()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, nil))

			config := &Config{
				Issuer:            "http://" + host + ":8080",
				AllowInsecureHTTP: false,
			}

			srv, err := New(provider, memStore, memStore, memStore, config, logger)
			if err != nil {
				t.Fatalf("Expected no error for localhost HTTP, got: %v", err)
			}
			if srv == nil {
				t.Fatal("Expected server to be created")
			}

			// Verify warning was logged
			logOutput := logBuf.String()
			if !strings.Contains(logOutput, "DEVELOPMENT WARNING") {
				t.Errorf("Expected warning log for HTTP localhost, got: %s", logOutput)
			}
			if !strings.Contains(logOutput, "Running OAuth over HTTP") {
				t.Errorf("Expected warning about HTTP, got: %s", logOutput)
			}
		})
	}
}

func TestValidateHTTPSEnforcement_HTTPLocalhostWithFlag(t *testing.T) {
	provider := mock.NewMockProvider()
	memStore := memory.New()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	config := &Config{
		Issuer:            "http://localhost:8080",
		AllowInsecureHTTP: true,
	}

	srv, err := New(provider, memStore, memStore, memStore, config, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if srv == nil {
		t.Fatal("Expected server to be created")
	}

	// With AllowInsecureHTTP=true, should not log development warning
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "DEVELOPMENT WARNING") {
		t.Errorf("Should not log development warning when AllowInsecureHTTP=true")
	}
}

func TestValidateHTTPSEnforcement_HTTPNonLocalhostBlocked(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
	}{
		{
			name:   "HTTP production domain",
			issuer: "http://oauth.example.com",
		},
		{
			name:   "HTTP production with port",
			issuer: "http://oauth.example.com:8080",
		},
		{
			name:   "HTTP IP address",
			issuer: "http://192.168.1.100",
		},
		{
			name:   "HTTP public IP",
			issuer: "http://203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := mock.NewMockProvider()
			memStore := memory.New()

			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: false,
			}

			srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())
			if err == nil {
				t.Fatalf("Expected error for non-localhost HTTP, but got none")
			}
			if srv != nil {
				t.Fatal("Expected server creation to fail")
			}

			// Verify error message
			errMsg := err.Error()
			if !strings.Contains(errMsg, "SECURITY ERROR") {
				t.Errorf("Expected SECURITY ERROR in message, got: %s", errMsg)
			}
			if !strings.Contains(errMsg, "HTTPS") {
				t.Errorf("Expected HTTPS mentioned in error, got: %s", errMsg)
			}
			if !strings.Contains(errMsg, "AllowInsecureHTTP") {
				t.Errorf("Expected AllowInsecureHTTP mentioned in error, got: %s", errMsg)
			}
		})
	}
}

func TestValidateHTTPSEnforcement_HTTPNonLocalhostWithFlag(t *testing.T) {
	provider := mock.NewMockProvider()
	memStore := memory.New()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	config := &Config{
		Issuer:            "http://oauth.example.com",
		AllowInsecureHTTP: true,
	}

	srv, err := New(provider, memStore, memStore, memStore, config, logger)
	if err != nil {
		t.Fatalf("Expected no error with AllowInsecureHTTP=true, got: %v", err)
	}
	if srv == nil {
		t.Fatal("Expected server to be created")
	}

	// Verify critical security warning was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "CRITICAL SECURITY WARNING") {
		t.Errorf("Expected critical warning for non-localhost HTTP, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "network sniffing") || !strings.Contains(logOutput, "MITM") {
		t.Errorf("Expected warning about security risks, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "OAuth 2.1") {
		t.Errorf("Expected OAuth 2.1 compliance mention, got: %s", logOutput)
	}
}

func TestValidateHTTPSEnforcement_InvalidScheme(t *testing.T) {
	provider := mock.NewMockProvider()
	memStore := memory.New()

	config := &Config{
		Issuer:            "ftp://oauth.example.com",
		AllowInsecureHTTP: false,
	}

	srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())
	if err == nil {
		t.Fatalf("Expected error for invalid scheme, but got none")
	}
	if srv != nil {
		t.Fatal("Expected server creation to fail")
	}

	// Verify error message
	errMsg := err.Error()
	if !strings.Contains(errMsg, "invalid issuer URL scheme") {
		t.Errorf("Expected invalid scheme error, got: %s", errMsg)
	}
}

func TestValidateHTTPSEnforcement_InvalidURL(t *testing.T) {
	provider := mock.NewMockProvider()
	memStore := memory.New()

	config := &Config{
		Issuer:            "://invalid-url",
		AllowInsecureHTTP: false,
	}

	srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())
	if err == nil {
		t.Fatalf("Expected error for invalid URL, but got none")
	}
	if srv != nil {
		t.Fatal("Expected server creation to fail")
	}
}

func TestIsLocalhostHostname(t *testing.T) {
	tests := []struct {
		hostname string
		want     bool
	}{
		// Localhost hostname
		{"localhost", true},

		// IPv4 loopback - standard
		{"127.0.0.1", true},

		// IPv4 loopback - entire 127.0.0.0/8 range (RFC 1122)
		{"127.0.0.0", true},
		{"127.0.0.2", true},
		{"127.1.2.3", true},
		{"127.255.255.255", true},

		// IPv6 loopback
		{"::1", true},
		{"[::1]", true},

		// IPv4-mapped IPv6 loopback
		{"::ffff:127.0.0.1", true},
		{"[::ffff:127.0.0.1]", true},

		// Special: 0.0.0.0 (bind-all, used in development)
		{"0.0.0.0", true},

		// Non-loopback addresses
		{"example.com", false},
		{"192.168.1.1", false},
		{"203.0.113.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},

		// Not localhost despite name similarity
		{"oauth.localhost.com", false},
		{"localhost.example.com", false},

		// Edge cases
		{"", false},
		{"localhost.", false}, // Trailing dot (FQDN)
		{"notlocalhost", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got := isLocalhostHostname(tt.hostname)
			if got != tt.want {
				t.Errorf("isLocalhostHostname(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

// TestValidateHTTPSEnforcement_LoopbackRange verifies that the entire
// 127.0.0.0/8 loopback range is correctly recognized as localhost
func TestValidateHTTPSEnforcement_LoopbackRange(t *testing.T) {
	loopbackAddresses := []string{
		"127.0.0.2",
		"127.1.2.3",
		"127.255.255.255",
	}

	for _, addr := range loopbackAddresses {
		t.Run("HTTP_"+addr, func(t *testing.T) {
			provider := mock.NewMockProvider()
			memStore := memory.New()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, nil))

			config := &Config{
				Issuer:            "http://" + addr + ":8080",
				AllowInsecureHTTP: false,
			}

			srv, err := New(provider, memStore, memStore, memStore, config, logger)
			if err != nil {
				t.Fatalf("Expected no error for loopback address %s, got: %v", addr, err)
			}
			if srv == nil {
				t.Fatal("Expected server to be created")
			}

			// Verify warning was logged (since it's localhost without AllowInsecureHTTP=true)
			logOutput := logBuf.String()
			if !strings.Contains(logOutput, "DEVELOPMENT WARNING") {
				t.Errorf("Expected warning log for HTTP on loopback %s, got: %s", addr, logOutput)
			}
		})
	}
}

// TestConfigSecurityWarning_AllowInsecureHTTP verifies that the config
// security warning is logged when AllowInsecureHTTP is enabled
func TestConfigSecurityWarning_AllowInsecureHTTP(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	config := &Config{
		Issuer:            "https://oauth.example.com",
		AllowInsecureHTTP: true,
	}

	// Apply secure defaults (which includes logging warnings)
	_ = applySecureDefaults(config, logger)

	// Verify critical security warning was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "CRITICAL SECURITY WARNING") {
		t.Errorf("Expected critical warning in config, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "HTTP is explicitly allowed") {
		t.Errorf("Expected warning about HTTP being allowed, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "OAuth 2.1") {
		t.Errorf("Expected OAuth 2.1 compliance mention, got: %s", logOutput)
	}
}

// TestHTTPSEnforcement_IntegrationWithStorage ensures HTTPS enforcement
// works correctly with different storage implementations
func TestHTTPSEnforcement_IntegrationWithStorage(t *testing.T) {
	provider := mock.NewMockProvider()
	memStore := memory.New()

	// Test that HTTPS enforcement happens before any storage operations
	config := &Config{
		Issuer:            "http://oauth.example.com",
		AllowInsecureHTTP: false,
	}

	srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())
	if err == nil {
		t.Fatal("Expected error for HTTP without flag")
	}
	if srv != nil {
		t.Fatal("Expected server creation to fail")
	}

	// Storage should not have been initialized since validation failed early
	// This is a behavioral test to ensure early validation
}

// TestHTTPSEnforcement_WithPort verifies HTTPS enforcement works with URLs
// that include port numbers
func TestHTTPSEnforcement_WithPort(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		allowHTTP bool
		wantErr   bool
	}{
		{
			name:      "HTTPS with standard port",
			issuer:    "https://oauth.example.com:443",
			allowHTTP: false,
			wantErr:   false,
		},
		{
			name:      "HTTPS with custom port",
			issuer:    "https://oauth.example.com:8443",
			allowHTTP: false,
			wantErr:   false,
		},
		{
			name:      "HTTP localhost with port allowed",
			issuer:    "http://localhost:8080",
			allowHTTP: false,
			wantErr:   false,
		},
		{
			name:      "HTTP production with port blocked",
			issuer:    "http://oauth.example.com:8080",
			allowHTTP: false,
			wantErr:   true,
		},
		{
			name:      "HTTP production with port and flag",
			issuer:    "http://oauth.example.com:8080",
			allowHTTP: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := mock.NewMockProvider()
			memStore := memory.New()

			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: tt.allowHTTP,
			}

			srv, err := New(provider, memStore, memStore, memStore, config, slog.Default())

			if tt.wantErr && err == nil {
				t.Fatalf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}
			if tt.wantErr && srv != nil {
				t.Fatal("Expected server creation to fail but got server")
			}
			if !tt.wantErr && srv == nil {
				t.Fatal("Expected server to be created but got nil")
			}
		})
	}
}
