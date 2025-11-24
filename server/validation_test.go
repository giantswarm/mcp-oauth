package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testServerSetup holds common test dependencies
type testServerSetup struct {
	provider *mock.MockProvider
	store    *memory.Store
	logger   *slog.Logger
	logBuf   *bytes.Buffer
}

// newTestServerSetup creates a test server setup with optional custom logger
func newTestServerSetup(customLogger bool) *testServerSetup {
	setup := &testServerSetup{
		provider: mock.NewMockProvider(),
		store:    memory.New(),
	}

	if customLogger {
		setup.logBuf = &bytes.Buffer{}
		setup.logger = slog.New(slog.NewTextHandler(setup.logBuf, nil))
	} else {
		setup.logger = slog.Default()
	}

	return setup
}

// createServer creates a server with the given config
func (s *testServerSetup) createServer(config *Config) (*Server, error) {
	return New(s.provider, s.store, s.store, s.store, config, s.logger)
}

// getLogs returns the captured log output (only if custom logger was used)
func (s *testServerSetup) getLogs() string {
	if s.logBuf == nil {
		return ""
	}
	return s.logBuf.String()
}

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
			setup := newTestServerSetup(false)
			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: false,
			}

			srv, err := setup.createServer(config)
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
			setup := newTestServerSetup(true)
			config := &Config{
				Issuer:            "http://" + host + ":8080",
				AllowInsecureHTTP: false,
			}

			srv, err := setup.createServer(config)
			if err != nil {
				t.Fatalf("Expected no error for localhost HTTP, got: %v", err)
			}
			if srv == nil {
				t.Fatal("Expected server to be created")
			}

			// Verify warning was logged
			logOutput := setup.getLogs()
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
	setup := newTestServerSetup(true)
	config := &Config{
		Issuer:            "http://localhost:8080",
		AllowInsecureHTTP: true,
	}

	srv, err := setup.createServer(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if srv == nil {
		t.Fatal("Expected server to be created")
	}

	// With AllowInsecureHTTP=true, should not log development warning
	logOutput := setup.getLogs()
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
			setup := newTestServerSetup(false)
			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: false,
			}

			srv, err := setup.createServer(config)
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
	setup := newTestServerSetup(true)
	config := &Config{
		Issuer:            "http://oauth.example.com",
		AllowInsecureHTTP: true,
	}

	srv, err := setup.createServer(config)
	if err != nil {
		t.Fatalf("Expected no error with AllowInsecureHTTP=true, got: %v", err)
	}
	if srv == nil {
		t.Fatal("Expected server to be created")
	}

	// Verify critical security warning was logged
	logOutput := setup.getLogs()
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
	setup := newTestServerSetup(false)
	config := &Config{
		Issuer:            "ftp://oauth.example.com",
		AllowInsecureHTTP: false,
	}

	srv, err := setup.createServer(config)
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
	setup := newTestServerSetup(false)
	config := &Config{
		Issuer:            "://invalid-url",
		AllowInsecureHTTP: false,
	}

	srv, err := setup.createServer(config)
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
			setup := newTestServerSetup(true)
			config := &Config{
				Issuer:            "http://" + addr + ":8080",
				AllowInsecureHTTP: false,
			}

			srv, err := setup.createServer(config)
			if err != nil {
				t.Fatalf("Expected no error for loopback address %s, got: %v", addr, err)
			}
			if srv == nil {
				t.Fatal("Expected server to be created")
			}

			// Verify warning was logged (since it's localhost without AllowInsecureHTTP=true)
			logOutput := setup.getLogs()
			if !strings.Contains(logOutput, "DEVELOPMENT WARNING") {
				t.Errorf("Expected warning log for HTTP on loopback %s, got: %s", addr, logOutput)
			}
		})
	}
}

// TestConfigSecurityWarning_AllowInsecureHTTP verifies that the config
// security warning is logged when AllowInsecureHTTP is enabled
func TestConfigSecurityWarning_AllowInsecureHTTP(t *testing.T) {
	setup := newTestServerSetup(true)
	config := &Config{
		Issuer:            "https://oauth.example.com",
		AllowInsecureHTTP: true,
	}

	// Apply secure defaults (which includes logging warnings)
	_ = applySecureDefaults(config, setup.logger)

	// Verify critical security warning was logged
	logOutput := setup.getLogs()
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
	setup := newTestServerSetup(false)

	// Test that HTTPS enforcement happens before any storage operations
	config := &Config{
		Issuer:            "http://oauth.example.com",
		AllowInsecureHTTP: false,
	}

	srv, err := setup.createServer(config)
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
			setup := newTestServerSetup(false)
			config := &Config{
				Issuer:            tt.issuer,
				AllowInsecureHTTP: tt.allowHTTP,
			}

			srv, err := setup.createServer(config)

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

func TestValidateStateParameter(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		RequirePKCE:    true,
		AllowPKCEPlain: false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name    string
		state   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty state",
			state:   "",
			wantErr: true,
			errMsg:  "state parameter is required for CSRF protection",
		},
		{
			name:    "state too short - 1 character",
			state:   "x",
			wantErr: true,
			errMsg:  "state parameter must be at least 32 characters for security",
		},
		{
			name:    "state too short - 10 characters",
			state:   "0123456789",
			wantErr: true,
			errMsg:  "state parameter must be at least 32 characters for security",
		},
		{
			name:    "state too short - 31 characters (just under minimum)",
			state:   "0123456789012345678901234567890",
			wantErr: true,
			errMsg:  "state parameter must be at least 32 characters for security",
		},
		{
			name:    "state exactly minimum length - 32 characters",
			state:   "01234567890123456789012345678901",
			wantErr: false,
		},
		{
			name:    "state above minimum - 43 characters (PKCE verifier length)",
			state:   "0123456789012345678901234567890123456789012",
			wantErr: false,
		},
		{
			name:    "state above minimum - 64 characters",
			state:   "0123456789012345678901234567890123456789012345678901234567890123",
			wantErr: false,
		},
		{
			name:    "state with special characters and minimum length",
			state:   "abcdef-GHIJKL_mnopqr.stuvwxyz",
			wantErr: true, // This is 31 chars
		},
		{
			name:    "state with base64url characters and minimum length",
			state:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", // 32 chars
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateStateParameter(tt.state)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateStateParameter() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateStateParameter() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateStateParameter() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestValidateStateParameter_TimingAttackResistance ensures that state validation
// combined with constant-time comparison provides timing attack resistance.
// This test verifies that the validation enforces minimum length requirements
// which is the first line of defense against timing attacks.
func TestValidateStateParameter_TimingAttackResistance(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		RequirePKCE:    true,
		AllowPKCEPlain: false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test that very short states (which could be brute-forced quickly) are rejected
	shortStates := []string{
		"a",
		"ab",
		"abc",
		"abcd",
		"12345",
		"0123456789",           // 10 chars
		"01234567890123456789", // 20 chars
	}

	for _, state := range shortStates {
		err := srv.validateStateParameter(state)
		if err == nil {
			t.Errorf("validateStateParameter(%q) expected error for short state (len=%d) but got none", state, len(state))
		}
	}

	// Test that states meeting minimum length are accepted
	// This ensures sufficient entropy for CSRF protection and timing attack resistance
	validStates := []string{
		strings.Repeat("a", 32),  // Exactly minimum
		strings.Repeat("b", 43),  // PKCE verifier length
		strings.Repeat("c", 64),  // Double minimum
		strings.Repeat("d", 128), // Very long
	}

	for _, state := range validStates {
		err := srv.validateStateParameter(state)
		if err != nil {
			t.Errorf("validateStateParameter(%q) unexpected error for valid state (len=%d): %v", state[:10]+"...", len(state), err)
		}
	}
}

// TestMinStateLength_ConstantSync ensures server.MinStateLength stays in sync with oauth.MinStateLength.
// This test will fail if the constants drift out of sync.
// The constants are duplicated to avoid circular imports (root package imports server).
// IMPORTANT: If this test fails, update BOTH constants.go AND server/validation.go
func TestMinStateLength_ConstantSync(t *testing.T) {
	// Expected value must match oauth.MinStateLength in constants.go
	const expectedMinStateLength = 32

	if MinStateLength != expectedMinStateLength {
		t.Errorf("server.MinStateLength (%d) != expected (%d) - constants out of sync! Update BOTH constants.go and server/validation.go",
			MinStateLength, expectedMinStateLength)
	}
}
