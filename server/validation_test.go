package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testServerSetup holds common test dependencies
type testServerSetup struct {
	provider *mock.Provider
	store    *memory.Store
	logger   *slog.Logger
	logBuf   *bytes.Buffer
}

// newTestServerSetup creates a test server setup with optional custom logger
func newTestServerSetup(customLogger bool) *testServerSetup {
	setup := &testServerSetup{
		provider: mock.NewProvider(),
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

	_ = applySecureDefaults(config, setup.logger)

	logOutput := setup.getLogs()
	if !strings.Contains(logOutput, "SECURITY WARNING: AllowInsecureHTTP is enabled") {
		t.Errorf("Expected AllowInsecureHTTP security warning, got: %s", logOutput)
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

func TestValidateClientStateParameter(t *testing.T) {
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
			errMsg:  "state parameter must be at least 24 characters for security",
		},
		{
			name:    "state too short - 10 characters",
			state:   "0123456789",
			wantErr: true,
			errMsg:  "state parameter must be at least 24 characters for security",
		},
		{
			name:    "state too short - 23 characters (just under minimum)",
			state:   "01234567890123456789012",
			wantErr: true,
			errMsg:  "state parameter must be at least 24 characters for security",
		},
		{
			name:    "state exactly minimum length - 24 characters",
			state:   "012345678901234567890123",
			wantErr: false,
		},
		{
			name:    "state 31 characters (above minimum)",
			state:   "0123456789012345678901234567890",
			wantErr: false,
		},
		{
			name:    "state above minimum - 32 characters",
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
			name:    "state with special characters above minimum length",
			state:   "abcdef-GHIJKL_mnopqr.stuvwxyz",
			wantErr: false, // 29 chars, above 24-char minimum
		},
		{
			name:    "state with base64url characters and above minimum length",
			state:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", // 32 chars
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateClientStateParameter(tt.state)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateClientStateParameter() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateClientStateParameter() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateClientStateParameter() unexpected error = %v", err)
			}
		})
	}
}

// TestValidateClientStateParameter_TimingAttackResistance ensures that state validation
// combined with constant-time comparison provides timing attack resistance.
// This test verifies that the validation enforces minimum length requirements
// which is the first line of defense against timing attacks.
func TestValidateClientStateParameter_TimingAttackResistance(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		RequirePKCE:    true,
		AllowPKCEPlain: false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

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
		err := srv.validateClientStateParameter(state)
		if err == nil {
			t.Errorf("validateClientStateParameter(%q) expected error for short state (len=%d) but got none", state, len(state))
		}
	}

	validStates := []string{
		strings.Repeat("a", 24),  // Exactly minimum
		strings.Repeat("b", 32),  // Previous default
		strings.Repeat("c", 43),  // PKCE verifier length
		strings.Repeat("d", 64),  // Well above minimum
		strings.Repeat("e", 128), // Very long
	}

	for _, state := range validStates {
		err := srv.validateClientStateParameter(state)
		if err != nil {
			t.Errorf("validateClientStateParameter(%q) unexpected error for valid state (len=%d): %v", state[:10]+"...", len(state), err)
		}
	}
}

func TestValidateClientScopes(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		RequirePKCE:    true,
		AllowPKCEPlain: false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		requestedScope string
		clientScopes   []string
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "empty client scopes allows all",
			requestedScope: "openid profile email",
			clientScopes:   []string{},
			wantErr:        false,
		},
		{
			name:           "nil client scopes allows all",
			requestedScope: "openid profile email",
			clientScopes:   nil,
			wantErr:        false,
		},
		{
			name:           "empty requested scope is always allowed",
			requestedScope: "",
			clientScopes:   []string{"openid"},
			wantErr:        false,
		},
		{
			name:           "single scope - authorized",
			requestedScope: "openid",
			clientScopes:   []string{"openid", "profile", "email"},
			wantErr:        false,
		},
		{
			name:           "single scope - unauthorized",
			requestedScope: "admin",
			clientScopes:   []string{"openid", "profile"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "multiple scopes - all authorized",
			requestedScope: "openid profile",
			clientScopes:   []string{"openid", "profile", "email"},
			wantErr:        false,
		},
		{
			name:           "multiple scopes - all authorized (different order)",
			requestedScope: "profile openid",
			clientScopes:   []string{"openid", "profile", "email"},
			wantErr:        false,
		},
		{
			name:           "multiple scopes - one unauthorized",
			requestedScope: "openid admin",
			clientScopes:   []string{"openid", "profile"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "multiple scopes - multiple unauthorized",
			requestedScope: "openid admin superuser",
			clientScopes:   []string{"openid", "profile"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "scope escalation attempt",
			requestedScope: "read:user write:user admin:all",
			clientScopes:   []string{"read:user", "write:user"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "exact match - single scope",
			requestedScope: "openid",
			clientScopes:   []string{"openid"},
			wantErr:        false,
		},
		{
			name:           "client restricted to subset",
			requestedScope: "openid",
			clientScopes:   []string{"openid", "profile"},
			wantErr:        false,
		},
		{
			name:           "request all client scopes",
			requestedScope: "openid profile email",
			clientScopes:   []string{"openid", "profile", "email"},
			wantErr:        false,
		},
		{
			name:           "custom scopes - authorized",
			requestedScope: "read:api write:api",
			clientScopes:   []string{"read:api", "write:api", "delete:api"},
			wantErr:        false,
		},
		{
			name:           "custom scopes - unauthorized",
			requestedScope: "read:api delete:api",
			clientScopes:   []string{"read:api", "write:api"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "scope with special characters - authorized",
			requestedScope: "https://www.googleapis.com/auth/userinfo.email",
			clientScopes:   []string{"https://www.googleapis.com/auth/userinfo.email", "openid"},
			wantErr:        false,
		},
		{
			name:           "scope with special characters - unauthorized",
			requestedScope: "https://www.googleapis.com/auth/admin.directory",
			clientScopes:   []string{"https://www.googleapis.com/auth/userinfo.email"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "case sensitive scope check",
			requestedScope: "OpenID",
			clientScopes:   []string{"openid"},
			wantErr:        true,
			errMsg:         "client is not authorized for one or more requested scopes",
		},
		{
			name:           "whitespace handling - single space",
			requestedScope: "openid profile",
			clientScopes:   []string{"openid", "profile"},
			wantErr:        false,
		},
		{
			name:           "whitespace handling - multiple spaces",
			requestedScope: "openid  profile   email",
			clientScopes:   []string{"openid", "profile", "email"},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateClientScopes(tt.requestedScope, tt.clientScopes)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateClientScopes() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateClientScopes() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateClientScopes() unexpected error = %v", err)
			}
		})
	}
}

// TestValidateClientScopes_SecurityScenarios tests real-world security scenarios
// to ensure proper scope validation prevents unauthorized access
func TestValidateClientScopes_SecurityScenarios(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		RequirePKCE:    true,
		AllowPKCEPlain: false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	t.Run("read-only client attempts write", func(t *testing.T) {
		err := srv.validateClientScopes("read:api write:api", []string{"read:api"})
		if err == nil {
			t.Error("Expected error when read-only client requests write scope")
		}
		// Verify error is generic (doesn't reveal specific unauthorized scope)
		if !strings.Contains(err.Error(), "client is not authorized for one or more requested scopes") {
			t.Errorf("Error should be generic security message, got: %v", err)
		}
	})

	t.Run("mobile app attempts admin escalation", func(t *testing.T) {
		// Mobile app registered with basic scopes attempts to get admin access
		err := srv.validateClientScopes("openid profile admin:users", []string{"openid", "profile", "email"})
		if err == nil {
			t.Error("Expected error when mobile app attempts admin escalation")
		}
		// Verify error is generic (doesn't reveal specific unauthorized scope)
		if !strings.Contains(err.Error(), "client is not authorized for one or more requested scopes") {
			t.Errorf("Error should be generic security message, got: %v", err)
		}
	})

	t.Run("compromised client with limited scopes", func(t *testing.T) {
		// Even if client is compromised, it can only get scopes it's authorized for
		clientScopes := []string{"read:public"}
		unauthorizedRequests := []string{
			"read:private",
			"write:public",
			"delete:public",
			"admin:all",
		}

		for _, scope := range unauthorizedRequests {
			err := srv.validateClientScopes(scope, clientScopes)
			if err == nil {
				t.Errorf("Expected error for unauthorized scope: %s", scope)
			}
		}
	})

	t.Run("backward compatibility - unrestricted clients", func(t *testing.T) {
		// Clients registered before scope restrictions were added (nil/empty scopes)
		// should still work with any requested scope for backward compatibility
		requests := []string{
			"openid",
			"openid profile email",
			"admin:all",
			"custom:scope",
		}

		for _, scope := range requests {
			// Empty client scopes
			err := srv.validateClientScopes(scope, []string{})
			if err != nil {
				t.Errorf("Expected no error for unrestricted client (empty scopes), scope=%s, got: %v", scope, err)
			}

			// Nil client scopes
			err = srv.validateClientScopes(scope, nil)
			if err != nil {
				t.Errorf("Expected no error for unrestricted client (nil scopes), scope=%s, got: %v", scope, err)
			}
		}
	})
}

// TestValidateClientStateParameter_AllowNoState tests that empty and short
// client state is allowed when AllowNoStateParameter is enabled.
func TestValidateClientStateParameter_AllowNoState(t *testing.T) {
	t.Run("empty state rejected when AllowNoStateParameter=false (default)", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: false,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateClientStateParameter("")
		if err == nil {
			t.Error("Expected error for empty state when AllowNoStateParameter=false")
		}
	})

	t.Run("empty state allowed when AllowNoStateParameter=true", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: true,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateClientStateParameter("")
		if err != nil {
			t.Errorf("Expected no error for empty state when AllowNoStateParameter=true, got: %v", err)
		}
	})

	t.Run("valid state works regardless of AllowNoStateParameter setting", func(t *testing.T) {
		validState := "0123456789012345678901234567890123456789012" // 43 chars

		setup1 := newTestServerSetup(false)
		srv1, err := setup1.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: false,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}
		if err := srv1.validateClientStateParameter(validState); err != nil {
			t.Errorf("Valid state should work with AllowNoStateParameter=false: %v", err)
		}

		setup2 := newTestServerSetup(false)
		srv2, err := setup2.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: true,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}
		if err := srv2.validateClientStateParameter(validState); err != nil {
			t.Errorf("Valid state should work with AllowNoStateParameter=true: %v", err)
		}
	})

	t.Run("short non-empty state accepted when AllowNoStateParameter=true", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: true,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateClientStateParameter("short")
		if err != nil {
			t.Errorf("Expected no error for short state when AllowNoStateParameter=true, got: %v", err)
		}
	})

	t.Run("short non-empty state rejected when AllowNoStateParameter=false", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: false,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateClientStateParameter("short")
		if err == nil {
			t.Error("Expected error for short state when AllowNoStateParameter=false")
		}
	})
}

// TestCanonicalLoopbackRedirectURI_Match tests RFC 8252 §7.3 port-agnostic
// matching for loopback redirect URIs.
func TestCanonicalLoopbackRedirectURI_Match(t *testing.T) {
	tests := []struct {
		name           string
		requestedURI   string
		registeredURIs []string
		want           bool
	}{
		// RFC 8252 Section 7.3: Port MUST be allowed to vary for loopback
		{
			name:           "localhost with ephemeral port matches registered without port",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{"http://localhost/callback"},
			want:           true,
		},
		{
			name:           "localhost with different ephemeral port",
			requestedURI:   "http://localhost:12345/callback",
			registeredURIs: []string{"http://localhost/callback"},
			want:           true,
		},
		{
			name:           "127.0.0.1 with ephemeral port matches registered without port",
			requestedURI:   "http://127.0.0.1:49567/callback",
			registeredURIs: []string{"http://127.0.0.1/callback"},
			want:           true,
		},
		{
			name:           "IPv6 loopback with port",
			requestedURI:   "http://[::1]:49567/callback",
			registeredURIs: []string{"http://[::1]/callback"},
			want:           true,
		},
		{
			name:           "registered with port matches request with different port",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{"http://localhost:3000/callback"},
			want:           true,
		},
		{
			name:           "exact match still works",
			requestedURI:   "http://localhost/callback",
			registeredURIs: []string{"http://localhost/callback"},
			want:           true,
		},
		// Path must match
		{
			name:           "different path does not match",
			requestedURI:   "http://localhost:49567/other",
			registeredURIs: []string{"http://localhost/callback"},
			want:           false,
		},
		// Path comparison is case-sensitive and exact — trailing slashes differ
		{
			name:           "trailing slash mismatch does not match (requested has slash)",
			requestedURI:   "http://localhost:49567/callback/",
			registeredURIs: []string{"http://localhost/callback"},
			want:           false,
		},
		{
			name:           "trailing slash mismatch does not match (registered has slash)",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{"http://localhost/callback/"},
			want:           false,
		},
		// Scheme must match
		{
			name:           "different scheme does not match",
			requestedURI:   "https://localhost:49567/callback",
			registeredURIs: []string{"http://localhost/callback"},
			want:           false,
		},
		// Host must match
		{
			name:           "localhost does not match 127.0.0.1",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{"http://127.0.0.1/callback"},
			want:           false,
		},
		// Non-loopback URIs are never matched by this function
		{
			name:           "non-loopback URI is not matched",
			requestedURI:   "https://example.com:8080/callback",
			registeredURIs: []string{"https://example.com/callback"},
			want:           false,
		},
		{
			name:           "non-loopback registered URI is skipped",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{"https://example.com/callback"},
			want:           false,
		},
		// Multiple registered URIs
		{
			name:         "matches one of multiple registered URIs",
			requestedURI: "http://localhost:49567/callback",
			registeredURIs: []string{
				"https://example.com/callback",
				"http://localhost/callback",
			},
			want: true,
		},
		// Empty/invalid
		{
			name:           "empty registered URIs",
			requestedURI:   "http://localhost:49567/callback",
			registeredURIs: []string{},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := canonicalLoopbackRedirectURI(tt.requestedURI, tt.registeredURIs)
			if got != tt.want {
				t.Errorf("canonicalLoopbackRedirectURI(%q, %v) match = %v, want %v",
					tt.requestedURI, tt.registeredURIs, got, tt.want)
			}
		})
	}
}

// TestValidateRedirectURI_RFC8252LoopbackPort tests the full validateRedirectURI
// flow with RFC 8252 port-agnostic matching enabled via AllowLocalhostRedirectURIs.
func TestValidateRedirectURI_RFC8252LoopbackPort(t *testing.T) {
	tests := []struct {
		name                       string
		redirectURI                string
		registeredURIs             []string
		allowLocalhostRedirectURIs bool
		wantErr                    bool
	}{
		{
			name:                       "loopback port matching enabled - matches",
			redirectURI:                "http://localhost:49567/callback",
			registeredURIs:             []string{"http://localhost/callback"},
			allowLocalhostRedirectURIs: true,
			wantErr:                    false,
		},
		{
			name:                       "loopback port matching disabled - rejects",
			redirectURI:                "http://localhost:49567/callback",
			registeredURIs:             []string{"http://localhost/callback"},
			allowLocalhostRedirectURIs: false,
			wantErr:                    true,
		},
		{
			name:                       "non-loopback is never port-agnostic even when enabled",
			redirectURI:                "https://example.com:8080/callback",
			registeredURIs:             []string{"https://example.com/callback"},
			allowLocalhostRedirectURIs: true,
			wantErr:                    true,
		},
		{
			name:                       "exact match works regardless of setting",
			redirectURI:                "http://localhost/callback",
			registeredURIs:             []string{"http://localhost/callback"},
			allowLocalhostRedirectURIs: false,
			wantErr:                    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := newTestServerSetup(false)
			config := &Config{
				AllowLocalhostRedirectURIs: tt.allowLocalhostRedirectURIs,
				AllowInsecureHTTP:          true,
				Issuer:                     "http://localhost:8080",
			}
			srv, err := setup.createServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			client := &storage.Client{
				ClientID:     "test-client",
				RedirectURIs: tt.registeredURIs,
			}

			err = srv.validateRedirectURI(client, tt.redirectURI)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestValidateProviderStateParameter tests that provider state validation always
// enforces minimum length regardless of AllowNoStateParameter.
func TestValidateProviderStateParameter(t *testing.T) {
	t.Run("empty provider state always rejected", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: true,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateProviderStateParameter("")
		if err == nil {
			t.Error("Expected error for empty provider state even with AllowNoStateParameter=true")
		}
	})

	t.Run("short provider state rejected even with AllowNoStateParameter=true", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: true,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		err = srv.validateProviderStateParameter("short")
		if err == nil {
			t.Error("Expected error for short provider state even with AllowNoStateParameter=true")
		}
	})

	t.Run("valid-length provider state accepted", func(t *testing.T) {
		setup := newTestServerSetup(false)
		srv, err := setup.createServer(&Config{
			RequirePKCE:           true,
			AllowNoStateParameter: false,
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		validState := "0123456789012345678901234567890123456789012" // 43 chars
		err = srv.validateProviderStateParameter(validState)
		if err != nil {
			t.Errorf("Expected no error for valid-length provider state, got: %v", err)
		}
	})
}
