package server

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewMockProvider()

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile"},
		AllowedCustomSchemes: []string{"^myapp$", "^com\\.example\\..+$"},
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv
}

func TestServer_validatePKCE(t *testing.T) {
	srv := setupTestServer(t)

	// Generate a valid verifier and challenge for testing
	validVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43 chars
	hash := sha256.Sum256([]byte(validVerifier))
	validChallengeS256 := base64.RawURLEncoding.EncodeToString(hash[:])

	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   bool
	}{
		{
			name:      "valid S256",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  validVerifier,
			wantErr:   false,
		},
		{
			name:      "no PKCE (empty challenge)",
			challenge: "",
			method:    "",
			verifier:  "",
			wantErr:   false,
		},
		{
			name:      "missing verifier when challenge present",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  "",
			wantErr:   true,
		},
		{
			name:      "verifier too short",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  "too-short",
			wantErr:   true,
		},
		{
			name:      "verifier too long",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  string(make([]byte, 129)),
			wantErr:   true,
		},
		{
			name:      "verifier with invalid characters",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  "invalid@characters#here!" + string(make([]byte, 30)),
			wantErr:   true,
		},
		{
			name:      "verifier mismatch",
			challenge: validChallengeS256,
			method:    PKCEMethodS256,
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX", // Different
			wantErr:   true,
		},
		{
			name:      "plain method not allowed",
			challenge: validVerifier,
			method:    PKCEMethodPlain,
			verifier:  validVerifier,
			wantErr:   true,
		},
		{
			name:      "unsupported method",
			challenge: validChallengeS256,
			method:    "MD5",
			verifier:  validVerifier,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validatePKCE(tt.challenge, tt.method, tt.verifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePKCE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_validatePKCE_PlainAllowed(t *testing.T) {
	srv := setupTestServer(t)
	srv.Config.AllowPKCEPlain = true

	validVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   bool
	}{
		{
			name:      "plain method allowed when configured",
			challenge: validVerifier,
			method:    PKCEMethodPlain,
			verifier:  validVerifier,
			wantErr:   false,
		},
		{
			name:      "plain method verifier mismatch",
			challenge: validVerifier,
			method:    PKCEMethodPlain,
			verifier:  "different-verifier-that-is-long-enough-chars",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validatePKCE(tt.challenge, tt.method, tt.verifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePKCE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_validateScopes(t *testing.T) {
	srv := setupTestServer(t)

	tests := []struct {
		name    string
		scope   string
		wantErr bool
	}{
		{
			name:    "valid single scope",
			scope:   "openid",
			wantErr: false,
		},
		{
			name:    "valid multiple scopes",
			scope:   "openid email profile",
			wantErr: false,
		},
		{
			name:    "empty scope",
			scope:   "",
			wantErr: false,
		},
		{
			name:    "unsupported scope",
			scope:   "admin",
			wantErr: true,
		},
		{
			name:    "mix of valid and invalid scopes",
			scope:   "openid admin",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateScopes(tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_validateScopes_NoRestriction(t *testing.T) {
	srv := setupTestServer(t)
	srv.Config.SupportedScopes = []string{} // No restriction

	tests := []struct {
		name  string
		scope string
	}{
		{
			name:  "any scope allowed",
			scope: "custom-scope other-scope",
		},
		{
			name:  "empty scope",
			scope: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateScopes(tt.scope)
			if err != nil {
				t.Errorf("validateScopes() with no restrictions error = %v", err)
			}
		})
	}
}

func TestServer_validateRedirectURI(t *testing.T) {
	srv := setupTestServer(t)

	// Create a test client with registered URIs
	client := &storage.Client{
		ClientID: "test-client",
		RedirectURIs: []string{
			"https://example.com/callback",
			"http://localhost:8080/callback",
			"myapp://callback",
		},
	}

	tests := []struct {
		name        string
		redirectURI string
		wantErr     bool
	}{
		{
			name:        "registered HTTPS URI",
			redirectURI: "https://example.com/callback",
			wantErr:     false,
		},
		{
			name:        "registered localhost HTTP URI",
			redirectURI: "http://localhost:8080/callback",
			wantErr:     false,
		},
		{
			name:        "registered custom scheme",
			redirectURI: "myapp://callback",
			wantErr:     false,
		},
		{
			name:        "unregistered URI",
			redirectURI: "https://evil.com/callback",
			wantErr:     true,
		},
		{
			name:        "URI with fragment",
			redirectURI: "https://example.com/callback#fragment",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := srv.validateRedirectURI(client, tt.redirectURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedirectURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCustomScheme(t *testing.T) {
	tests := []struct {
		name           string
		scheme         string
		allowedSchemes []string
		wantErr        bool
	}{
		{
			name:           "valid custom scheme",
			scheme:         "myapp",
			allowedSchemes: []string{"^myapp$"},
			wantErr:        false,
		},
		{
			name:           "valid pattern match",
			scheme:         "com.example.myapp",
			allowedSchemes: []string{"^com\\.example\\..+$"},
			wantErr:        false,
		},
		{
			name:           "dangerous scheme - javascript",
			scheme:         "javascript",
			allowedSchemes: []string{".*"},
			wantErr:        true,
		},
		{
			name:           "dangerous scheme - data",
			scheme:         "data",
			allowedSchemes: []string{".*"},
			wantErr:        true,
		},
		{
			name:           "dangerous scheme - file",
			scheme:         "file",
			allowedSchemes: []string{".*"},
			wantErr:        true,
		},
		{
			name:           "scheme not in allowed list",
			scheme:         "notallowed",
			allowedSchemes: []string{"^myapp$"},
			wantErr:        true,
		},
		{
			name:           "default RFC 3986 pattern",
			scheme:         "com.example.app",
			allowedSchemes: []string{},
			wantErr:        false,
		},
		{
			name:           "invalid RFC 3986 pattern",
			scheme:         "123invalid",
			allowedSchemes: []string{},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCustomScheme(tt.scheme, tt.allowedSchemes)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCustomScheme() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "localhost",
			hostname: "localhost",
			want:     true,
		},
		{
			name:     "127.0.0.1",
			hostname: "127.0.0.1",
			want:     true,
		},
		{
			name:     "127.x.x.x range",
			hostname: "127.1.2.3",
			want:     true,
		},
		{
			name:     "IPv6 loopback",
			hostname: "::1",
			want:     true,
		},
		{
			name:     "IPv6 loopback with brackets",
			hostname: "[::1]",
			want:     true,
		},
		{
			name:     "localhost with port",
			hostname: "localhost:8080",
			want:     true,
		},
		{
			name:     "non-loopback",
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "non-loopback IP",
			hostname: "192.168.1.1",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLoopbackAddress(tt.hostname)
			if got != tt.want {
				t.Errorf("isLoopbackAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURISecurityEnhanced(t *testing.T) {
	tests := []struct {
		name                 string
		redirectURI          string
		serverIssuer         string
		allowedCustomSchemes []string
		wantErr              bool
	}{
		{
			name:         "valid HTTPS URI",
			redirectURI:  "https://example.com/callback",
			serverIssuer: "https://auth.example.com",
			wantErr:      false,
		},
		{
			name:         "valid HTTP localhost",
			redirectURI:  "http://localhost:8080/callback",
			serverIssuer: "https://auth.example.com",
			wantErr:      false,
		},
		{
			name:         "valid HTTP 127.0.0.1",
			redirectURI:  "http://127.0.0.1:3000/callback",
			serverIssuer: "https://auth.example.com",
			wantErr:      false,
		},
		{
			name:         "HTTP non-localhost with HTTPS server",
			redirectURI:  "http://example.com/callback",
			serverIssuer: "https://auth.example.com",
			wantErr:      true,
		},
		{
			name:         "HTTP non-localhost with HTTP server",
			redirectURI:  "http://example.com/callback",
			serverIssuer: "http://auth.example.com",
			wantErr:      false,
		},
		{
			name:         "URI with fragment",
			redirectURI:  "https://example.com/callback#fragment",
			serverIssuer: "https://auth.example.com",
			wantErr:      true,
		},
		{
			name:                 "valid custom scheme",
			redirectURI:          "myapp://callback",
			serverIssuer:         "https://auth.example.com",
			allowedCustomSchemes: []string{"^myapp$"},
			wantErr:              false,
		},
		{
			name:                 "invalid custom scheme",
			redirectURI:          "notallowed://callback",
			serverIssuer:         "https://auth.example.com",
			allowedCustomSchemes: []string{"^myapp$"},
			wantErr:              true,
		},
		{
			name:         "invalid URI format",
			redirectURI:  "://invalid",
			serverIssuer: "https://auth.example.com",
			wantErr:      true,
		},
		{
			name:         "dangerous javascript scheme",
			redirectURI:  "javascript:alert(1)",
			serverIssuer: "https://auth.example.com",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedirectURISecurityEnhanced(tt.redirectURI, tt.serverIssuer, tt.allowedCustomSchemes)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedirectURISecurityEnhanced() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
