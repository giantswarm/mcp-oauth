package google

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"openid", "email"},
			},
			wantErr: false,
		},
		{
			name: "missing client ID",
			config: &Config{
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
			},
			wantErr: true,
		},
		{
			name: "missing client secret",
			config: &Config{
				ClientID:    "test-client-id",
				RedirectURL: "https://example.com/callback",
			},
			wantErr: true,
		},
		{
			name: "default scopes",
			config: &Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && provider != nil {
				if provider.httpClient == nil {
					t.Error("NewProvider() httpClient is nil")
				}
			}
		})
	}
}

func TestNewProvider_WithCustomHTTPClient(t *testing.T) {
	customClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	config := &Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		HTTPClient:   customClient,
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	if provider.httpClient != customClient {
		t.Error("NewProvider() did not use custom HTTP client")
	}
}

func TestProvider_Name(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	if got := provider.Name(); got != "google" {
		t.Errorf("Name() = %q, want %q", got, "google")
	}
}

func TestProvider_AuthorizationURL(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	tests := []struct {
		name                string
		state               string
		codeChallenge       string
		codeChallengeMethod string
		wantContains        []string
	}{
		{
			name:                "with PKCE",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			wantContains: []string{
				"state=test-state",
				"code_challenge=test-challenge",
				"code_challenge_method=S256",
				"access_type=offline",
			},
		},
		{
			name:  "without PKCE",
			state: "test-state",
			wantContains: []string{
				"state=test-state",
				"access_type=offline",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := provider.AuthorizationURL(tt.state, tt.codeChallenge, tt.codeChallengeMethod)

			for _, want := range tt.wantContains {
				if !strings.Contains(authURL, want) {
					t.Errorf("AuthorizationURL() missing %q in URL %q", want, authURL)
				}
			}
		})
	}
}

func TestProvider_ExchangeCode(t *testing.T) {
	// Create mock Google token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		// Verify code parameter
		if r.FormValue("code") != "test-code" {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "test-refresh-token",
		})
	}))
	defer server.Close()

	// Create provider with mock endpoint
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// Override endpoint for testing
	provider.Endpoint.TokenURL = server.URL + "/token"

	// Test exchange
	ctx := context.Background()
	token, err := provider.ExchangeCode(ctx, "test-code", "")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
	}

	if token.RefreshToken != "test-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "test-refresh-token")
	}
}

func TestProvider_ExchangeCode_WithPKCE(t *testing.T) {
	// Create mock Google token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		// Verify code_verifier parameter
		if r.FormValue("code_verifier") != "test-verifier" {
			http.Error(w, "invalid code_verifier", http.StatusBadRequest)
			return
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	provider.Endpoint.TokenURL = server.URL + "/token"

	ctx := context.Background()
	token, err := provider.ExchangeCode(ctx, "test-code", "test-verifier")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
	}
}

func TestProvider_ValidateToken(t *testing.T) {
	// Create mock Google userinfo endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Return mock user info
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            "123456789",
			"email":          "test@example.com",
			"email_verified": true,
			"name":           "Test User",
			"given_name":     "Test",
			"family_name":    "User",
			"picture":        "https://example.com/photo.jpg",
			"locale":         "en",
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// Override endpoint for testing
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &mockTransport{server: server},
	})

	userInfo, err := provider.ValidateToken(ctx, "test-access-token")
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if userInfo.ID != "123456789" {
		t.Errorf("ID = %q, want %q", userInfo.ID, "123456789")
	}

	if userInfo.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", userInfo.Email, "test@example.com")
	}

	if !userInfo.EmailVerified {
		t.Error("EmailVerified should be true")
	}

	if userInfo.Name != "Test User" {
		t.Errorf("Name = %q, want %q", userInfo.Name, "Test User")
	}
}

func TestProvider_ValidateToken_InvalidToken(t *testing.T) {
	// Create mock Google userinfo endpoint that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &mockTransport{server: server},
	})

	_, err = provider.ValidateToken(ctx, "invalid-token")
	if err == nil {
		t.Error("ValidateToken() should return error for invalid token")
	}
}

func TestProvider_RefreshToken(t *testing.T) {
	// Create mock Google token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		// Verify refresh_token parameter
		if r.FormValue("refresh_token") != "test-refresh-token" {
			http.Error(w, "invalid refresh_token", http.StatusBadRequest)
			return
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "new-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	provider.Endpoint.TokenURL = server.URL + "/token"

	ctx := context.Background()
	token, err := provider.RefreshToken(ctx, "test-refresh-token")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if token.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access-token")
	}
}

func TestProvider_RevokeToken(t *testing.T) {
	// Create mock Google revoke endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		// Verify token parameter
		if r.FormValue("token") != "test-token" {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		HTTPClient: &http.Client{
			Transport: &revokeTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	ctx := context.Background()
	err = provider.RevokeToken(ctx, "test-token")
	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}
}

func TestProvider_RevokeToken_Failed(t *testing.T) {
	// Create mock Google revoke endpoint that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "revocation failed", http.StatusBadRequest)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		HTTPClient: &http.Client{
			Transport: &revokeTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	ctx := context.Background()
	err = provider.RevokeToken(ctx, "test-token")
	if err == nil {
		t.Error("RevokeToken() should return error on failure")
	}
}

// mockTransport is a custom http.RoundTripper that redirects userinfo requests to our test server
type mockTransport struct {
	server *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect userinfo requests to our test server
	if strings.Contains(req.URL.String(), "googleapis.com/oauth2/v2/userinfo") {
		testURL, _ := url.Parse(m.server.URL)
		req.URL = testURL
	}
	return http.DefaultTransport.RoundTrip(req)
}

// revokeTransport is a custom http.RoundTripper that redirects revoke requests to our test server
type revokeTransport struct {
	server *httptest.Server
}

func (r *revokeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect revoke requests to our test server
	if strings.Contains(req.URL.String(), "oauth2.googleapis.com/revoke") {
		testURL, _ := url.Parse(r.server.URL)
		req.URL = testURL
	}
	return http.DefaultTransport.RoundTrip(req)
}
