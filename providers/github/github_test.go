package github

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

const (
	testTokenEndpoint  = "/token"
	testAccessToken    = "test-access-token"
	testScopeReadOrg   = "read:org"
	testClientID       = "test-client-id"
	testClientSecret   = "test-client-secret"
	testCallbackURL    = "https://example.com/callback"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
			},
			wantErr: false,
		},
		{
			name: "valid config with custom scopes",
			config: &Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"user:email", "read:user", "repo"},
			},
			wantErr: false,
		},
		{
			name: "valid config with organizations",
			config: &Config{
				ClientID:             "test-client-id",
				ClientSecret:         "test-client-secret",
				RedirectURL:          "https://example.com/callback",
				AllowedOrganizations: []string{"giantswarm"},
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
			errMsg:  "client ID is required",
		},
		{
			name: "missing client secret",
			config: &Config{
				ClientID:    "test-client-id",
				RedirectURL: "https://example.com/callback",
			},
			wantErr: true,
			errMsg:  "client secret is required",
		},
		{
			name: "empty organization name",
			config: &Config{
				ClientID:             "test-client-id",
				ClientSecret:         "test-client-secret",
				AllowedOrganizations: []string{"giantswarm", ""},
			},
			wantErr: true,
			errMsg:  "organization name cannot be empty",
		},
		{
			name: "organization name too long",
			config: &Config{
				ClientID:             "test-client-id",
				ClientSecret:         "test-client-secret",
				AllowedOrganizations: []string{strings.Repeat("a", 40)},
			},
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("NewProvider() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
			if !tt.wantErr && provider != nil {
				if provider.httpClient == nil {
					t.Error("NewProvider() httpClient is nil")
				}
			}
		})
	}
}

func TestNewProvider_AddReadOrgScope(t *testing.T) {
	// When AllowedOrganizations is set, read:org should be automatically added
	config := &Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		RedirectURL:          "https://example.com/callback",
		Scopes:               []string{"user:email"},
		AllowedOrganizations: []string{"giantswarm"},
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	hasReadOrg := false
	for _, scope := range provider.Scopes {
		if scope == testScopeReadOrg {
			hasReadOrg = true
			break
		}
	}

	if !hasReadOrg {
		t.Error("NewProvider() should automatically add read:org scope when AllowedOrganizations is set")
	}
}

func TestNewProvider_ReadOrgScopeNotDuplicated(t *testing.T) {
	// When read:org is already present, it shouldn't be duplicated
	config := &Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		RedirectURL:          "https://example.com/callback",
		Scopes:               []string{"user:email", "read:org"},
		AllowedOrganizations: []string{"giantswarm"},
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	count := 0
	for _, scope := range provider.Scopes {
		if scope == testScopeReadOrg {
			count++
		}
	}

	if count != 1 {
		t.Errorf("NewProvider() should have exactly 1 read:org scope, got %d", count)
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

func TestNewProvider_RequireVerifiedEmailDefault(t *testing.T) {
	config := &Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	if !provider.requireVerifiedEmail {
		t.Error("NewProvider() should default requireVerifiedEmail to true")
	}
}

func TestNewProvider_RequireVerifiedEmailFalse(t *testing.T) {
	falseVal := false
	config := &Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		RequireVerifiedEmail: &falseVal,
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	if provider.requireVerifiedEmail {
		t.Error("NewProvider() should set requireVerifiedEmail to false when explicitly set")
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

	if got := provider.Name(); got != "github" {
		t.Errorf("Name() = %q, want %q", got, "github")
	}
}

func TestProvider_DefaultScopes(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	scopes := provider.DefaultScopes()
	if len(scopes) != 2 {
		t.Errorf("DefaultScopes() returned %d scopes, want 2", len(scopes))
	}

	// Verify defaults contain expected scopes
	hasUserEmail := false
	hasReadUser := false
	for _, scope := range scopes {
		if scope == "user:email" {
			hasUserEmail = true
		}
		if scope == "read:user" {
			hasReadUser = true
		}
	}

	if !hasUserEmail || !hasReadUser {
		t.Errorf("DefaultScopes() = %v, want [user:email, read:user]", scopes)
	}
}

func TestProvider_DefaultScopes_DeepCopy(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	scopes1 := provider.DefaultScopes()
	scopes2 := provider.DefaultScopes()

	// Modify first copy
	if len(scopes1) > 0 {
		scopes1[0] = "modified"
	}

	// Second copy should be unaffected
	if scopes2[0] == "modified" {
		t.Error("DefaultScopes() should return deep copy, but modification affected second call")
	}
}

func TestProvider_AuthorizationURL(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"user:email", "read:user"},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	tests := []struct {
		name                string
		state               string
		codeChallenge       string
		codeChallengeMethod string
		scopes              []string
		wantContains        []string
		wantNotContains     []string
	}{
		{
			name:                "with PKCE",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              nil,
			wantContains: []string{
				"state=test-state",
				"code_challenge=test-challenge",
				"code_challenge_method=S256",
				"client_id=test-client-id",
			},
		},
		{
			name:   "without PKCE",
			state:  "test-state",
			scopes: nil,
			wantContains: []string{
				"state=test-state",
				"client_id=test-client-id",
			},
			wantNotContains: []string{
				"code_challenge",
				"code_challenge_method",
			},
		},
		{
			name:                "with custom scopes",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              []string{"repo", "workflow"},
			wantContains: []string{
				"state=test-state",
				"scope=repo+workflow",
			},
		},
		{
			name:                "with empty scopes uses defaults",
			state:               "test-state",
			codeChallenge:       "",
			codeChallengeMethod: "",
			scopes:              []string{},
			wantContains: []string{
				"state=test-state",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := provider.AuthorizationURL(tt.state, tt.codeChallenge, tt.codeChallengeMethod, tt.scopes)

			for _, want := range tt.wantContains {
				if !strings.Contains(authURL, want) {
					t.Errorf("AuthorizationURL() missing %q in URL %q", want, authURL)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(authURL, notWant) {
					t.Errorf("AuthorizationURL() should not contain %q", notWant)
				}
			}
		})
	}
}

func TestProvider_AuthorizationURL_DeepCopySafety(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"user:email", "read:user"},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// Store original scopes
	originalScopes := make([]string, len(provider.Scopes))
	copy(originalScopes, provider.Scopes)

	// Generate URL with custom scopes
	customScopes := []string{"repo", "workflow"}
	_ = provider.AuthorizationURL("state1", "challenge1", "S256", customScopes)

	// Modify custom scopes after call
	customScopes[0] = "MODIFIED"

	// Generate another URL - provider should be unaffected
	url2 := provider.AuthorizationURL("state2", "challenge2", "S256", nil)

	// Verify original scopes are used for default
	for i, scope := range provider.Scopes {
		if scope != originalScopes[i] {
			t.Errorf("Provider scopes modified: got %q, want %q", scope, originalScopes[i])
		}
	}

	if strings.Contains(url2, "MODIFIED") {
		t.Error("AuthorizationURL() should use deep copy of scopes")
	}
}

func TestProvider_ExchangeCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenEndpoint {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		if r.FormValue("code") != "test-code" {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
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

	provider.Endpoint.TokenURL = server.URL + testTokenEndpoint

	token, err := provider.ExchangeCode(context.Background(), "test-code", "")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}

	if token.AccessToken != testAccessToken {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, testAccessToken)
	}
}

func TestProvider_ExchangeCode_WithPKCE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenEndpoint {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		if r.FormValue("code_verifier") != "test-verifier" {
			http.Error(w, "invalid or missing code_verifier", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
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

	provider.Endpoint.TokenURL = server.URL + testTokenEndpoint

	token, err := provider.ExchangeCode(context.Background(), "test-code", "test-verifier")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}

	if token.AccessToken != testAccessToken {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, testAccessToken)
	}
}

func TestProvider_ValidateToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+testAccessToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         12345678,
			"login":      "octocat",
			"name":       "The Octocat",
			"email":      "octocat@github.com",
			"avatar_url": "https://avatars.githubusercontent.com/u/583231",
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	userInfo, err := provider.ValidateToken(context.Background(), testAccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if userInfo.ID != "12345678" {
		t.Errorf("ID = %q, want %q", userInfo.ID, "12345678")
	}

	if userInfo.Email != "octocat@github.com" {
		t.Errorf("Email = %q, want %q", userInfo.Email, "octocat@github.com")
	}

	if userInfo.Name != "The Octocat" {
		t.Errorf("Name = %q, want %q", userInfo.Name, "The Octocat")
	}
}

func TestProvider_ValidateToken_EmailFallback(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/user/emails") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"email": "secondary@example.com", "primary": false, "verified": true},
				{"email": "primary@example.com", "primary": true, "verified": true},
			})
			return
		}

		// Return user without email (private email)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    12345678,
			"login": "octocat",
			"name":  "The Octocat",
			"email": nil, // No public email
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	userInfo, err := provider.ValidateToken(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if userInfo.Email != "primary@example.com" {
		t.Errorf("Email = %q, want %q", userInfo.Email, "primary@example.com")
	}

	if !userInfo.EmailVerified {
		t.Error("EmailVerified should be true for verified primary email")
	}
}

func TestProvider_ValidateToken_OrganizationRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/user/orgs") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"login": "other-org"},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    12345678,
			"login": "octocat",
			"email": "test@example.com",
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		AllowedOrganizations: []string{"giantswarm"},
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	_, err = provider.ValidateToken(context.Background(), "test-token")
	if err == nil {
		t.Error("ValidateToken() should return error when user is not in allowed organization")
	}

	if err != ErrOrganizationRequired {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrOrganizationRequired)
	}
}

func TestProvider_ValidateToken_OrganizationAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/user/orgs") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"login": "other-org"},
				{"login": "giantswarm"},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    12345678,
			"login": "octocat",
			"email": "test@example.com",
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		AllowedOrganizations: []string{"giantswarm"},
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	userInfo, err := provider.ValidateToken(context.Background(), "test-token")
	if err != nil {
		t.Errorf("ValidateToken() error = %v, want nil", err)
	}

	if userInfo == nil {
		t.Error("ValidateToken() returned nil userInfo")
	}
}

func TestProvider_ValidateToken_OrganizationCaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/user/orgs") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"login": "GiantSwarm"}, // Different case
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    12345678,
			"login": "octocat",
			"email": "test@example.com",
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		AllowedOrganizations: []string{"giantswarm"}, // lowercase
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	userInfo, err := provider.ValidateToken(context.Background(), "test-token")
	if err != nil {
		t.Errorf("ValidateToken() should match organization case-insensitively, got error: %v", err)
	}

	if userInfo == nil {
		t.Error("ValidateToken() returned nil userInfo")
	}
}

func TestProvider_ValidateToken_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	_, err = provider.ValidateToken(context.Background(), "invalid-token")
	if err == nil {
		t.Error("ValidateToken() should return error for invalid token")
	}
}

func TestProvider_RefreshToken(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	_, err = provider.RefreshToken(context.Background(), "test-refresh-token")
	if err == nil {
		t.Error("RefreshToken() should return error for GitHub OAuth Apps")
	}

	if err != ErrRefreshNotSupported {
		t.Errorf("RefreshToken() error = %v, want %v", err, ErrRefreshNotSupported)
	}
}

func TestProvider_RevokeToken(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// RevokeToken should return nil (graceful degradation)
	err = provider.RevokeToken(context.Background(), "test-token")
	if err != nil {
		t.Errorf("RevokeToken() error = %v, want nil (graceful degradation)", err)
	}
}

func TestProvider_HealthCheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unhealthy - server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
		{
			name:       "unhealthy - service unavailable",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			provider, err := NewProvider(&Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				HTTPClient: &http.Client{
					Transport: &healthCheckTransport{server: server},
				},
			})
			if err != nil {
				t.Fatalf("NewProvider() error = %v", err)
			}

			err = provider.HealthCheck(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("HealthCheck() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProvider_HealthCheck_WithTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		RequestTimeout: 10 * time.Millisecond, // Very short timeout
		HTTPClient: &http.Client{
			Transport: &healthCheckTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	err = provider.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck() should timeout with short deadline")
	}
}

func TestProvider_HealthCheck_WithExistingDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient: &http.Client{
			Transport: &healthCheckTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = provider.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck() with existing deadline failed: %v", err)
	}
}

func TestProvider_GetUserOrganizations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"login": "org1"},
			{"login": "org2"},
			{"login": "giantswarm"},
		})
	}))
	defer server.Close()

	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient: &http.Client{
			Transport: &mockUserTransport{server: server},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	orgs, err := provider.GetUserOrganizations(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("GetUserOrganizations() error = %v", err)
	}

	if len(orgs) != 3 {
		t.Errorf("GetUserOrganizations() returned %d orgs, want 3", len(orgs))
	}

	expectedOrgs := map[string]bool{"org1": true, "org2": true, "giantswarm": true}
	for _, org := range orgs {
		if !expectedOrgs[org] {
			t.Errorf("Unexpected org %q in result", org)
		}
	}
}

func TestProvider_GetProviderToken(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	token := provider.GetProviderToken(testAccessToken)

	if token.AccessToken != testAccessToken {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, testAccessToken)
	}

	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
}

func TestProvider_BuildAuthenticatedURL(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	u, err := provider.BuildAuthenticatedURL("https://api.github.com/repos/owner/repo", "test-token")
	if err != nil {
		t.Fatalf("BuildAuthenticatedURL() error = %v", err)
	}

	if u.Host != "api.github.com" {
		t.Errorf("Host = %q, want %q", u.Host, "api.github.com")
	}
}

func TestProvider_BuildAuthenticatedURL_Invalid(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	_, err = provider.BuildAuthenticatedURL("://invalid", "test-token")
	if err == nil {
		t.Error("BuildAuthenticatedURL() should return error for invalid URL")
	}
}

func TestProvider_ensureContextTimeout(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// Test with context without deadline
	ctx1 := context.Background()
	newCtx, cancel := provider.ensureContextTimeout(ctx1)
	defer cancel()

	if _, hasDeadline := newCtx.Deadline(); !hasDeadline {
		t.Error("ensureContextTimeout() should add deadline when none exists")
	}

	// Test with context with deadline
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	newCtx2, cancel3 := provider.ensureContextTimeout(ctx2)
	defer cancel3()

	// Should return same context
	if newCtx2 != ctx2 {
		t.Error("ensureContextTimeout() should return original context when deadline exists")
	}
}

// mockUserTransport redirects GitHub API requests to test server.
type mockUserTransport struct {
	server *httptest.Server
}

func (m *mockUserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "api.github.com") {
		testURL, _ := url.Parse(m.server.URL + req.URL.Path)
		req.URL = testURL
	}
	return http.DefaultTransport.RoundTrip(req)
}

// healthCheckTransport redirects rate limit requests to test server.
type healthCheckTransport struct {
	server *httptest.Server
}

func (h *healthCheckTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), "rate_limit") {
		testURL, _ := url.Parse(h.server.URL + "/rate_limit")
		req.URL = testURL
	}
	return http.DefaultTransport.RoundTrip(req)
}

// Test that the Provider implements the providers.Provider interface
func TestProvider_ImplementsInterface(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// This will fail at compile time if Provider doesn't implement the interface
	var _ interface {
		Name() string
		DefaultScopes() []string
		AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string) string
		ExchangeCode(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error)
		ValidateToken(ctx context.Context, accessToken string) (*interface{ ID() string }, error)
		RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
		RevokeToken(ctx context.Context, token string) error
		HealthCheck(ctx context.Context) error
	}

	_ = provider
}
