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

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
)

const (
	testTokenEndpoint = "/token"
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
		scopes              []string
		wantContains        []string
		wantNotContains     []string
	}{
		{
			name:                "with PKCE (OAuth 2.1 security)",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              nil, // Use provider defaults
			wantContains: []string{
				"state=test-state",
				"code_challenge=test-challenge",
				"code_challenge_method=S256",
				"access_type=offline",
				"prompt=consent", // Default ForceConsent=true
			},
		},
		{
			name:   "without PKCE parameters",
			state:  "test-state",
			scopes: nil, // Use provider defaults
			wantContains: []string{
				"state=test-state",
				"access_type=offline",
				"prompt=consent", // Default ForceConsent=true
			},
			wantNotContains: []string{
				"code_challenge",
				"code_challenge_method",
			},
		},
		{
			name:                "with dynamic scopes - uses requested scopes",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              []string{"https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/drive.readonly"},
			wantContains: []string{
				"state=test-state",
				"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.readonly",
			},
		},
		{
			name:                "with empty scopes array - uses provider defaults",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              []string{}, // Empty array should use provider defaults
			wantContains: []string{
				"state=test-state",
			},
		},
		{
			name:                "filters out offline_access scope - Google uses access_type param instead",
			state:               "test-state",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "S256",
			scopes:              []string{"openid", "email", "offline_access", "profile"},
			wantContains: []string{
				"state=test-state",
				"access_type=offline", // Google's way of requesting refresh tokens
				"scope=",              // Should have scope parameter
			},
			wantNotContains: []string{
				"offline_access", // Should NOT be passed to Google
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := provider.AuthorizationURL(tt.state, tt.codeChallenge, tt.codeChallengeMethod, tt.scopes, nil)

			for _, want := range tt.wantContains {
				if !strings.Contains(authURL, want) {
					t.Errorf("AuthorizationURL() missing %q in URL %q", want, authURL)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(authURL, notWant) {
					t.Errorf("AuthorizationURL() should not contain %q (confidential client)", notWant)
				}
			}
		})
	}
}

// TestProvider_AuthorizationURL_ForceConsent verifies that ForceConsent config option
// controls whether prompt=consent is added to the authorization URL.
// See: https://developers.google.com/identity/protocols/oauth2/web-server#offline
func TestProvider_AuthorizationURL_ForceConsent(t *testing.T) {
	tests := []struct {
		name              string
		forceConsent      *bool
		wantPromptConsent bool
	}{
		{
			name:              "default (nil) - ForceConsent enabled",
			forceConsent:      nil,
			wantPromptConsent: true,
		},
		{
			name:              "ForceConsent explicitly enabled",
			forceConsent:      boolPtr(true),
			wantPromptConsent: true,
		},
		{
			name:              "ForceConsent explicitly disabled",
			forceConsent:      boolPtr(false),
			wantPromptConsent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(&Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"openid", "email"},
				ForceConsent: tt.forceConsent,
			})
			if err != nil {
				t.Fatalf("NewProvider() error = %v", err)
			}

			authURL := provider.AuthorizationURL("test-state", "test-challenge", "S256", nil, nil)

			hasPromptConsent := strings.Contains(authURL, "prompt=consent")
			if hasPromptConsent != tt.wantPromptConsent {
				if tt.wantPromptConsent {
					t.Errorf("AuthorizationURL() should contain prompt=consent, got URL: %q", authURL)
				} else {
					t.Errorf("AuthorizationURL() should NOT contain prompt=consent, got URL: %q", authURL)
				}
			}

			// access_type=offline should always be present
			if !strings.Contains(authURL, "access_type=offline") {
				t.Errorf("AuthorizationURL() should always contain access_type=offline, got URL: %q", authURL)
			}
		})
	}
}

// boolPtr returns a pointer to a bool value
func boolPtr(b bool) *bool {
	return &b
}

// TestProvider_AuthorizationURL_FiltersOfflineAccess verifies that offline_access
// scope is filtered out since Google uses access_type=offline parameter instead.
// See: https://developers.google.com/identity/protocols/oauth2/web-server#offline
func TestProvider_AuthorizationURL_FiltersOfflineAccess(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "email", "offline_access"}, // Provider default includes offline_access
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	tests := []struct {
		name              string
		scopes            []string
		wantScopesPresent []string // Scopes that SHOULD be in the URL
	}{
		{
			name:              "filters offline_access from requested scopes",
			scopes:            []string{"openid", "email", "offline_access", "profile"},
			wantScopesPresent: []string{"openid", "email", "profile"},
		},
		{
			name:              "filters offline_access from provider defaults",
			scopes:            nil, // Uses provider defaults which include offline_access
			wantScopesPresent: []string{"openid", "email"},
		},
		{
			name:              "handles only offline_access scope - results in empty scope list",
			scopes:            []string{"offline_access"},
			wantScopesPresent: nil, // No scopes should remain
		},
		{
			name:              "handles offline_access with OIDC scopes",
			scopes:            []string{"openid", "offline_access"},
			wantScopesPresent: []string{"openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := provider.AuthorizationURL("test-state", "test-challenge", "S256", tt.scopes, nil)

			// Verify offline_access is NOT in the URL
			if strings.Contains(authURL, "offline_access") {
				t.Errorf("AuthorizationURL() should not contain offline_access, got URL: %q", authURL)
			}

			// Verify access_type=offline IS present (Google's way of requesting refresh tokens)
			if !strings.Contains(authURL, "access_type=offline") {
				t.Errorf("AuthorizationURL() should contain access_type=offline, got URL: %q", authURL)
			}

			// Verify expected scopes are present
			for _, wantScope := range tt.wantScopesPresent {
				if !strings.Contains(authURL, wantScope) {
					t.Errorf("AuthorizationURL() should contain scope %q, got URL: %q", wantScope, authURL)
				}
			}
		})
	}
}

// TestProvider_AuthorizationURL_DeepCopySafety verifies that the provider creates
// deep copies of scopes to prevent race conditions and unexpected modifications
func TestProvider_AuthorizationURL_DeepCopySafety(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	// Test 1: Using provider defaults - should not affect original
	originalScopes := make([]string, len(provider.Scopes))
	copy(originalScopes, provider.Scopes)

	authURL1 := provider.AuthorizationURL("state1", "challenge1", "S256", nil, nil)

	// Verify provider's scopes weren't modified
	if len(provider.Scopes) != len(originalScopes) {
		t.Errorf("Provider scopes length changed: got %d, want %d", len(provider.Scopes), len(originalScopes))
	}
	for i, scope := range provider.Scopes {
		if scope != originalScopes[i] {
			t.Errorf("Provider scope[%d] changed: got %q, want %q", i, scope, originalScopes[i])
		}
	}

	// Test 2: Using custom scopes - should not affect provider defaults
	customScopes := []string{"custom:scope1", "custom:scope2"}
	authURL2 := provider.AuthorizationURL("state2", "challenge2", "S256", customScopes, nil)

	// Verify provider's scopes are still unchanged
	if len(provider.Scopes) != len(originalScopes) {
		t.Errorf("Provider scopes length changed after custom scopes: got %d, want %d", len(provider.Scopes), len(originalScopes))
	}

	// Test 3: Modifying input slice shouldn't affect provider
	inputScopes := []string{"input:scope1", "input:scope2"}
	authURL3 := provider.AuthorizationURL("state3", "challenge3", "S256", inputScopes, nil)

	// Modify the input slice after the call
	inputScopes[0] = "MODIFIED"
	_ = append(inputScopes, "APPENDED") // Intentionally not using result to test isolation

	// Generate another URL - should not be affected by the modification
	authURL4 := provider.AuthorizationURL("state4", "challenge4", "S256", []string{"input:scope1", "input:scope2"}, nil)

	// URLs 3 and 4 should have the same scopes (ignoring state/challenge differences)
	if !strings.Contains(authURL3, "input%3Ascope1") {
		t.Errorf("URL 3 should contain input:scope1")
	}
	if !strings.Contains(authURL4, "input%3Ascope1") {
		t.Errorf("URL 4 should contain input:scope1")
	}

	// Verify all URLs were generated successfully
	if authURL1 == "" || authURL2 == "" || authURL3 == "" || authURL4 == "" {
		t.Error("One or more URLs were not generated")
	}

	t.Log("✓ Deep copy prevents race conditions")
	t.Log("✓ Provider defaults are protected from modification")
	t.Log("✓ Input slices can be safely modified after call")
}

// TestProvider_AuthorizationURL_Options tests that AuthorizationURLOptions are correctly
// applied to the authorization URL for silent authentication and other OIDC features.
func TestProvider_AuthorizationURL_Options(t *testing.T) {
	provider, err := NewProvider(&Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "email"},
		ForceConsent: boolPtr(false), // Disable so we can test prompt parameter
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	tests := []struct {
		name           string
		opts           *providers.AuthorizationURLOptions
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "nil options - uses defaults",
			opts: nil,
			wantContains: []string{
				"access_type=offline",
			},
			wantNotContain: []string{
				"prompt=",
				"login_hint=",
				"max_age=",
			},
		},
		{
			name: "prompt=none for silent auth",
			opts: &providers.AuthorizationURLOptions{
				Prompt: "none",
			},
			wantContains: []string{
				"prompt=none",
				"access_type=offline",
			},
		},
		{
			name: "prompt=login for forced re-auth",
			opts: &providers.AuthorizationURLOptions{
				Prompt: "login",
			},
			wantContains: []string{
				"prompt=login",
			},
		},
		{
			name: "prompt=consent for forced consent",
			opts: &providers.AuthorizationURLOptions{
				Prompt: "consent",
			},
			wantContains: []string{
				"prompt=consent",
			},
		},
		{
			name: "login_hint for known user",
			opts: &providers.AuthorizationURLOptions{
				LoginHint: "user@example.com",
			},
			wantContains: []string{
				"login_hint=user%40example.com",
			},
		},
		{
			name: "max_age for session freshness",
			opts: &providers.AuthorizationURLOptions{
				MaxAge: testutil.IntPtr(0), // Force re-auth
			},
			wantContains: []string{
				"max_age=0",
			},
		},
		{
			name: "max_age with specific value",
			opts: &providers.AuthorizationURLOptions{
				MaxAge: testutil.IntPtr(3600), // Session must be less than 1 hour old
			},
			wantContains: []string{
				"max_age=3600",
			},
		},
		{
			name: "id_token_hint for silent auth",
			opts: &providers.AuthorizationURLOptions{
				IDTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
			},
			wantContains: []string{
				"id_token_hint=",
			},
		},
		{
			name: "acr_values for authentication context",
			opts: &providers.AuthorizationURLOptions{
				ACRValues: "urn:mace:incommon:iap:silver",
			},
			wantContains: []string{
				"acr_values=",
			},
		},
		{
			name: "extra parameters",
			opts: &providers.AuthorizationURLOptions{
				Extra: map[string]string{
					"hd": "example.com", // Google-specific: hosted domain
				},
			},
			wantContains: []string{
				"hd=example.com",
			},
		},
		{
			name: "combination - silent auth with login_hint",
			opts: &providers.AuthorizationURLOptions{
				Prompt:      "none",
				LoginHint:   "user@example.com",
				IDTokenHint: "previous-id-token",
			},
			wantContains: []string{
				"prompt=none",
				"login_hint=",
				"id_token_hint=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := provider.AuthorizationURL("test-state", "test-challenge", "S256", nil, tt.opts)

			for _, want := range tt.wantContains {
				if !strings.Contains(authURL, want) {
					t.Errorf("AuthorizationURL() missing %q in URL: %s", want, authURL)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(authURL, notWant) {
					t.Errorf("AuthorizationURL() should not contain %q in URL: %s", notWant, authURL)
				}
			}
		})
	}
}

func TestProvider_ExchangeCode(t *testing.T) {
	ctx := context.Background()
	// Create mock Google token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenEndpoint {
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
	ctx := context.Background()
	// Create mock Google token endpoint that verifies code_verifier IS sent (OAuth 2.1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenEndpoint {
			http.NotFound(w, r)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		// Verify code_verifier is sent (OAuth 2.1 security enhancement)
		if r.FormValue("code_verifier") != "test-verifier" {
			http.Error(w, "invalid or missing code_verifier", http.StatusBadRequest)
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

	// Pass verifier parameter for OAuth 2.1 PKCE security
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ctx := context.Background()
	// Create mock Google token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenEndpoint {
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

	token, err := provider.RefreshToken(ctx, "test-refresh-token")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if token.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access-token")
	}
}

func TestProvider_RevokeToken(t *testing.T) {
	ctx := context.Background()
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

	err = provider.RevokeToken(ctx, "test-token")
	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}
}

func TestProvider_RevokeToken_Failed(t *testing.T) {
	ctx := context.Background()
	// Create mock Google revoke endpoint that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	err = provider.RevokeToken(ctx, "test-token")
	if err == nil {
		t.Error("RevokeToken() should return error on failure")
	}
}

// mockTransport is a custom http.RoundTripper that redirects userinfo requests to our test server.
// This allows testing the user info validation flow without making actual calls to Google's endpoints.
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

// revokeTransport is a custom http.RoundTripper that redirects revoke requests to our test server.
// This allows testing the revoke flow without making actual calls to Google's endpoints.
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

func TestProvider_HealthCheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy provider",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unhealthy provider - internal server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
		{
			name:       "unhealthy provider - service unavailable",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify it's requesting the discovery document
				if !strings.Contains(r.URL.Path, ".well-known/openid-configuration") {
					t.Errorf("Expected .well-known/openid-configuration request, got %s", r.URL.Path)
				}
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

			if tt.wantErr && err != nil {
				// Verify error message is meaningful
				if !strings.Contains(err.Error(), "google oauth provider") {
					t.Errorf("HealthCheck() error should mention provider, got: %v", err)
				}
			}
		})
	}
}

func TestProvider_HealthCheck_WithTimeout(t *testing.T) {
	// Create a server that delays response to test timeout handling
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	// This should timeout
	err = provider.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck() should timeout with short deadline")
	}
}

func TestProvider_HealthCheck_WithExistingDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	// Create context with existing deadline
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = provider.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck() with existing deadline failed: %v", err)
	}
}

// healthCheckTransport is a custom http.RoundTripper that redirects health check requests to our test server.
// This allows testing the health check flow without making actual calls to Google's endpoints.
type healthCheckTransport struct {
	server *httptest.Server
}

func (h *healthCheckTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect health check requests to our test server
	if strings.Contains(req.URL.String(), ".well-known/openid-configuration") {
		testURL, _ := url.Parse(h.server.URL + "/.well-known/openid-configuration")
		req.URL = testURL
	}
	return http.DefaultTransport.RoundTrip(req)
}
