package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestHandler_ServeAuthorization_StateTooLong(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	oversized := strings.Repeat("a", oauth.MaxStateLength+1)
	target := "/authorize?client_id=any&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&response_type=code&code_challenge=c&code_challenge_method=S256&state=" + oversized

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "state > MaxStateLength must be rejected; body: %s", w.Body.String())
}

func TestHandler_ServeAuthorization_MissingParams(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_ServeAuthorization_CompleteFlow(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client first
	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Generate valid PKCE challenge
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Test authorization request
	// State must be at least 32 characters for security
	validState := testutil.GenerateRandomString(43) // Use PKCE verifier length for state
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id="+client.ClientID+
			"&redirect_uri=https://example.com/callback"+
			"&scope=openid+email"+
			"&response_type=code"+
			"&code_challenge="+challenge+
			"&code_challenge_method=S256"+
			"&state="+validState,
		nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	// Should redirect to provider
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set for redirect")
	}
}

func TestHandler_ServeAuthorization_NonceTooLong(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, _, err := handler.server.RegisterClient(
		ctx,
		"Nonce Length Test Client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	validState := testutil.GenerateRandomString(43)
	oversizedNonce := strings.Repeat("a", oauth.MaxNonceLength+1)

	query := url.Values{}
	query.Set("client_id", client.ClientID)
	query.Set("redirect_uri", "https://example.com/callback")
	query.Set("scope", "openid email")
	query.Set("response_type", "code")
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	query.Set("state", validState)
	query.Set("nonce", oversizedNonce)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := httptest.NewRecorder()

	handler.ServeAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for nonce length > %d", w.Code, http.StatusBadRequest, oauth.MaxNonceLength)
	}
}

// TestHandler_ServeAuthorization_OIDCParameterForwarding tests that OIDC parameters
// from the query string are properly extracted and forwarded to the upstream IdP.
// This enables silent re-authentication (prompt=none), user hints, session freshness
// requirements (max_age), and authentication context (acr_values).
// See: OpenID Connect Core 1.0 Section 3.1.2.1
func TestHandler_ServeAuthorization_OIDCParameterForwarding(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		queryParams     map[string]string
		wantPrompt      string
		wantLoginHint   string
		wantIDTokenHint string
		wantMaxAge      *int
		wantACRValues   string
		description     string
	}{
		{
			name:        "no OIDC params",
			queryParams: map[string]string{},
			description: "Base case: no OIDC parameters should be forwarded",
		},
		{
			name: "prompt=none for silent auth",
			queryParams: map[string]string{
				"prompt": "none",
			},
			wantPrompt:  "none",
			description: "Silent authentication: no UI should be displayed",
		},
		{
			name: "prompt=login for forced re-auth",
			queryParams: map[string]string{
				"prompt": "login",
			},
			wantPrompt:  "login",
			description: "Force re-authentication even if session exists",
		},
		{
			name: "login_hint for known user",
			queryParams: map[string]string{
				"login_hint": "user@example.com",
			},
			wantLoginHint: "user@example.com",
			description:   "Pre-fill email/username at IdP",
		},
		{
			name: "id_token_hint for session binding",
			queryParams: map[string]string{
				"id_token_hint": "eyJhbGciOiJSUzI1NiJ9.test.signature",
			},
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiJ9.test.signature",
			description:     "Previously issued ID token as session hint",
		},
		{
			name: "max_age for session freshness",
			queryParams: map[string]string{
				"max_age": "3600",
			},
			wantMaxAge:  testutil.IntPtr(3600),
			description: "Require re-auth if session is older than 1 hour",
		},
		{
			name: "max_age=0 for immediate re-auth",
			queryParams: map[string]string{
				"max_age": "0",
			},
			wantMaxAge:  testutil.IntPtr(0),
			description: "max_age=0 is equivalent to prompt=login",
		},
		{
			name: "acr_values for authentication context",
			queryParams: map[string]string{
				"acr_values": "urn:mace:incommon:iap:silver",
			},
			wantACRValues: "urn:mace:incommon:iap:silver",
			description:   "Request specific authentication level (e.g., MFA)",
		},
		{
			name: "all OIDC params combined (full silent re-auth)",
			queryParams: map[string]string{
				"prompt":        "none",
				"login_hint":    "user@example.com",
				"id_token_hint": "eyJhbGciOiJSUzI1NiJ9.test.signature",
				"max_age":       "7200",
				"acr_values":    "urn:mace:incommon:iap:silver",
			},
			wantPrompt:      "none",
			wantLoginHint:   "user@example.com",
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiJ9.test.signature",
			wantMaxAge:      testutil.IntPtr(7200),
			wantACRValues:   "urn:mace:incommon:iap:silver",
			description:     "Full silent re-authentication with all hints",
		},
		{
			name: "invalid max_age is ignored",
			queryParams: map[string]string{
				"max_age": "not-a-number",
				"prompt":  "login",
			},
			wantPrompt:  "login",
			wantMaxAge:  nil, // Invalid max_age should be ignored
			description: "Invalid max_age values are silently ignored",
		},
		{
			name: "oversized max_age length is ignored",
			queryParams: map[string]string{
				"max_age": strings.Repeat("9", oauth.MaxMaxAgeLength+1),
				"prompt":  "login",
			},
			wantPrompt:  "login",
			wantMaxAge:  nil,
			description: "Overlong max_age values are ignored",
		},
		{
			name: "max_age above allowed range is ignored",
			queryParams: map[string]string{
				"max_age": strconv.Itoa(oauth.MaxMaxAgeSeconds + 1),
				"prompt":  "login",
			},
			wantPrompt:  "login",
			wantMaxAge:  nil,
			description: "Out-of-range max_age values are ignored",
		},
		{
			name: "negative max_age is ignored",
			queryParams: map[string]string{
				"max_age": "-100",
				"prompt":  "login",
			},
			wantPrompt:  "login",
			wantMaxAge:  nil, // Negative max_age should be ignored
			description: "Negative max_age values are silently ignored",
		},
		{
			name: "prompt with newline is normalized",
			queryParams: map[string]string{
				"prompt": "login\nconsent",
			},
			wantPrompt:  "login consent",
			description: "Control characters are normalized out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			defer store.Stop()

			// Create mock provider that captures the authorization URL options
			var capturedOpts *providers.AuthorizationURLOptions
			provider := mock.NewProvider()
			provider.AuthorizationURLFunc = func(state, _, _ string, _ []string, opts *providers.AuthorizationURLOptions) string {
				capturedOpts = opts
				return "https://mock.example.com/authorize?state=" + state
			}

			config := &server.Config{
				Issuer: testIssuer,
			}

			srv, err := server.New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("server.New() error = %v", err)
			}

			handler := New(srv, nil)

			// Register a client
			client, _, err := srv.RegisterClient(
				ctx,
				"Test Client",
				"confidential",
				"",
				[]string{"https://example.com/callback"},
				[]string{"openid", "email"},
				"192.168.1.100",
				10,
			)
			if err != nil {
				t.Fatalf("RegisterClient() error = %v", err)
			}

			// Generate valid PKCE challenge
			verifier := testutil.GenerateRandomString(50)
			hash := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(hash[:])
			validState := testutil.GenerateRandomString(43)

			// Build the authorization URL with OIDC parameters
			reqURL := "/authorize?client_id=" + client.ClientID +
				"&redirect_uri=https://example.com/callback" +
				"&scope=openid+email" +
				"&response_type=code" +
				"&code_challenge=" + challenge +
				"&code_challenge_method=S256" +
				"&state=" + validState

			// Add OIDC parameters from test case
			for key, value := range tt.queryParams {
				reqURL += "&" + key + "=" + url.QueryEscape(value)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			w := httptest.NewRecorder()

			handler.ServeAuthorization(w, req)

			// Should redirect to provider
			if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
				t.Errorf("status = %d, want redirect status", w.Code)
				return
			}

			if capturedOpts == nil {
				t.Fatal("Expected authOpts to be passed to provider, got nil")
			}
			if capturedOpts.Nonce == "" {
				t.Error("Expected server-generated nonce on OIDC flow, got empty")
			}
			if tt.wantPrompt != "" && capturedOpts.Prompt != tt.wantPrompt {
				t.Errorf("prompt = %q, want %q", capturedOpts.Prompt, tt.wantPrompt)
			}
			if tt.wantLoginHint != "" && capturedOpts.LoginHint != tt.wantLoginHint {
				t.Errorf("login_hint = %q, want %q", capturedOpts.LoginHint, tt.wantLoginHint)
			}
			if tt.wantIDTokenHint != "" && capturedOpts.IDTokenHint != tt.wantIDTokenHint {
				t.Errorf("id_token_hint = %q, want %q", capturedOpts.IDTokenHint, tt.wantIDTokenHint)
			}
			if tt.wantMaxAge != nil {
				if capturedOpts.MaxAge == nil {
					t.Error("max_age = nil, want non-nil")
				} else if *capturedOpts.MaxAge != *tt.wantMaxAge {
					t.Errorf("max_age = %d, want %d", *capturedOpts.MaxAge, *tt.wantMaxAge)
				}
			}
			if tt.wantACRValues != "" && capturedOpts.ACRValues != tt.wantACRValues {
				t.Errorf("acr_values = %q, want %q", capturedOpts.ACRValues, tt.wantACRValues)
			}
		})
	}
}

// TestParseOIDCOptions_Validation tests that parseOIDCOptions properly validates
// OIDC parameters for length limits and allowed values (security hardening).
func TestParseOIDCOptions_Validation(t *testing.T) {
	tests := []struct {
		name            string
		queryParams     map[string]string
		wantNil         bool
		wantPrompt      string
		wantLoginHint   string
		wantIDTokenHint string
		wantMaxAge      *int
		wantACRValues   string
		description     string
	}{
		{
			name:        "valid prompt=none",
			queryParams: map[string]string{"prompt": "none"},
			wantPrompt:  "none",
			description: "Valid prompt value should be accepted",
		},
		{
			name:        "valid prompt=login",
			queryParams: map[string]string{"prompt": "login"},
			wantPrompt:  "login",
			description: "Valid prompt value should be accepted",
		},
		{
			name:        "valid prompt=consent",
			queryParams: map[string]string{"prompt": "consent"},
			wantPrompt:  "consent",
			description: "Valid prompt value should be accepted",
		},
		{
			name:        "valid prompt=select_account",
			queryParams: map[string]string{"prompt": "select_account"},
			wantPrompt:  "select_account",
			description: "Valid prompt value should be accepted",
		},
		{
			name:        "valid combined prompt values",
			queryParams: map[string]string{"prompt": "login consent"},
			wantPrompt:  "login consent",
			description: "Multiple valid prompt values should be accepted",
		},
		{
			name:        "invalid prompt value rejected",
			queryParams: map[string]string{"prompt": "invalid_value"},
			wantNil:     true,
			description: "Unknown prompt value should be rejected",
		},
		{
			name:        "prompt with injection attempt rejected",
			queryParams: map[string]string{"prompt": "none&other_param=injected"},
			wantNil:     true,
			description: "Prompt containing & (injection attempt) should be rejected",
		},
		{
			name:        "prompt with newline normalized",
			queryParams: map[string]string{"prompt": "login\nconsent"},
			wantPrompt:  "login consent",
			description: "Prompt control characters are normalized out",
		},
		{
			name:        "prompt exceeds max length",
			queryParams: map[string]string{"prompt": string(make([]byte, oauth.MaxPromptLength+1))},
			wantNil:     true,
			description: "Oversized prompt should be rejected",
		},
		{
			name:          "login_hint within limit",
			queryParams:   map[string]string{"login_hint": "user@example.com"},
			wantLoginHint: "user@example.com",
			description:   "Valid login_hint should be accepted",
		},
		{
			name:        "login_hint exceeds max length",
			queryParams: map[string]string{"login_hint": string(make([]byte, oauth.MaxLoginHintLength+1))},
			wantNil:     true,
			description: "Oversized login_hint should be rejected",
		},
		{
			name:          "login_hint at max length",
			queryParams:   map[string]string{"login_hint": string(make([]byte, oauth.MaxLoginHintLength))},
			wantLoginHint: string(make([]byte, oauth.MaxLoginHintLength)),
			description:   "login_hint at exactly max length should be accepted",
		},
		{
			name:            "id_token_hint within limit",
			queryParams:     map[string]string{"id_token_hint": "eyJhbGciOiJSUzI1NiJ9.test.signature"},
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiJ9.test.signature",
			description:     "Valid id_token_hint should be accepted",
		},
		{
			name:        "id_token_hint exceeds max length (64KB)",
			queryParams: map[string]string{"id_token_hint": string(make([]byte, oauth.MaxIDTokenHintLength+1))},
			wantNil:     true,
			description: "Oversized id_token_hint should be rejected",
		},
		{
			name:          "acr_values within limit",
			queryParams:   map[string]string{"acr_values": "urn:mace:incommon:iap:silver"},
			wantACRValues: "urn:mace:incommon:iap:silver",
			description:   "Valid acr_values should be accepted",
		},
		{
			name:        "acr_values exceeds max length",
			queryParams: map[string]string{"acr_values": string(make([]byte, oauth.MaxACRValuesLength+1))},
			wantNil:     true,
			description: "Oversized acr_values should be rejected",
		},
		{
			name:        "max_age within range",
			queryParams: map[string]string{"max_age": "3600"},
			wantMaxAge:  testutil.IntPtr(3600),
			description: "Valid max_age should be accepted",
		},
		{
			name:        "max_age exceeds length limit",
			queryParams: map[string]string{"max_age": strings.Repeat("9", oauth.MaxMaxAgeLength+1)},
			wantNil:     true,
			description: "Overlong max_age should be ignored",
		},
		{
			name:        "max_age exceeds range",
			queryParams: map[string]string{"max_age": strconv.Itoa(oauth.MaxMaxAgeSeconds + 1)},
			wantNil:     true,
			description: "Out-of-range max_age should be ignored",
		},
		{
			name:          "mixed valid and invalid - invalid prompt rejects all",
			queryParams:   map[string]string{"prompt": "invalid", "login_hint": "user@example.com"},
			wantLoginHint: "user@example.com",
			wantNil:       false, // login_hint is still valid
			description:   "Invalid prompt doesn't reject valid login_hint",
		},
		{
			name: "all parameters valid",
			queryParams: map[string]string{
				"prompt":        "none",
				"login_hint":    "user@example.com",
				"id_token_hint": "eyJhbGciOiJSUzI1NiJ9.test",
				"acr_values":    "urn:mace:incommon:iap:silver",
			},
			wantPrompt:      "none",
			wantLoginHint:   "user@example.com",
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiJ9.test",
			wantACRValues:   "urn:mace:incommon:iap:silver",
			description:     "All valid parameters should be accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query values
			query := url.Values{}
			for k, v := range tt.queryParams {
				query.Set(k, v)
			}

			opts, err := parseOIDCOptions(query)
			if err != nil {
				t.Fatalf("parseOIDCOptions returned error: %v", err)
			}

			if tt.wantNil {
				if opts != nil {
					t.Errorf("Expected nil options, got %+v", opts)
				}
				return
			}

			// Check specific expected values
			if tt.wantPrompt != "" {
				if opts == nil {
					t.Fatal("Expected non-nil options for prompt check")
				}
				if opts.Prompt != tt.wantPrompt {
					t.Errorf("prompt = %q, want %q", opts.Prompt, tt.wantPrompt)
				}
			}
			if tt.wantLoginHint != "" {
				if opts == nil {
					t.Fatal("Expected non-nil options for login_hint check")
				}
				if opts.LoginHint != tt.wantLoginHint {
					t.Errorf("login_hint = %q, want %q", opts.LoginHint, tt.wantLoginHint)
				}
			}
			if tt.wantIDTokenHint != "" {
				if opts == nil {
					t.Fatal("Expected non-nil options for id_token_hint check")
				}
				if opts.IDTokenHint != tt.wantIDTokenHint {
					t.Errorf("id_token_hint = %q, want %q", opts.IDTokenHint, tt.wantIDTokenHint)
				}
			}
			if tt.wantACRValues != "" {
				if opts == nil {
					t.Fatal("Expected non-nil options for acr_values check")
				}
				if opts.ACRValues != tt.wantACRValues {
					t.Errorf("acr_values = %q, want %q", opts.ACRValues, tt.wantACRValues)
				}
			}
			if tt.wantMaxAge != nil {
				if opts == nil {
					t.Fatal("Expected non-nil options for max_age check")
				}
				if opts.MaxAge == nil {
					t.Fatal("Expected non-nil max_age value")
				}
				if *opts.MaxAge != *tt.wantMaxAge {
					t.Errorf("max_age = %d, want %d", *opts.MaxAge, *tt.wantMaxAge)
				}
			}

			t.Logf("✓ %s", tt.description)
		})
	}
}

// TestValidatePrompt tests the validatePrompt helper function directly.
func TestValidatePrompt(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		{"", "", "empty string is valid"},
		{"none", "none", "valid single value: none"},
		{"login", "login", "valid single value: login"},
		{"consent", "consent", "valid single value: consent"},
		{"select_account", "select_account", "valid single value: select_account"},
		{"login consent", "login consent", "valid combined: login consent"},
		{"none login consent select_account", "none login consent select_account", "all valid values - semantic validation is IdP's responsibility"},
		{"invalid", "", "invalid value rejected"},
		{"none invalid", "", "mixed valid/invalid rejected"},
		{"NONE", "", "case-sensitive: uppercase rejected"},
		{"None", "", "case-sensitive: mixed case rejected"},
		{"login  consent", "login consent", "extra whitespace normalized"},
		{"login\tconsent", "login consent", "tab normalized to single space"},
		{"login\nconsent", "login consent", "newline normalized to single space"},
		{string(make([]byte, oauth.MaxPromptLength)), "", "at max length with invalid content"},
		{string(make([]byte, oauth.MaxPromptLength+1)), "", "exceeds max length"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := validatePrompt(tt.input)
			if result != tt.expected {
				t.Errorf("validatePrompt(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHandler_ServeCallback(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create authorization state
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// State must be at least 32 characters for security
	clientState := testutil.GenerateRandomString(43)
	authURL, err := handler.server.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		challenge,
		"S256",
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow(ctx, ) error = %v", err)
	}

	// Extract provider state from auth URL
	if authURL == "" {
		t.Fatal("authURL is empty")
	}

	// Get auth state to find provider state
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	// Test callback with valid state
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should redirect to client with authorization code
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set")
	}

	// Verify location contains code and state
	if !strings.Contains(location, "code=") {
		t.Error("Location should contain authorization code")
	}
	if !strings.Contains(location, "state="+clientState) {
		t.Error("Location should contain original client state")
	}
	// RFC 9207: Location MUST carry the URL-encoded `iss` parameter so the client
	// can confirm the response came from the expected authorization server.
	if !strings.Contains(location, "iss="+url.QueryEscape(testIssuer)) {
		t.Errorf("Location should contain URL-encoded iss=%s; got %q", testIssuer, location)
	}
}

func TestHandler_ServeCallback_InvalidState(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Use a state with valid length but not in storage (will fail at lookup)
	validLengthButInvalidState := testutil.GenerateRandomString(43)
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+validLengthButInvalidState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Handler returns 500 for invalid state (internal error)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestHandler_ServeCallback_MissingParams(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "missing state",
			url:  "/oauth/callback?code=test-code",
		},
		{
			name: "missing code",
			url:  "/oauth/callback?state=" + testutil.GenerateRandomString(43),
		},
		{
			name: "missing all params",
			url:  "/oauth/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()

			handler.ServeCallback(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHandler_ServeAuthorization_StateLength(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a test client
	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name           string
		state          string
		wantStatus     int
		wantErrorParam string // empty when the request is expected to succeed
	}{
		{
			name:           "state too short (1 char)",
			state:          "x",
			wantStatus:     http.StatusFound,
			wantErrorParam: constants.ErrorCodeInvalidRequest,
		},
		{
			name:           "state too short (10 chars)",
			state:          "0123456789",
			wantStatus:     http.StatusFound,
			wantErrorParam: constants.ErrorCodeInvalidRequest,
		},
		{
			name:           "state too short (23 chars, just under minimum)",
			state:          "01234567890123456789012",
			wantStatus:     http.StatusFound,
			wantErrorParam: constants.ErrorCodeInvalidRequest,
		},
		{
			name:       "state exactly minimum length (24 chars)",
			state:      "012345678901234567890123",
			wantStatus: http.StatusFound,
		},
		{
			name:       "state above minimum length (64 chars)",
			state:      "0123456789012345678901234567890123456789012345678901234567890123",
			wantStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=https://example.com/callback&response_type=code&scope=openid&state=%s&code_challenge=test-challenge&code_challenge_method=S256",
				client.ClientID, tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeAuthorization(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if tt.wantErrorParam != "" {
				assertAuthorizationErrorRedirect(t, w, "https://example.com/callback", tt.wantErrorParam, "state parameter", tt.state)
			}
		})
	}
}

func TestHandler_ServeCallback_StateLength(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name       string
		state      string
		wantStatus int
	}{
		{
			name:       "state too short (1 char)",
			state:      "x",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state too short (10 chars)",
			state:      "0123456789",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state too short (23 chars)",
			state:      "01234567890123456789012",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "state exactly minimum length (24 chars) - will fail with invalid state since not in storage",
			state:      "012345678901234567890123",
			wantStatus: http.StatusInternalServerError, // Will fail at state lookup, but passed length validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/oauth/callback?state=%s&code=test-code", tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeCallback(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_ServeAuthorization_ShortStateWithAllowNoState(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandlerWithAllowNoState(t)
	defer store.Stop()

	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name       string
		state      string
		wantStatus int
	}{
		{
			name:       "short state (1 char) accepted with AllowNoStateParameter=true",
			state:      "x",
			wantStatus: http.StatusFound,
		},
		{
			name:       "short state (10 chars) accepted with AllowNoStateParameter=true",
			state:      "0123456789",
			wantStatus: http.StatusFound,
		},
		{
			name:       "empty state accepted with AllowNoStateParameter=true",
			state:      "",
			wantStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=https://example.com/callback&response_type=code&scope=openid&state=%s&code_challenge=test-challenge&code_challenge_method=S256",
				client.ClientID, tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeAuthorization(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_ServeAuthorization_NoResponseType_Rejected(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validState := testutil.GenerateRandomString(43)

	tests := []struct {
		name         string
		responseType string
	}{
		{name: "response_type missing", responseType: ""},
		{name: "response_type=token (implicit flow rejected)", responseType: "token"},
		{name: "response_type=id_token (OIDC implicit rejected)", responseType: "id_token"},
		{name: "response_type=code id_token (hybrid rejected)", responseType: "code id_token"},
		{name: "response_type=unknown", responseType: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := "/authorize?client_id=" + client.ClientID +
				"&redirect_uri=https://example.com/callback" +
				"&scope=openid" +
				"&state=" + validState +
				"&code_challenge=test-challenge" +
				"&code_challenge_method=S256"
			if tt.responseType != "" {
				reqURL += "&response_type=" + url.QueryEscape(tt.responseType)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			w := httptest.NewRecorder()
			handler.ServeAuthorization(w, req)

			assertAuthorizationErrorRedirect(t, w, "https://example.com/callback", constants.ErrorCodeUnsupportedResponseType, "response_type must be one of [code]", validState)
		})
	}
}

func TestHandler_ServeAuthorization_InvalidRequest_RedirectsToRedirectURI(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, _, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name      string
		state     string
		wantState string // empty when the client did not send a state parameter
	}{
		{
			name:      "state missing",
			state:     "",
			wantState: "",
		},
		{
			name:      "state too short",
			state:     "short",
			wantState: "short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := "/authorize?client_id=" + client.ClientID +
				"&redirect_uri=https://example.com/callback" +
				"&response_type=code" +
				"&scope=openid" +
				"&code_challenge=test-challenge" +
				"&code_challenge_method=S256"
			if tt.state != "" {
				reqURL += "&state=" + tt.state
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			w := httptest.NewRecorder()
			handler.ServeAuthorization(w, req)

			assertAuthorizationErrorRedirect(t, w, "https://example.com/callback", constants.ErrorCodeInvalidRequest, "state parameter", tt.wantState)
		})
	}

	t.Run("missing redirect_uri falls back to JSON 400", func(t *testing.T) {
		reqURL := "/authorize?client_id=" + client.ClientID +
			"&response_type=code" +
			"&scope=openid" +
			"&code_challenge=test-challenge" +
			"&code_challenge_method=S256"

		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		w := httptest.NewRecorder()
		handler.ServeAuthorization(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d (no parseable redirect_uri must JSON-error)", w.Code, http.StatusBadRequest)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("response body is not JSON: %v", err)
		}
		if body["error"] != constants.ErrorCodeInvalidRequest {
			t.Errorf("error = %q, want %q", body["error"], constants.ErrorCodeInvalidRequest)
		}
	})

	t.Run("non-http redirect_uri falls back to JSON 400", func(t *testing.T) {
		reqURL := "/authorize?client_id=" + client.ClientID +
			"&redirect_uri=" + url.QueryEscape("javascript:alert(1)") +
			"&response_type=code" +
			"&scope=openid" +
			"&code_challenge=test-challenge" +
			"&code_challenge_method=S256"

		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		w := httptest.NewRecorder()
		handler.ServeAuthorization(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d (non-http redirect_uri must JSON-error)", w.Code, http.StatusBadRequest)
		}
	})

	// Scheme-valid http(s) URL not registered for the client: must JSON-error,
	// not redirect — otherwise /authorize error branches become an open-redirect
	// gadget under RFC 6749 §4.1.2.1 + §3.1.2.4.
	t.Run("scheme-valid but unregistered redirect_uri must JSON-error", func(t *testing.T) {
		reqURL := "/authorize?client_id=" + client.ClientID +
			"&redirect_uri=" + url.QueryEscape("https://attacker.example/landing") +
			"&response_type=xxx" + // would otherwise hit the response_type branch
			"&scope=openid" +
			"&state=" + testutil.GenerateRandomString(43) +
			"&code_challenge=test-challenge" +
			"&code_challenge_method=S256"

		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		w := httptest.NewRecorder()
		handler.ServeAuthorization(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("Location header set to %q; unregistered redirect_uri must not redirect", loc)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("response body is not JSON: %v", err)
		}
		if body["error"] != constants.ErrorCodeInvalidRequest {
			t.Errorf("error = %q, want %q", body["error"], constants.ErrorCodeInvalidRequest)
		}
	})
}

// Native-app custom-scheme redirect URIs (RFC 8252 §7.1) cannot carry an HTTP
// 302 redirect; respondAuthorizationError must fall back to JSON 400 for
// those clients rather than attempt a Location redirect.
func TestHandler_ServeAuthorization_CustomSchemeRedirectURI_FallsBackToJSON(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config.AllowedCustomSchemes = []string{"^myapp$"}

	client, _, err := handler.server.RegisterClient(
		ctx,
		"Native App",
		"public",
		"",
		[]string{"myapp://callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validState := testutil.GenerateRandomString(43)
	reqURL := "/authorize?client_id=" + client.ClientID +
		"&redirect_uri=" + url.QueryEscape("myapp://callback") +
		"&response_type=token" +
		"&scope=openid" +
		"&state=" + validState +
		"&code_challenge=test-challenge" +
		"&code_challenge_method=S256"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (custom-scheme redirect_uri must JSON-error)", w.Code, http.StatusBadRequest)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location header set to %q; custom-scheme redirect must not 302", loc)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if body["error"] != constants.ErrorCodeUnsupportedResponseType {
		t.Errorf("error = %q, want %q", body["error"], constants.ErrorCodeUnsupportedResponseType)
	}
}

func TestHandler_ServeCallback_ShortProviderStateAlwaysRejected(t *testing.T) {
	handler, store := setupTestHandlerWithAllowNoState(t)
	defer store.Stop()

	tests := []struct {
		name  string
		state string
	}{
		{
			name:  "short provider state (1 char) rejected even with AllowNoStateParameter=true",
			state: "x",
		},
		{
			name:  "short provider state (10 chars) rejected even with AllowNoStateParameter=true",
			state: "0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/oauth/callback?state=%s&code=test-code", tt.state)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.ServeCallback(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("short provider state should be rejected at validation layer, got status %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// TestIsCustomURLScheme tests the isCustomURLScheme helper function
func TestIsCustomURLScheme(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		// HTTP schemes - should NOT trigger interstitial
		{
			name:     "http scheme",
			uri:      "http://example.com/callback",
			expected: false,
		},
		{
			name:     "https scheme",
			uri:      "https://example.com/callback",
			expected: false,
		},
		{
			name:     "HTTP uppercase",
			uri:      "HTTP://example.com/callback",
			expected: false,
		},
		{
			name:     "HTTPS uppercase",
			uri:      "HTTPS://example.com/callback",
			expected: false,
		},
		{
			name:     "http localhost",
			uri:      "http://localhost:8080/callback",
			expected: false,
		},
		{
			name:     "http loopback",
			uri:      "http://127.0.0.1:8080/callback",
			expected: false,
		},

		// Custom URL schemes - SHOULD trigger interstitial
		{
			name:     "cursor scheme",
			uri:      "cursor://oauth/callback",
			expected: true,
		},
		{
			name:     "vscode scheme",
			uri:      "vscode://example.extension/callback",
			expected: true,
		},
		{
			name:     "slack scheme",
			uri:      "slack://oauth/callback",
			expected: true,
		},
		{
			name:     "notion scheme",
			uri:      "notion://oauth/callback",
			expected: true,
		},
		{
			name:     "obsidian scheme",
			uri:      "obsidian://plugin/callback",
			expected: true,
		},
		{
			name:     "custom-app scheme",
			uri:      "myapp://auth/done",
			expected: true,
		},
		{
			name:     "com.example.app scheme (reverse domain)",
			uri:      "com.example.app://callback",
			expected: true,
		},
		{
			name:     "custom scheme with query params",
			uri:      "cursor://callback?code=abc&state=xyz",
			expected: true,
		},

		// Edge cases
		{
			name:     "empty string",
			uri:      "",
			expected: false,
		},
		{
			name:     "no scheme",
			uri:      "example.com/callback",
			expected: false,
		},
		{
			name:     "relative path",
			uri:      "/callback",
			expected: false,
		},
		{
			name:     "malformed URL",
			uri:      "://invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCustomURLScheme(tt.uri)
			if result != tt.expected {
				t.Errorf("isCustomURLScheme(%q) = %v, want %v", tt.uri, result, tt.expected)
			}
		})
	}
}

// TestGetAppNameFromScheme tests the getAppNameFromScheme helper function
func TestGetAppNameFromScheme(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		// Known app schemes
		{
			name:     "cursor",
			uri:      "cursor://oauth/callback",
			expected: "Cursor",
		},
		{
			name:     "vscode",
			uri:      "vscode://extension/callback",
			expected: "Visual Studio Code",
		},
		{
			name:     "code",
			uri:      "code://extension/callback",
			expected: "Visual Studio Code",
		},
		{
			name:     "slack",
			uri:      "slack://callback",
			expected: "Slack",
		},
		{
			name:     "notion",
			uri:      "notion://callback",
			expected: "Notion",
		},
		{
			name:     "obsidian",
			uri:      "obsidian://plugin",
			expected: "Obsidian",
		},
		{
			name:     "figma",
			uri:      "figma://callback",
			expected: "Figma",
		},
		{
			name:     "linear",
			uri:      "linear://callback",
			expected: "Linear",
		},
		{
			name:     "raycast",
			uri:      "raycast://callback",
			expected: "Raycast",
		},
		{
			name:     "warp",
			uri:      "warp://callback",
			expected: "Warp",
		},
		{
			name:     "zed",
			uri:      "zed://callback",
			expected: "Zed",
		},
		{
			name:     "windsurf",
			uri:      "windsurf://callback",
			expected: "Windsurf",
		},

		// Unknown schemes - should capitalize first letter
		{
			name:     "unknown scheme",
			uri:      "myapp://callback",
			expected: "Myapp",
		},
		{
			name:     "unknown scheme with dashes",
			uri:      "custom-app://callback",
			expected: "Custom-app",
		},

		// HTTP schemes - capitalizes like unknown schemes (caller should check isCustomURLScheme first)
		{
			name:     "http scheme",
			uri:      "http://example.com",
			expected: "Http",
		},
		{
			name:     "https scheme",
			uri:      "https://example.com",
			expected: "Https",
		},

		// Edge cases
		{
			name:     "empty string",
			uri:      "",
			expected: "",
		},
		{
			name:     "malformed URL",
			uri:      "://invalid",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAppNameFromScheme(tt.uri)
			if result != tt.expected {
				t.Errorf("getAppNameFromScheme(%q) = %q, want %q", tt.uri, result, tt.expected)
			}
		})
	}
}

// TestHandler_ServeCallback_CustomURLScheme tests that custom URL schemes
// receive an interstitial page instead of a direct redirect
func TestHandler_ServeCallback_CustomURLScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with custom URL scheme redirect
	client, _, err := handler.server.RegisterClient(
		ctx,
		"Cursor Test Client",
		"public",
		"none", // Public client (no secret)
		[]string{"cursor://oauth/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create authorization state
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// State must be at least 32 characters for security
	clientState := testutil.GenerateRandomString(43)
	_, err = handler.server.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "cursor://oauth/callback"),
		"openid email",
		"", // resource parameter (optional)
		challenge,
		"S256",
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get auth state to find provider state
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	// Test callback with valid state
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should return HTML interstitial, NOT a redirect
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for custom URL scheme", w.Code, http.StatusOK)
	}

	// Check content type is HTML
	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	// Verify HTML content contains expected elements
	body := w.Body.String()

	// Should contain success message
	if !strings.Contains(body, "Authorization Successful") {
		t.Error("Response should contain 'Authorization Successful' message")
	}

	// Should contain app name
	if !strings.Contains(body, "Cursor") {
		t.Error("Response should contain app name 'Cursor'")
	}

	// Should contain the redirect URL with authorization code
	if !strings.Contains(body, "cursor://oauth/callback") {
		t.Error("Response should contain the redirect URL")
	}
	if !strings.Contains(body, "code=") {
		t.Error("Response should contain authorization code")
	}
	if !strings.Contains(body, "state="+clientState) {
		t.Error("Response should contain original client state")
	}
	// RFC 9207: the embedded redirect URL in the interstitial must include `iss`
	// so the client app sees the same authorization-response parameters it would
	// have received via a direct 302.
	if !strings.Contains(body, "iss="+url.QueryEscape(testIssuer)) {
		t.Errorf("Interstitial should contain URL-encoded iss=%s in the embedded redirect", testIssuer)
	}

	// Should contain manual button
	if !strings.Contains(body, "Open Cursor") {
		t.Error("Response should contain manual 'Open Cursor' button")
	}

	// Should contain close hint
	if !strings.Contains(body, "close this window") {
		t.Error("Response should contain 'close this window' hint")
	}

	// Should NOT have Location header (no redirect)
	if location := w.Header().Get("Location"); location != "" {
		t.Errorf("Location header should be empty for interstitial page, got %q", location)
	}
}

// TestHandler_ServeCallback_HTTPScheme tests that HTTP/HTTPS schemes
// still use direct redirects (not interstitial)
func TestHandler_ServeCallback_HTTPScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with HTTPS redirect
	client, _, err := handler.server.RegisterClient(
		ctx,
		"Web App Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create authorization state
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	clientState := testutil.GenerateRandomString(43)
	_, err = handler.server.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		challenge,
		"S256",
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	// Test callback
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should redirect, NOT return HTML interstitial
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want redirect status for HTTPS scheme", w.Code)
	}

	// Should have Location header
	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set for HTTPS redirect")
	}

	// Verify redirect URL
	if !strings.HasPrefix(location, "https://example.com/callback") {
		t.Errorf("Location = %q, want to start with https://example.com/callback", location)
	}
	if !strings.Contains(location, "code=") {
		t.Error("Location should contain authorization code")
	}
	if !strings.Contains(location, "state="+clientState) {
		t.Error("Location should contain original client state")
	}
}

// TestHandler_ServeCallback_VSCodeScheme tests VS Code custom scheme handling
func TestHandler_ServeCallback_VSCodeScheme(t *testing.T) {
	ctx := context.Background()
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client with VS Code scheme
	client, _, err := handler.server.RegisterClient(
		ctx,
		"VS Code Extension",
		"public",
		"none",
		[]string{"vscode://example.extension/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err = handler.server.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "vscode://example.extension/callback"),
		"openid",
		"",
		challenge,
		"S256",
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	// Should return interstitial
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for VS Code scheme", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Visual Studio Code") {
		t.Error("Response should contain 'Visual Studio Code' app name")
	}
	if !strings.Contains(body, "vscode://") {
		t.Error("Response should contain vscode:// redirect URL")
	}
}

// TestHandler_ServeSuccessInterstitial tests the interstitial page rendering
func TestHandler_ServeSuccessInterstitial(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	tests := []struct {
		name           string
		redirectURL    string
		wantAppName    string
		wantURLPattern string // Pattern to look for (scheme + path, not full URL with query string)
	}{
		{
			name:           "cursor scheme",
			redirectURL:    "cursor://callback?code=abc123&state=xyz789",
			wantAppName:    "Cursor",
			wantURLPattern: "cursor://callback", // URL base without query params (& gets HTML-escaped)
		},
		{
			name:           "vscode scheme",
			redirectURL:    "vscode://extension/callback?code=abc",
			wantAppName:    "Visual Studio Code",
			wantURLPattern: "vscode://extension/callback",
		},
		{
			name:           "unknown scheme",
			redirectURL:    "myapp://auth/done?code=abc",
			wantAppName:    "Myapp",
			wantURLPattern: "myapp://auth/done",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
			handler.serveSuccessInterstitial(w, r, tt.redirectURL)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
			}

			contentType := w.Header().Get("Content-Type")
			if !strings.HasPrefix(contentType, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", contentType)
			}

			body := w.Body.String()

			// Check for success message
			if !strings.Contains(body, "Authorization Successful") {
				t.Error("Missing 'Authorization Successful' message")
			}

			// Check for app name
			if !strings.Contains(body, tt.wantAppName) {
				t.Errorf("Missing app name %q in response", tt.wantAppName)
			}

			// Check for redirect URL pattern (note: & in URLs gets HTML-escaped to &amp;)
			if !strings.Contains(body, tt.wantURLPattern) {
				t.Errorf("Missing redirect URL pattern %q in response", tt.wantURLPattern)
			}

			// Check for security headers
			if w.Header().Get("X-Content-Type-Options") == "" {
				t.Error("Missing X-Content-Type-Options security header")
			}

			// Check CSP includes script hash (not 'none' for scripts)
			csp := w.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Error("Missing Content-Security-Policy header")
			}
			if !strings.Contains(csp, "script-src") {
				t.Error("CSP should contain script-src directive for interstitial page")
			}
			if !strings.Contains(csp, "sha256-") {
				t.Error("CSP should contain SHA-256 hash for inline script")
			}
		})
	}
}

// TestHandler_ServeSuccessInterstitial_Branding tests interstitial page with branding configuration
func TestHandler_ServeSuccessInterstitial_Branding(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	// Configure with branding
	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				LogoURL:            "https://cdn.example.com/logo.svg",
				LogoAlt:            "Example Corp Logo",
				Title:              "Connected to Example Corp",
				Message:            "Welcome! You are now authenticated.",
				ButtonText:         "Return to App",
				PrimaryColor:       "#4F46E5",
				BackgroundGradient: "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)",
				CustomCSS:          ".container { max-width: 600px; }",
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom branding elements
	if !strings.Contains(body, "https://cdn.example.com/logo.svg") {
		t.Error("Response should contain custom logo URL")
	}
	if !strings.Contains(body, "Example Corp Logo") {
		t.Error("Response should contain custom logo alt text")
	}
	if !strings.Contains(body, "Connected to Example Corp") {
		t.Error("Response should contain custom title")
	}
	if !strings.Contains(body, "Welcome! You are now authenticated.") {
		t.Error("Response should contain custom message")
	}
	if !strings.Contains(body, "Return to App") {
		t.Error("Response should contain custom button text")
	}
	if !strings.Contains(body, "#4F46E5") {
		t.Error("Response should contain custom primary color")
	}
	if !strings.Contains(body, "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)") {
		t.Error("Response should contain custom background gradient")
	}
	if !strings.Contains(body, ".container { max-width: 600px; }") {
		t.Error("Response should contain custom CSS")
	}

	// Should NOT contain default success icon (since logo is set)
	if strings.Contains(body, `<div class="success-icon">`) {
		t.Error("Response should NOT contain default success icon when logo is configured")
	}

	// Security: Logo should have crossorigin="anonymous" for CORS isolation
	if !strings.Contains(body, `crossorigin="anonymous"`) {
		t.Error("Logo img should have crossorigin=\"anonymous\" for security isolation")
	}
}

// TestHandler_ServeSuccessInterstitial_CustomTemplate tests interstitial with custom template
func TestHandler_ServeSuccessInterstitial_CustomTemplate(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	customTemplate := `<!DOCTYPE html>
<html>
<head><title>Custom Auth Page</title></head>
<body>
<h1>Custom Success - {{.AppName}}</h1>
<a href="{{.RedirectURL}}">Continue</a>
</body>
</html>`

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			CustomTemplate: customTemplate,
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom template content
	if !strings.Contains(body, "Custom Auth Page") {
		t.Error("Response should contain custom template title")
	}
	if !strings.Contains(body, "Custom Success - Cursor") {
		t.Error("Response should contain custom heading with app name")
	}
	if !strings.Contains(body, "cursor://oauth/callback") {
		t.Error("Response should contain redirect URL")
	}

	// Should NOT contain default template content
	if strings.Contains(body, "Authorization Successful") {
		t.Error("Response should NOT contain default title when custom template is used")
	}
}

// TestHandler_ServeSuccessInterstitial_CustomHandler tests interstitial with custom handler
func TestHandler_ServeSuccessInterstitial_CustomHandler(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	var capturedRedirectURL, capturedAppName string

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			CustomHandler: func(w http.ResponseWriter, r *http.Request) {
				// Extract values from context using helper functions
				capturedRedirectURL = InterstitialRedirectURL(r.Context())
				capturedAppName = InterstitialAppName(r.Context())

				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Custom Handler Response</body></html>"))
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	handler.serveSuccessInterstitial(w, r, "vscode://extension/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom handler response
	if !strings.Contains(body, "Custom Handler Response") {
		t.Error("Response should contain custom handler output")
	}

	// Verify context values were passed correctly
	if capturedRedirectURL != "vscode://extension/callback?code=abc" {
		t.Errorf("InterstitialRedirectURL() = %q, want %q", capturedRedirectURL, "vscode://extension/callback?code=abc")
	}
	if capturedAppName != "Visual Studio Code" {
		t.Errorf("InterstitialAppName() = %q, want %q", capturedAppName, "Visual Studio Code")
	}

	// Should NOT contain default template content
	if strings.Contains(body, "Authorization Successful") {
		t.Error("Response should NOT contain default content when custom handler is used")
	}
}

// TestInterstitialContextHelpers tests the context helper functions
func TestInterstitialContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test with empty context
	if got := InterstitialRedirectURL(ctx); got != "" {
		t.Errorf("InterstitialRedirectURL(empty ctx) = %q, want empty string", got)
	}
	if got := InterstitialAppName(ctx); got != "" {
		t.Errorf("InterstitialAppName(empty ctx) = %q, want empty string", got)
	}

	// Test with values set
	ctx = context.WithValue(ctx, interstitialRedirectURLKey, "cursor://callback")
	ctx = context.WithValue(ctx, interstitialAppNameKey, "Cursor")

	if got := InterstitialRedirectURL(ctx); got != "cursor://callback" {
		t.Errorf("InterstitialRedirectURL() = %q, want %q", got, "cursor://callback")
	}
	if got := InterstitialAppName(ctx); got != "Cursor" {
		t.Errorf("InterstitialAppName() = %q, want %q", got, "Cursor")
	}
}

// TestHandler_ServeCallback_CustomURLScheme_WithBranding tests callback with branding
func TestHandler_ServeCallback_CustomURLScheme_WithBranding(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				Title:        "Welcome Back!",
				PrimaryColor: "#FF5733",
			},
		},
		DisableNonceEchoRequirement: true,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	// Register a client with custom URL scheme redirect
	client, _, err := srv.RegisterClient(
		ctx,
		"Branded Test Client",
		"public",
		"none",
		[]string{"cursor://oauth/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create authorization state
	verifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "cursor://oauth/callback"),
		"openid email",
		"",
		challenge,
		"S256",
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?state="+authState.ProviderState+"&code=provider-auth-code",
		nil)
	w := httptest.NewRecorder()

	handler.ServeCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for custom URL scheme with branding", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check custom branding
	if !strings.Contains(body, "Welcome Back!") {
		t.Error("Response should contain custom title from branding config")
	}
	if !strings.Contains(body, "#FF5733") {
		t.Error("Response should contain custom primary color from branding config")
	}
}

// TestHandler_ServeSuccessInterstitial_AppNamePlaceholder tests that {{.AppName}} placeholder is replaced
func TestHandler_ServeSuccessInterstitial_AppNamePlaceholder(t *testing.T) {
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	// Configure with branding that uses {{.AppName}} placeholders
	config := &server.Config{
		Issuer: testIssuer,
		Interstitial: &server.InterstitialConfig{
			Branding: &server.InterstitialBranding{
				Title:      "Connected to Inboxfewer",
				Message:    "You have been authenticated with {{.AppName}}. You can now close this window.",
				ButtonText: "Open {{.AppName}}",
			},
		},
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	handler := New(srv, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	// cursor:// scheme should be detected and replaced with "Cursor"
	handler.serveSuccessInterstitial(w, r, "cursor://oauth/callback?code=abc")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check that {{.AppName}} was replaced with actual app name (Cursor)
	if strings.Contains(body, "{{.AppName}}") {
		t.Error("Response should NOT contain literal {{.AppName}} placeholder - it should be replaced")
	}

	// Check that "Cursor" appears in the message and button
	if !strings.Contains(body, "You have been authenticated with Cursor") {
		t.Error("Response should contain 'You have been authenticated with Cursor' (AppName replaced)")
	}
	if !strings.Contains(body, "Open Cursor") {
		t.Error("Response should contain 'Open Cursor' (AppName replaced in button)")
	}
}
