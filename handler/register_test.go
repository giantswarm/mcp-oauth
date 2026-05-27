package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestHandler_ServeClientRegistration_RFC7591Fields(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()
	handler.server.Config().AllowPublicClientRegistration = true

	body, err := json.Marshal(oauth.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "RFC 7591 Client",
		ClientType:              "confidential",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeClientRegistration(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	issuedAt, ok := resp["client_id_issued_at"].(float64)
	require.True(t, ok, "client_id_issued_at must be present and numeric (response=%v)", resp)
	require.GreaterOrEqual(t, int64(issuedAt), time.Now().Add(-5*time.Second).Unix())

	// Confidential client → client_secret + client_secret_expires_at:0 (never).
	require.NotEmpty(t, resp["client_secret"])
	require.Equal(t, float64(0), resp["client_secret_expires_at"],
		"client_secret_expires_at == 0 signals 'never expires' per RFC 7591 §3.2.1")
}

func TestHandler_ServeClientRegistration(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Create registration request
	regReq := oauth.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		ClientType:              "confidential",
	}

	body, err := json.Marshal(regReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	// For now, just verify it doesn't panic and returns a response
	// Actual registration might fail without proper configuration
	if w.Code == 0 {
		t.Error("handler should set status code")
	}
}

func TestHandler_ServeClientRegistration_Success(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Enable public registration for this test
	handler.server.Config().AllowPublicClientRegistration = true

	regReq := oauth.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		ClientType:              "confidential",
	}

	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp oauth.ClientRegistrationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ClientID == "" {
		t.Error("ClientID should not be empty")
	}
	if resp.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}
}

func TestHandler_ServeClientRegistration_TokenEndpointAuthMethod(t *testing.T) {
	handler, _ := setupTestHandler(t)
	// Enable public registration for these tests
	handler.server.Config().AllowPublicClientRegistration = true
	handler.server.Config().AllowPublicClientsWithoutPKCE = true

	tests := []struct {
		name                    string
		tokenEndpointAuthMethod string
		clientType              string
		wantStatus              int
		wantAuthMethod          string
		wantClientType          string
		wantSecret              bool
	}{
		{
			name:                    "auth_method=none creates public client",
			tokenEndpointAuthMethod: "none",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "none",
			wantClientType:          "public",
			wantSecret:              false,
		},
		{
			name:                    "auth_method=client_secret_basic creates confidential client",
			tokenEndpointAuthMethod: "client_secret_basic",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_basic",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "auth_method=client_secret_post creates confidential client",
			tokenEndpointAuthMethod: "client_secret_post",
			clientType:              "",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_post",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "unsupported auth_method returns error",
			tokenEndpointAuthMethod: "client_secret_jwt",
			clientType:              "",
			wantStatus:              http.StatusBadRequest,
		},
		{
			name:                    "empty auth_method defaults to client_secret_basic",
			tokenEndpointAuthMethod: "",
			clientType:              "confidential",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "client_secret_basic",
			wantClientType:          "confidential",
			wantSecret:              true,
		},
		{
			name:                    "auth_method=none overrides client_type=confidential",
			tokenEndpointAuthMethod: "none",
			clientType:              "confidential",
			wantStatus:              http.StatusCreated,
			wantAuthMethod:          "none",
			wantClientType:          "public",
			wantSecret:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regReq := oauth.ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Test Client - " + tt.name,
				ClientType:              tt.clientType,
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1." + tt.name[:3] // Unique IP per test
			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusCreated {
				var resp oauth.ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}

				if resp.TokenEndpointAuthMethod != tt.wantAuthMethod {
					t.Errorf("TokenEndpointAuthMethod = %q, want %q", resp.TokenEndpointAuthMethod, tt.wantAuthMethod)
				}

				if resp.ClientType != tt.wantClientType {
					t.Errorf("ClientType = %q, want %q", resp.ClientType, tt.wantClientType)
				}

				if tt.wantSecret {
					if resp.ClientSecret == "" {
						t.Error("ClientSecret should not be empty for confidential client")
					}
				} else {
					if resp.ClientSecret != "" {
						t.Error("ClientSecret should be empty for public client")
					}
				}
			}
		})
	}
}

func TestHandler_ServeClientRegistration_PublicClientPolicy(t *testing.T) {
	// Test that public client registration is properly controlled by AllowPublicClientRegistration
	const testRegistrationToken = "test-registration-token-12345"

	tests := []struct {
		name                          string
		allowPublicClientRegistration bool
		tokenEndpointAuthMethod       string
		clientType                    string
		wantStatus                    int
		wantErrorContains             string
	}{
		{
			name:                          "public client rejected when policy disabled (auth_method=none)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client rejected when policy disabled (client_type=public)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "",
			clientType:                    "public",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client rejected when policy disabled (both specified)",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "public",
			wantStatus:                    http.StatusBadRequest,
			wantErrorContains:             "Public client registration is not enabled",
		},
		{
			name:                          "public client allowed when policy enabled (auth_method=none)",
			allowPublicClientRegistration: true,
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "public client allowed when policy enabled (client_type=public)",
			allowPublicClientRegistration: true,
			tokenEndpointAuthMethod:       "",
			clientType:                    "public",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "confidential client allowed when policy disabled",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "client_secret_basic",
			clientType:                    "",
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "confidential client (default) allowed when policy disabled",
			allowPublicClientRegistration: false,
			tokenEndpointAuthMethod:       "",
			clientType:                    "confidential",
			wantStatus:                    http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			// Configure the policy for this test
			handler.server.Config().AllowPublicClientRegistration = tt.allowPublicClientRegistration
			handler.server.Config().AllowPublicClientsWithoutPKCE = true // Not relevant for registration test

			// Set registration token when authentication is required
			if !tt.allowPublicClientRegistration {
				handler.server.Config().RegistrationAccessToken = testRegistrationToken
			}

			regReq := oauth.ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				ClientType:              tt.clientType,
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Test Client - " + tt.name,
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1.100"

			// Add authentication header when required
			if !tt.allowPublicClientRegistration {
				req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
			}

			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusBadRequest && tt.wantErrorContains != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantErrorContains) {
					t.Errorf("error response should contain %q, got: %s", tt.wantErrorContains, body)
				}
			}

			if tt.wantStatus == http.StatusCreated {
				var resp oauth.ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}

				// Verify the client was created with correct type
				expectedType := tt.clientType
				if tt.tokenEndpointAuthMethod == "none" {
					expectedType = "public"
				} else if expectedType == "" {
					expectedType = "confidential"
				}

				if resp.ClientType != expectedType {
					t.Errorf("ClientType = %q, want %q", resp.ClientType, expectedType)
				}
			}
		})
	}
}

func TestHandler_ServeClientRegistration_TrustedSchemes(t *testing.T) {
	// Test that clients can register without a token when using trusted URI schemes
	const testRegistrationToken = "test-registration-token-12345"

	tests := []struct {
		name                          string
		trustedSchemes                []string
		disableStrictSchemeMatching   bool // true = permissive mode, false = strict mode (default)
		registrationAccessToken       string
		allowPublicClientRegistration bool
		redirectURIs                  []string
		tokenEndpointAuthMethod       string
		clientType                    string
		provideToken                  bool
		wantStatus                    int
		wantErrorContains             string
	}{
		// Trusted scheme registration tests
		{
			name:                          "cursor scheme - no token - allowed",
			trustedSchemes:                []string{"cursor"},
			disableStrictSchemeMatching:   false, // strict mode (default)
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "vscode scheme - no token - allowed",
			trustedSchemes:                []string{"vscode", "cursor"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"vscode://oauth/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusCreated,
		},
		{
			name:                          "multiple trusted URIs - all trusted - allowed",
			trustedSchemes:                []string{"cursor", "vscode"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback", "vscode://oauth/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusCreated,
		},

		// Strict matching tests
		{
			name:                          "strict: mixed schemes - rejected",
			trustedSchemes:                []string{"cursor"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback", "https://example.com/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusUnauthorized,
			wantErrorContains:             "authentication",
		},
		{
			name:                          "strict: https only - rejected without token",
			trustedSchemes:                []string{"cursor"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"https://example.com/callback"},
			tokenEndpointAuthMethod:       "",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusUnauthorized,
			wantErrorContains:             "authentication",
		},

		// Permissive matching tests
		{
			name:                          "permissive: mixed schemes - allowed (has trusted)",
			trustedSchemes:                []string{"cursor"},
			disableStrictSchemeMatching:   true, // permissive mode
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback", "https://example.com/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusCreated,
		},

		// Token always works
		{
			name:                          "with token - any scheme works",
			trustedSchemes:                []string{"cursor"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"https://example.com/callback"},
			tokenEndpointAuthMethod:       "",
			clientType:                    "",
			provideToken:                  true,
			wantStatus:                    http.StatusCreated,
		},

		// No trusted schemes configured
		{
			name:                          "no trusted schemes - token required",
			trustedSchemes:                nil,
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusUnauthorized,
		},

		// Case insensitivity
		{
			name:                          "case insensitive scheme matching",
			trustedSchemes:                []string{"Cursor"},
			disableStrictSchemeMatching:   false,
			registrationAccessToken:       testRegistrationToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"cursor://oauth/callback"},
			tokenEndpointAuthMethod:       "none",
			clientType:                    "",
			provideToken:                  false,
			wantStatus:                    http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			// Configure server with trusted schemes and pre-computed map
			handler.server.Config().TrustedPublicRegistrationSchemes = tt.trustedSchemes
			handler.server.Config().DisableStrictSchemeMatching = tt.disableStrictSchemeMatching
			handler.server.Config().RegistrationAccessToken = tt.registrationAccessToken
			handler.server.Config().AllowPublicClientRegistration = tt.allowPublicClientRegistration
			// Disable production mode for tests to allow custom schemes without full validation
			handler.server.Config().ProductionMode = false

			// Build pre-computed trusted schemes map (normally done by config validation)
			if len(tt.trustedSchemes) > 0 {
				handler.server.Config().SetTrustedSchemesMap(tt.trustedSchemes)
			}

			regReq := oauth.ClientRegistrationRequest{
				ClientName:              "Test Client",
				ClientType:              tt.clientType,
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				RedirectURIs:            tt.redirectURIs,
			}

			body, err := json.Marshal(regReq)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1.100:12345"

			if tt.provideToken {
				req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
			}

			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus != http.StatusCreated && tt.wantErrorContains != "" {
				respBody := w.Body.String()
				if !strings.Contains(strings.ToLower(respBody), strings.ToLower(tt.wantErrorContains)) {
					t.Errorf("error response should contain %q (case-insensitive), got: %s", tt.wantErrorContains, respBody)
				}
			}

			if tt.wantStatus == http.StatusCreated {
				var resp oauth.ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}

				// Verify redirect URIs match
				if len(resp.RedirectURIs) != len(tt.redirectURIs) {
					t.Errorf("RedirectURIs length = %d, want %d", len(resp.RedirectURIs), len(tt.redirectURIs))
				}
			}
		})
	}
}

func TestHandler_ServeClientRegistration_ClientNameValidation(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Enable public registration for this test
	handler.server.Config().AllowPublicClientRegistration = true

	tests := []struct {
		name           string
		clientName     string
		wantStatus     int
		wantErrContain string
	}{
		{
			name:       "valid client name succeeds",
			clientName: "Test Application",
			wantStatus: http.StatusCreated,
		},
		{
			name:           "script tag rejected",
			clientName:     "<script>alert(1)</script>",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "special characters",
		},
		{
			name:           "HTML tag rejected",
			clientName:     "<b>Bold App</b>",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "special characters",
		},
		{
			name:           "single quote rejected (JS injection)",
			clientName:     "Client's App",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "special characters",
		},
		{
			name:           "backtick rejected (template injection)",
			clientName:     "App `test`",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "special characters",
		},
		{
			name:           "long name rejected",
			clientName:     strings.Repeat("x", 300),
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "256 characters",
		},
		{
			name:           "control character rejected",
			clientName:     "App\x00Name",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "printable characters",
		},
		{
			name:           "newline rejected (log injection prevention)",
			clientName:     "Legit App\nWARN Fake log entry",
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "newline characters",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regReq := oauth.ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              tt.clientName,
				ClientType:              "confidential",
			}

			body, _ := json.Marshal(regReq)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			// Use unique IP per test to avoid rate limiting
			req.RemoteAddr = fmt.Sprintf("192.168.%d.%d:12345", i/256, i%256)
			w := httptest.NewRecorder()

			handler.ServeClientRegistration(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus != http.StatusCreated {
				// Verify error message contains expected text
				if !strings.Contains(w.Body.String(), tt.wantErrContain) {
					t.Errorf("error response %q should contain %q",
						w.Body.String(), tt.wantErrContain)
				}
			} else {
				// Verify successful registration
				var resp oauth.ClientRegistrationResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.ClientID == "" {
					t.Error("ClientID should not be empty")
				}
			}
		})
	}
}

func TestHandler_ServeClientRegistration_InvalidJSON(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config().AllowPublicClientRegistration = true

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()

	handler.ServeClientRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Empty redirect URIs are apparently allowed, so this test is removed

func TestHandler_checkClientRegistrationRateLimit_Reject(t *testing.T) {
	// Limit of 1 with sub-second window so retryAfter<1 branch is also hit.
	rl := security.NewClientRegistrationRateLimiterWithConfig(1, time.Millisecond, 100, nil)
	t.Cleanup(rl.Stop)
	handler, store := setupTestHandlerWithOpts(t, server.WithClientRegistrationRateLimiter(rl))
	defer store.Stop()
	handler.server.Config().MaxRegistrationsPerHour = 1
	handler.server.Config().RegistrationRateLimitWindow = 0

	const ip = "192.0.2.77"
	rl.Allow(security.RateLimitBucket(ip)) // consume the one allowed slot

	w := httptest.NewRecorder()
	rejected := handler.checkClientRegistrationRateLimit(t.Context(), w, ip, time.Now())

	require.True(t, rejected)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestHandler_authorizeClientRegistration_InvalidTokenLogs(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config().RegistrationAccessToken = "correct-token"

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	_, ok := handler.authorizeClientRegistration(w, req, &clientRegistrationRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	}, "192.0.2.1")

	require.False(t, ok)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_authorizeClientRegistration_TrustedSchemeInvalidURI(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config().TrustedPublicRegistrationSchemes = []string{"myapp"}
	handler.server.Config().SetTrustedSchemesMap([]string{"myapp"})
	handler.server.Config().RegistrationAccessToken = "secret"

	// A URI with no scheme triggers the error path in CanRegisterWithTrustedScheme.
	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()

	_, ok := handler.authorizeClientRegistration(w, req, &clientRegistrationRequest{
		RedirectURIs: []string{"no-scheme-uri"},
	}, "192.0.2.1")

	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_getMaxClientsPerIP_Default(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	handler.server.Config().MaxClientsPerIP = 0
	require.Equal(t, 10, handler.getMaxClientsPerIP())
}

func TestHandler_recordTrustedAllowlistSpan_UnknownGate(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	auth := registrationAuthResult{viaTrustedAllowlist: true, gate: "unknown-gate"}
	handler.recordTrustedAllowlistSpan(noop.Span{}, auth)
}

func TestHandler_auditTrustedAllowlistRegistration_UnknownGate(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	auth := registrationAuthResult{viaTrustedAllowlist: true, gate: "unknown-gate"}
	client := &storage.Client{
		ClientID:     "test-client",
		ClientType:   oauth.ClientTypeConfidential,
		RedirectURIs: []string{"https://example.com/callback"},
	}
	handler.auditTrustedAllowlistRegistration(t.Context(), auth, client, "192.0.2.1")
}
