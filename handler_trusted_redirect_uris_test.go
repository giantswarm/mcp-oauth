package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const trustedRedirectURITestToken = "test-registration-token-trusted-uris-12345"

func TestHandler_ServeClientRegistration_TrustedRedirectURIs(t *testing.T) {
	tests := []struct {
		name                          string
		trustedURIs                   []string
		registrationAccessToken       string
		allowPublicClientRegistration bool
		redirectURIs                  []string
		tokenEndpointAuthMethod       string
		clientType                    string
		provideToken                  bool
		wantStatus                    int
		wantErrorContains             string
	}{
		{
			name:                    "single matching URI - no token - public client allowed",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusCreated,
		},
		{
			name:                    "uppercase host matches normalised entry",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://CLAUDE.AI/api/mcp/auth_callback"},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusCreated,
		},
		{
			name:                    "default port matches without port",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://claude.ai:443/api/mcp/auth_callback"},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusCreated,
		},
		{
			name:                    "strict: any non-matching URI in request rejects",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs: []string{
				"https://claude.ai/api/mcp/auth_callback",
				"https://attacker.example/cb",
			},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusUnauthorized,
			wantErrorContains:       "authentication",
		},
		{
			name:                    "case-sensitive path mismatch rejects",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://claude.ai/api/MCP/auth_callback"},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusUnauthorized,
		},
		{
			name:                    "no allowlist configured - token required",
			trustedURIs:             nil,
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
			tokenEndpointAuthMethod: "none",
			wantStatus:              http.StatusUnauthorized,
		},
		{
			name:                    "with token - any URI works",
			trustedURIs:             []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken: trustedRedirectURITestToken,
			redirectURIs:            []string{"https://example.com/cb"},
			provideToken:            true,
			wantStatus:              http.StatusCreated,
		},
		{
			name:                          "public client via allowlist without token_endpoint_auth_method=none still ok",
			trustedURIs:                   []string{"https://claude.ai/api/mcp/auth_callback"},
			registrationAccessToken:       trustedRedirectURITestToken,
			allowPublicClientRegistration: false,
			redirectURIs:                  []string{"https://claude.ai/api/mcp/auth_callback"},
			tokenEndpointAuthMethod:       "",
			wantStatus:                    http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			handler.server.Config.RegistrationAccessToken = tt.registrationAccessToken
			handler.server.Config.AllowPublicClientRegistration = tt.allowPublicClientRegistration
			handler.server.Config.TrustedPublicRegistrationRedirectURIs = tt.trustedURIs
			handler.server.Config.SetTrustedRedirectURIsSet(tt.trustedURIs)
			handler.server.Config.ProductionMode = false

			regReq := ClientRegistrationRequest{
				ClientName:              "Test Client",
				ClientType:              tt.clientType,
				TokenEndpointAuthMethod: tt.tokenEndpointAuthMethod,
				RedirectURIs:            tt.redirectURIs,
			}

			body, err := json.Marshal(regReq)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1.100:12345"
			if tt.provideToken {
				req.Header.Set("Authorization", "Bearer "+tt.registrationAccessToken)
			}

			w := httptest.NewRecorder()
			handler.ServeClientRegistration(w, req)

			require.Equal(t, tt.wantStatus, w.Code, "body: %s", w.Body.String())

			if tt.wantErrorContains != "" {
				require.Contains(t, w.Body.String(), tt.wantErrorContains)
			}

			if tt.wantStatus == http.StatusCreated {
				var resp ClientRegistrationResponse
				require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
				require.NotEmpty(t, resp.ClientID)
				require.Equal(t, len(tt.redirectURIs), len(resp.RedirectURIs))
			}
		})
	}
}

func TestHandler_IsRegistrationAvailable_TrustedRedirectURIs(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	require.False(t, handler.isRegistrationAvailable(), "no gate configured")

	handler.server.Config.TrustedPublicRegistrationRedirectURIs = []string{"https://claude.ai/cb"}
	require.True(t, handler.isRegistrationAvailable(), "allowlist enables DCR")
}
