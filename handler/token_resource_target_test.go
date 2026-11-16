package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestServeToken_AuthorizationCode_ResourceTarget(t *testing.T) {
	tests := []struct {
		name       string
		resource   string
		wantStatus int
		wantError  string
	}{
		{name: "this server", resource: testIssuer, wantStatus: http.StatusOK},
		{name: "another server", resource: "https://other.example.com/mcp", wantStatus: http.StatusBadRequest, wantError: constants.ErrorCodeInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			client, secret, err := handler.server.RegisterClient(t.Context(), "Test Client", "confidential", "",
				[]string{refusalRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
			require.NoError(t, err)

			verifier := testutil.GenerateRandomString(50)
			challengeHash := sha256.Sum256([]byte(verifier))
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            client.ClientID,
				RedirectURI:         refusalRedirectURI,
				Scope:               "openid",
				Resource:            testIssuer,
				CodeChallenge:       base64.RawURLEncoding.EncodeToString(challengeHash[:]),
				CodeChallengeMethod: "S256",
				UserID:              "test-user-123",
				ProviderToken:       testutil.GenerateTestToken(),
				CreatedAt:           time.Now(),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}
			require.NoError(t, store.SaveAuthorizationCode(t.Context(), authCode))

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode.Code},
				"redirect_uri":  {refusalRedirectURI},
				"code_verifier": {verifier},
				"resource":      {tt.resource},
			}
			request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(client.ClientID, secret)
			recorder := httptest.NewRecorder()

			handler.ServeToken(recorder, request)

			require.Equal(t, tt.wantStatus, recorder.Code, "body: %s", recorder.Body.String())
			if tt.wantError == "" {
				return
			}
			var errorResponse oauth.ErrorResponse
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&errorResponse))
			require.Equal(t, tt.wantError, errorResponse.Error)
		})
	}
}

func TestServeAuthorization_MultipleResourcesRedirectInvalidTarget(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	audit := installAuditCapture(handler)
	client, _, err := handler.server.RegisterClient(t.Context(), "Test Client", "public", "",
		[]string{refusalRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	trustClient(handler.server, client.ClientID)
	state := testutil.GenerateRandomString(43)

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {refusalRedirectURI},
		"state":                 {state},
		"scope":                 {"openid"},
		"resource":              {testIssuer, testIssuer},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	recorder := httptest.NewRecorder()
	handler.ServeAuthorization(recorder, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))

	requireAuthorizationErrorRedirect(t, recorder, constants.ErrorCodeInvalidTarget, multipleResourcesDescription, state)
	require.Contains(t, audit.String(), auditReasonMultipleResources)
}

func TestServeAuthorization_MultipleResourcesWithUnregisteredRedirectAnswerDirectly(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client, _, err := handler.server.RegisterClient(t.Context(), "Test Client", "public", "",
		[]string{refusalRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)

	query := url.Values{
		"response_type": {"code"},
		"client_id":     {client.ClientID},
		"redirect_uri":  {"https://attacker.example.com/callback"},
		"resource":      {testIssuer, "https://other.example.com/mcp"},
	}
	recorder := httptest.NewRecorder()
	handler.ServeAuthorization(recorder, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	require.Empty(t, recorder.Header().Get("Location"))
}

func TestServeToken_MultipleResourcesInvalidTarget(t *testing.T) {
	for _, grantType := range []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"} {
		t.Run(grantType, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			audit := installAuditCapture(handler)

			form := url.Values{
				"grant_type": {grantType},
				"resource":   {testIssuer, "https://other.example.com/mcp"},
			}
			request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()

			handler.ServeToken(recorder, request)

			require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
			var errorResponse oauth.ErrorResponse
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&errorResponse))
			require.Equal(t, constants.ErrorCodeInvalidTarget, errorResponse.Error)
			require.Contains(t, audit.String(), auditReasonMultipleResources)
		})
	}
}

func TestServeToken_RefreshResource(t *testing.T) {
	tests := []struct {
		name       string
		resource   []string
		wantStatus int
		wantError  string
	}{
		{name: "absent", wantStatus: http.StatusOK},
		{name: "the grant's audience", resource: []string{testIssuer}, wantStatus: http.StatusOK},
		{name: "the grant's audience in another case with a trailing slash", resource: []string{strings.ToUpper(testIssuer) + "/"}, wantStatus: http.StatusOK},
		{name: "another server", resource: []string{"https://other.example.com/mcp"}, wantStatus: http.StatusBadRequest, wantError: constants.ErrorCodeInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			audit := installAuditCapture(handler)
			client, secret, err := handler.server.RegisterClient(t.Context(), "Test Client", "confidential", "",
				[]string{refusalRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
			require.NoError(t, err)

			verifier := testutil.GenerateRandomString(50)
			challengeHash := sha256.Sum256([]byte(verifier))
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            client.ClientID,
				RedirectURI:         refusalRedirectURI,
				Scope:               "openid",
				Resource:            testIssuer,
				CodeChallenge:       base64.RawURLEncoding.EncodeToString(challengeHash[:]),
				CodeChallengeMethod: "S256",
				UserID:              "test-user-123",
				ProviderToken:       testutil.GenerateTestToken(),
				CreatedAt:           time.Now(),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}
			require.NoError(t, store.SaveAuthorizationCode(t.Context(), authCode))
			tokens, _, err := handler.server.ExchangeAuthorizationCode(t.Context(), authCode.Code, client.ClientID,
				refusalRedirectURI, testIssuer, verifier, "")
			require.NoError(t, err)
			require.NoError(t, store.SaveUserProviderToken(t.Context(), authCode.UserID, authCode.ProviderToken))

			refresh := func(resource []string) *httptest.ResponseRecorder {
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}
				if resource != nil {
					form["resource"] = resource
				}
				request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.SetBasicAuth(client.ClientID, secret)
				recorder := httptest.NewRecorder()
				handler.ServeToken(recorder, request)
				return recorder
			}

			recorder := refresh(tt.resource)

			require.Equal(t, tt.wantStatus, recorder.Code, "body: %s", recorder.Body.String())
			if tt.wantError == "" {
				return
			}
			var errorResponse oauth.ErrorResponse
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&errorResponse))
			require.Equal(t, tt.wantError, errorResponse.Error)
			require.Contains(t, audit.String(), "refresh_resource_mismatch")
			require.NotContains(t, audit.String(), "reuse_detected")

			retry := refresh(nil)
			require.Equal(t, http.StatusOK, retry.Code, "the refused refresh token stays usable: %s", retry.Body.String())
		})
	}
}
