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
