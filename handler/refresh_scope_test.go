package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestHandler_ServeToken_RefreshScope(t *testing.T) {
	tests := []struct {
		name       string
		scope      string
		wantScope  string
		wantAccess []string
	}{
		{name: "omitted", scope: "", wantScope: "openid email profile", wantAccess: []string{"openid", "email", "profile"}},
		{name: "subset narrows the access token", scope: "email", wantScope: "email", wantAccess: []string{"email"}},
		{name: "beyond the grant issues the grant", scope: "email admin", wantScope: "openid email profile", wantAccess: []string{"openid", "email", "profile"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRefreshTestEnv(t)
			clientID, secret := env.registerClient(t, oauth.ClientTypeConfidential)
			expiresAt := time.Now().Add(time.Hour)
			refreshToken := env.seedRefreshToken(t, clientID, "user-scope", "family-scope", expiresAt)
			require.NoError(t, env.store.SaveTokenMetadata(t.Context(), refreshToken, storage.TokenMetadata{
				UserID: "user-scope", ClientID: clientID, FamilyID: "family-scope", TokenType: "refresh",
				Scopes: []string{"openid", "email", "profile"}, IssuedAt: time.Now(), ExpiresAt: expiresAt,
			}))

			form := formWith("grant_type", "refresh_token", "refresh_token", refreshToken)
			if tt.scope != "" {
				form.Set("scope", tt.scope)
			}
			recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

			response := decodeTokenResponse(t, recorder)
			require.Equal(t, tt.wantScope, response.Scope)
			access, err := env.store.GetTokenMetadata(response.AccessToken)
			require.NoError(t, err)
			require.Equal(t, tt.wantAccess, access.Scopes)
			refresh, err := env.store.GetTokenMetadata(response.RefreshToken)
			require.NoError(t, err)
			require.Equal(t, []string{"openid", "email", "profile"}, refresh.Scopes)
		})
	}
}
