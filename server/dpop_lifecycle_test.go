package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestDPoPTokenTypeAndIntrospectionSurviveRefresh(t *testing.T) {
	server, store, _ := setupFlowTestServer(t)
	providerToken := &oauth2.Token{AccessToken: "upstream-access", RefreshToken: "upstream-refresh", Expiry: time.Now().Add(time.Hour)}
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", providerToken))
	token, err := server.generateAndStoreTokens(t.Context(), &storage.AuthorizationCode{
		UserID: "person", ProviderToken: providerToken, Scope: "openid", Audience: server.Config.GetResourceIdentifier(),
	}, "client", "family", "public-key-thumbprint")
	require.NoError(t, err)
	require.Equal(t, tokenTypeDPoP, token.TokenType)
	require.NoError(t, server.trackRefreshTokenFamily(t.Context(), token.RefreshToken, "person", "client", "family"))
	for range 2 {
		response, err := server.IntrospectToken(t.Context(), token.AccessToken, "client")
		require.NoError(t, err)
		require.Equal(t, true, response["active"])
		require.Equal(t, tokenTypeDPoP, response["token_type"])
		require.Equal(t, map[string]any{"jkt": "public-key-thumbprint"}, response["cnf"])
		metadata, err := store.GetTokenMetadata(token.AccessToken)
		require.NoError(t, err)
		require.Equal(t, metadata.ExpiresAt.Add(time.Duration(server.Config.ClockSkewGracePeriod)*time.Second), metadata.RetainUntil)
		token, err = server.RefreshAccessToken(t.Context(), token.RefreshToken, "client")
		require.NoError(t, err)
		require.Equal(t, tokenTypeDPoP, token.TokenType)
	}
}

func TestJWTIntrospectionReportsDPoPTokenType(t *testing.T) {
	response := introspectionResponseFromJWTClaims(map[string]any{
		"cnf": map[string]any{"jkt": "public-key-thumbprint"},
	}, "client")
	require.Equal(t, tokenTypeDPoP, response["token_type"])
	require.Equal(t, map[string]any{"jkt": "public-key-thumbprint"}, response["cnf"])
}
