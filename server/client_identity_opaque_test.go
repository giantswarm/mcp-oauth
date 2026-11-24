package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

func TestValidateTokenOpaqueClientIdentity(t *testing.T) {
	server, store, provider := setupFlowTestServer(t)
	provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		return &providers.UserInfo{ID: "alice", ClientID: "provider-side-client"}, nil
	}
	seedProviderToken(t, store, "opaque-access", "alice", &oauth2.Token{AccessToken: "upstream", Expiry: time.Now().Add(time.Hour)})

	userInfo, err := server.ValidateToken(t.Context(), "opaque-access")
	require.NoError(t, err)
	require.Equal(t, "test-client", userInfo.ClientID)
	require.Equal(t, server.Config.Issuer, userInfo.Issuer)
	require.Equal(t, providers.TokenSourceOAuth, userInfo.TokenSource)
}
