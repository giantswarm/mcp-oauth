package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestValidatedClientContextDoesNotMutateCachedIdentity(t *testing.T) {
	user := &providers.UserInfo{Issuer: "https://issuer.example.test", ID: "subject", ClientID: "signed-client"}
	first := contextWithValidatedToken(t.Context(), user, &storage.TokenMetadata{ClientID: "client-a"})
	second := contextWithValidatedToken(t.Context(), user, &storage.TokenMetadata{ClientID: "client-b"})
	a, ok := UserInfoFromContext(first)
	require.True(t, ok)
	b, ok := UserInfoFromContext(second)
	require.True(t, ok)
	require.Equal(t, "client-a", a.ClientID)
	require.Equal(t, "client-b", b.ClientID)
	require.Equal(t, "signed-client", user.ClientID)
	forwarded := contextWithValidatedToken(t.Context(), user, nil)
	info, ok := UserInfoFromContext(forwarded)
	require.True(t, ok)
	require.Equal(t, "signed-client", info.ClientID)
}
