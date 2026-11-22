package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfIssuedJWTIdentityIncludesValidatedDelegation(t *testing.T) {
	identity, err := userInfoFromJWTClaims(map[string]any{
		"iss": "https://auth.example.test", "sub": "person",
		"act": map[string]any{"iss": "https://agents.example.test", "sub": "agent", "act": map[string]any{"iss": "https://agents.example.test", "sub": "prior-agent"}},
	})
	require.NoError(t, err)
	require.Equal(t, "https://auth.example.test", identity.Issuer)
	require.Equal(t, "person", identity.ID)
	require.Equal(t, "https://agents.example.test", identity.ActorIssuer)
	require.Equal(t, "agent", identity.ActorSubject)
	require.Len(t, identity.ActorChain, 2)
	for _, claims := range []map[string]any{
		{"iss": "https://auth.example.test"},
		{"sub": "person", "act": "invalid"},
		{"sub": "person", "act": map[string]any{"sub": "agent"}},
	} {
		_, err := userInfoFromJWTClaims(claims)
		require.Error(t, err)
	}
}

func TestValidatedSelfIssuedJWTExposesActor(t *testing.T) {
	authorizationServer, _, _ := setupJWTFlowTestServer(t)
	now := time.Now()
	for _, actor := range []*Actor{nil, {Iss: "https://agents.example.test", Sub: "agent"}} {
		bearer, err := authorizationServer.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
			Subject: "person", ClientID: "client", Audience: authorizationServer.Config.GetResourceIdentifier(),
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), Act: actor,
		})
		require.NoError(t, err)
		identity, err := authorizationServer.ValidateToken(t.Context(), bearer)
		require.NoError(t, err)
		require.Equal(t, authorizationServer.Config.Issuer, identity.Issuer)
		require.Equal(t, actor != nil, identity.IsOBO())
		if actor != nil {
			require.Equal(t, actor.Iss, identity.ActorIssuer)
			require.Equal(t, actor.Sub, identity.ActorSubject)
		}
	}
}
