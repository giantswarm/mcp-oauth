package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRevocationPreservesOtherClientRefreshAfterProviderExpiry(t *testing.T) {
	server, store, provider := setupFlowTestServer(t)
	revoked := false
	refreshed := false
	provider.RevokeTokenFunc = func(_ context.Context, access string) error {
		require.Equal(t, "shared-upstream-access", access)
		revoked = true
		return nil
	}
	provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
		refreshed = true
		if revoked {
			return nil, errors.New("upstream grant revoked")
		}
		return &oauth2.Token{AccessToken: "fresh-upstream", RefreshToken: "shared-upstream-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	}
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", &oauth2.Token{AccessToken: "shared-upstream-access", RefreshToken: "shared-upstream-refresh", Expiry: time.Now().Add(time.Hour)}))
	for _, clientID := range []string{"first-client", "other-client"} {
		require.NoError(t, store.SaveProviderTokenRef(t.Context(), clientID+"-refresh", "person", time.Now().Add(time.Hour)))
		require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), clientID+"-refresh", "person", clientID, clientID+"-family", 0, time.Now().Add(time.Hour)))
	}
	require.NoError(t, server.RevokeToken(t.Context(), "first-client-refresh", "first-client", "192.0.2.1"))
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", &oauth2.Token{AccessToken: "shared-upstream-access", RefreshToken: "shared-upstream-refresh", Expiry: time.Now().Add(-time.Minute)}))
	_, err := server.RefreshAccessToken(t.Context(), "other-client-refresh", "other-client")
	require.NoError(t, err, "revoking one client's family must preserve the other client's shared upstream grant")
	require.False(t, revoked)
	require.True(t, refreshed, "the unaffected client must refresh the expired upstream grant")
}
