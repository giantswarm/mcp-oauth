package memory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TestStore_RevokeTokensForFamily_KeepsOtherFamilies: revoking one family
// deletes its refresh, access and id_tokens and leaves the same user+client's
// other family untouched.
func TestStore_RevokeTokensForFamily_KeepsOtherFamilies(t *testing.T) {
	store := New()
	defer store.Stop()
	ctx := t.Context()
	expiry := time.Now().Add(time.Hour)

	seed := func(familyID string) (refreshToken, accessToken, idToken string) {
		refreshToken, accessToken, idToken = "rt-"+familyID, "at-"+familyID, "id-"+familyID
		require.NoError(t, store.SaveRefreshTokenWithFamily(ctx, refreshToken, "user-1", "client-1", familyID, 1, expiry))
		require.NoError(t, store.SaveToken(ctx, accessToken, &oauth2.Token{AccessToken: "provider-at", Expiry: expiry}))
		for token, tokenType := range map[string]string{refreshToken: "refresh", accessToken: "access", idToken: "id"} {
			require.NoError(t, store.SaveTokenMetadata(ctx, token, storage.TokenMetadata{
				UserID: "user-1", ClientID: "client-1", TokenType: tokenType, FamilyID: familyID, ExpiresAt: expiry,
			}))
		}
		return refreshToken, accessToken, idToken
	}
	rt1, at1, id1 := seed("family-1")
	rt2, at2, id2 := seed("family-2")

	count, err := store.RevokeTokensForFamily(ctx, "user-1", "client-1", "family-1")
	require.NoError(t, err)
	require.Equal(t, 3, count)

	_, err = store.GetRefreshTokenInfo(ctx, rt1)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	_, err = store.GetToken(ctx, at1)
	require.Error(t, err)
	family1, err := store.GetRefreshTokenFamily(ctx, rt1)
	require.NoError(t, err)
	require.True(t, family1.Revoked)

	_, err = store.GetRefreshTokenInfo(ctx, rt2)
	require.NoError(t, err)
	_, err = store.GetToken(ctx, at2)
	require.NoError(t, err)
	family2, err := store.GetRefreshTokenFamily(ctx, rt2)
	require.NoError(t, err)
	require.False(t, family2.Revoked)

	tokens, err := store.GetTokensByUserClient(ctx, "user-1", "client-1")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{rt2, at2, id2}, tokens)
	require.NotContains(t, tokens, id1)
}
