package valkey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TestRevokeTokensForFamily_KeepsOtherFamilies: revoking one family deletes
// its refresh, access and id_tokens with their user+client index entries and
// leaves the same user+client's other family untouched.
func TestRevokeTokensForFamily_KeepsOtherFamilies(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour)

	seed := func(familyID string) (refreshToken, accessToken, idToken string) {
		refreshToken, accessToken, idToken = "rt-"+familyID, "at-"+familyID, "id-"+familyID
		require.NoError(t, s.SaveRefreshTokenWithFamily(ctx, refreshToken, "user-1", "client-1", familyID, 1, expiry))
		require.NoError(t, s.SaveToken(ctx, accessToken, &oauth2.Token{AccessToken: "provider-at", Expiry: expiry}))
		for token, tokenType := range map[string]string{refreshToken: nsRefresh, accessToken: "access", idToken: "id"} {
			require.NoError(t, s.SaveTokenMetadata(ctx, token, storage.TokenMetadata{
				UserID: "user-1", ClientID: "client-1", TokenType: tokenType, FamilyID: familyID, ExpiresAt: expiry,
			}))
		}
		return refreshToken, accessToken, idToken
	}
	rt1, at1, id1 := seed("family-1")
	rt2, at2, id2 := seed("family-2")

	_, err := s.RevokeTokensForFamily(ctx, "user-1", "client-1", "family-1")
	require.NoError(t, err)

	_, err = s.GetRefreshTokenInfo(ctx, rt1)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	_, err = s.GetToken(ctx, at1)
	require.Error(t, err)
	_, err = s.GetTokenMetadata(id1)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	family1, err := s.GetRefreshTokenFamily(ctx, rt1)
	require.NoError(t, err)
	require.True(t, family1.Revoked)

	_, err = s.GetRefreshTokenInfo(ctx, rt2)
	require.NoError(t, err)
	_, err = s.GetToken(ctx, at2)
	require.NoError(t, err)
	_, err = s.GetTokenMetadata(id2)
	require.NoError(t, err)
	family2, err := s.GetRefreshTokenFamily(ctx, rt2)
	require.NoError(t, err)
	require.False(t, family2.Revoked)

	tokens, err := s.GetTokensByUserClient(ctx, "user-1", "client-1")
	require.NoError(t, err)
	require.NotContains(t, tokens, rt1)
	require.NotContains(t, tokens, at1)
	require.Contains(t, tokens, rt2)
}
