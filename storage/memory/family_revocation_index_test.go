package memory

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestFamilyRevocationIndexFencesEmptyFamiliesAndExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := New(WithRevokedFamilyRetentionDays(1))
		t.Cleanup(store.Stop)
		require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "family"))
		revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
		require.NoError(t, err)
		require.True(t, revoked)
		require.ErrorIs(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh", "person", "client", "family", 1, time.Now().Add(time.Hour)), storage.ErrRefreshTokenFamilyRevoked)
		time.Sleep(25 * time.Hour)
		revoked, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
		require.NoError(t, err)
		require.False(t, revoked)
	})
}

func TestFamilyRevocationIndexRetainsAcceptanceHorizon(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := New(WithRevokedFamilyRetentionDays(1))
		t.Cleanup(store.Stop)
		require.NoError(t, store.SaveTokenMetadata(t.Context(), "access", storage.TokenMetadata{
			UserID: "person", ClientID: "client", TokenType: "access", FamilyID: "family",
			ExpiresAt: time.Now().Add(48 * time.Hour), RetainUntil: time.Now().Add(49 * time.Hour),
		}))
		require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "family"))
		time.Sleep(48 * time.Hour)
		revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
		require.NoError(t, err)
		require.True(t, revoked)
		time.Sleep(2 * time.Hour)
		revoked, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
		require.NoError(t, err)
		require.False(t, revoked)
	})
}
