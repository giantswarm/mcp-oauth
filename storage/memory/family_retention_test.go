package memory

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestFamilyRevocationRetainsAccessAcceptanceHorizon(t *testing.T) {
	store := New(WithRevokedFamilyRetentionDays(1))
	t.Cleanup(store.Stop)
	now := time.Now()
	accessExpiry := now.Add(48 * time.Hour)
	retainUntil := accessExpiry.Add(5 * time.Minute)
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "long-lived-access", storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access", FamilyID: "family",
		ExpiresAt: accessExpiry, RetainUntil: retainUntil,
	}))
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "short-lived-refresh", "person", "client", "family", 0, now.Add(time.Hour)))
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "shorter-access", storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access", FamilyID: "family",
		ExpiresAt: now.Add(2 * time.Hour), RetainUntil: now.Add(time.Hour),
	}))
	_, err := store.RevokeTokensForFamily(t.Context(), "person", "client", "family")
	require.NoError(t, err)
	_, err = store.GetTokenMetadata("long-lived-access")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)

	store.mu.Lock()
	store.refreshTokenFamilies["short-lived-refresh"].RevokedAt = now.Add(-48 * time.Hour)
	horizon := store.familyRetainUntil["family"]
	cleaned := store.cleanupRevokedFamilies()
	store.mu.Unlock()
	require.Equal(t, retainUntil, horizon)
	require.Zero(t, cleaned)
	family, err := store.GetRefreshTokenFamilyByID(t.Context(), "family")
	require.NoError(t, err)
	require.True(t, family.Revoked)

	store.mu.Lock()
	store.familyRetainUntil["family"] = now.Add(-time.Minute)
	cleaned = store.cleanupRevokedFamilies()
	horizonsCleaned := store.cleanupExpiredFamilyRetention()
	store.mu.Unlock()
	require.Equal(t, 1, cleaned)
	require.Equal(t, 1, horizonsCleaned)
	_, err = store.GetRefreshTokenFamilyByID(t.Context(), "family")
	require.ErrorIs(t, err, storage.ErrRefreshTokenFamilyNotFound)
}

func TestFamilyRevocationHonorsConfiguredRetentionBeyondAcceptance(t *testing.T) {
	store := New(WithRevokedFamilyRetentionDays(2))
	t.Cleanup(store.Stop)
	now := time.Now()
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh", "person", "client", "family", 0, now.Add(time.Hour)))
	require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "family"))

	store.mu.Lock()
	store.familyRetainUntil["family"] = now.Add(-time.Minute)
	store.refreshTokenFamilies["refresh"].RevokedAt = now.Add(-24 * time.Hour)
	cleaned := store.cleanupRevokedFamilies()
	horizonsCleaned := store.cleanupExpiredFamilyRetention()
	store.mu.Unlock()
	require.Zero(t, cleaned)
	require.Equal(t, 1, horizonsCleaned)
	family, err := store.GetRefreshTokenFamilyByID(t.Context(), "family")
	require.NoError(t, err)
	require.True(t, family.Revoked)
}

func TestFamilyRetentionBoundsUnfinishedIssuanceState(t *testing.T) {
	store := New()
	t.Cleanup(store.Stop)
	now := time.Now()
	store.mu.Lock()
	for index := range hardMaxFamilyMetadataEntries {
		store.familyRetainUntil[strconv.Itoa(index)] = now.Add(time.Hour)
	}
	store.mu.Unlock()
	metadata := storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access", FamilyID: "new-family", ExpiresAt: now.Add(time.Hour),
	}
	require.ErrorContains(t, store.SaveTokenMetadata(t.Context(), "new-access", metadata), "retention limit exceeded")
	_, err := store.GetTokenMetadata("new-access")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	metadata.FamilyID = "0"
	metadata.ExpiresAt = now.Add(2 * time.Hour)
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "existing-family-access", metadata))

	store.mu.Lock()
	store.familyRetainUntil["1"] = now.Add(-time.Minute)
	cleaned := store.cleanupExpiredFamilyRetention()
	store.mu.Unlock()
	require.Equal(t, 1, cleaned)
	metadata.FamilyID = "new-family"
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "new-access", metadata))
}
