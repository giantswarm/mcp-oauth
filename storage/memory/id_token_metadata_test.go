package memory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// The id_token metadata key is deliberately never registered via SaveToken, so
// it is absent from every token map. These tests pin the two behaviors that
// absence would otherwise break in this backend: the orphan sweep must not
// treat a still-valid id_token entry as garbage, and bulk revocation must still
// tear it down.

func TestStore_IDTokenMetadata_SurvivesOrphanCleanupUntilExpiry(t *testing.T) {
	store := New()
	defer store.Stop()
	ctx := t.Context()

	liveIDToken := "id-token-live"
	require.NoError(t, store.SaveTokenMetadata(ctx, liveIDToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  "client-1",
		TokenType: "id",
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	expiredIDToken := "id-token-expired"
	require.NoError(t, store.SaveTokenMetadata(ctx, expiredIDToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  "client-1",
		TokenType: "id",
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	store.cleanup()

	// A still-valid id_token entry is NOT orphaned, so the bearer keeps
	// resolving its FamilyID-derived session instead of falling back to ext-.
	_, err := store.GetTokenMetadata(liveIDToken)
	require.NoError(t, err)

	// An expired id_token entry is still reclaimed by its own ExpiresAt — the
	// only mechanism that frees it in this backend — so it cannot leak forever.
	_, err = store.GetTokenMetadata(expiredIDToken)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestStore_RevokeAllTokensForUserClient_DeletesIDTokenMetadata(t *testing.T) {
	store := New()
	defer store.Stop()
	ctx := t.Context()

	accessToken := "access-token-1"
	idToken := "id-token-1"

	require.NoError(t, store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-access",
		Expiry:      time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  "client-1",
		TokenType: "access",
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SaveTokenMetadata(ctx, idToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  "client-1",
		TokenType: "id",
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	_, err := store.RevokeAllTokensForUserClient(ctx, "user-1", "client-1")
	require.NoError(t, err)

	// The id_token entry has no backing token, but reuse detection must still
	// remove it alongside its sibling access token — otherwise the revoked
	// session stays resolvable through the id_token bearer.
	_, err = store.GetTokenMetadata(idToken)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)

	_, err = store.GetTokenMetadata(accessToken)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}
