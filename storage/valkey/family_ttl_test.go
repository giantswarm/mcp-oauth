package valkey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestFamilySet_TTLExtendOnly guards the add path: the {prefix}family:{fid} SET
// was bounded with a plain EXPIRE, which RESET the TTL to the newly added
// token's horizon on every rotation. A rotation under a shortened
// RefreshTokenTTL therefore shrank the set below the metadata horizon of
// earlier members, so reuse detection still fired on a rotated-away token while
// RevokeRefreshTokenFamily walked an empty set and could never mark the family
// revoked.
func TestFamilySet_TTLExtendOnly(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		userID   = "user-fam-ttl"
		clientID = "client-fam-ttl"
		familyID = "fam-extend-only"
		longRT   = "rt-fam-long"
		shortRT  = "rt-fam-short"
	)
	now := time.Now()
	familySetKey := store.familyKey(familyID)
	const shortTTLCeil = int64(3600) + 5 // 1h horizon plus a little slack

	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, longRT, userID, clientID, familyID, 0, now.Add(30*24*time.Hour)))
	ttlAfterLong := ttlSeconds(t, store, familySetKey)
	require.Greater(t, ttlAfterLong, shortTTLCeil, "long-lived member must bound the set at its own horizon")

	// A rotation issued under a shorter horizon must not shrink the set below
	// the first member, whose family metadata still carries the long horizon.
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, shortRT, userID, clientID, familyID, 1, now.Add(time.Hour)))
	ttlAfterShort := ttlSeconds(t, store, familySetKey)
	require.Greater(t, ttlAfterShort, shortTTLCeil, "short-lived rotation must not shrink the family set")

	// Both members stay reachable, so family-wide revocation still covers them.
	tokens, err := store.getFamilyTokens(ctx, familyID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{longRT, shortRT}, tokens)
}
