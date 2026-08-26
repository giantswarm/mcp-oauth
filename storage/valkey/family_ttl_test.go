package valkey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

// shortMemberTTLCeil bounds the one-hour member horizon these tests issue, with
// a little slack: a set TTL above it can only come from a longer-lived member or
// from the retention window.
const shortMemberTTLCeil = int64(3600) + 5

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

	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, longRT, userID, clientID, familyID, 0, now.Add(30*24*time.Hour)))
	ttlAfterLong := ttlSeconds(t, store, familySetKey)
	require.Greater(t, ttlAfterLong, shortMemberTTLCeil, "long-lived member must bound the set at its own horizon")

	// A rotation issued under a shorter horizon must not shrink the set below
	// the first member, whose family metadata still carries the long horizon.
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, shortRT, userID, clientID, familyID, 1, now.Add(time.Hour)))
	ttlAfterShort := ttlSeconds(t, store, familySetKey)
	require.Greater(t, ttlAfterShort, shortMemberTTLCeil, "short-lived rotation must not shrink the family set")

	// Both members stay reachable, so family-wide revocation still covers them.
	tokens, err := store.getFamilyTokens(ctx, familyID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{longRT, shortRT}, tokens)
}

// TestRevokedFamilySet_RetainedForRetentionWindow guards the revocation path:
// markFamilyMetadataRevoked retains each member's metadata for
// RevokedFamilyRetentionDays, but nothing extended the family SET, so the
// by-family-ID index expired at the last add's horizon and the revoked signal
// decayed to not-found long before the retained metadata did.
func TestRevokedFamilySet_RetainedForRetentionWindow(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		userID   = "user-fam-revoked"
		clientID = "client-fam-revoked"
		familyID = "fam-revoked-retention"
		token    = "rt-fam-revoked"
	)
	familySetKey := store.familyKey(familyID)

	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, token, userID, clientID, familyID, 0, time.Now().Add(time.Hour)))
	require.LessOrEqual(t, ttlSeconds(t, store, familySetKey), shortMemberTTLCeil,
		"precondition: the set starts at the member horizon, well below the retention window")

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	retentionSeconds := int64((time.Duration(store.revokedFamilyRetentionDays) * 24 * time.Hour).Seconds())
	require.Greater(t, ttlSeconds(t, store, familySetKey), retentionSeconds-60,
		"revocation must hold the set for the same window as the retained member metadata")

	// The revoked signal, not merely not-found, must survive on both by-ID reads.
	meta, err := store.GetRefreshTokenFamilyByID(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.True(t, meta.Revoked)

	_, _, err = store.GetActiveRefreshTokenByFamily(ctx, familyID)
	require.ErrorIs(t, err, storage.ErrRefreshTokenFamilyRevoked)
}

// TestRevokedFamilySet_RetainsLegacyTwin covers the legacy half of the same
// index: getFamilyTokens unions the hashed and the pre-key-hashing set, so a
// family whose members were written by pre-migration pods needs the legacy key
// retained too, or its revoked signal still decays to not-found.
func TestRevokedFamilySet_RetainsLegacyTwin(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		userID   = "user-fam-legacy"
		clientID = "client-fam-legacy"
		familyID = "fam-revoked-legacy"
		token    = "rt-fam-legacy"
	)
	legacySetKey := store.legacyFamilyKey(familyID)

	// A pre-migration pod wrote the member into the legacy set and its metadata
	// under the hashed metadata key layout this store reads. The legacy write is
	// a raw SADD plus EXPIRE, the way that pod did it, not the extend-only
	// helper under test here.
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, token, userID, clientID, familyID, 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.client.Do(ctx,
		store.client.B().Sadd().Key(legacySetKey).Member(token).Build()).Error())
	require.NoError(t, store.client.Do(ctx,
		store.client.B().Expire().Key(legacySetKey).Seconds(3600).Build()).Error())

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	retentionSeconds := int64((time.Duration(store.revokedFamilyRetentionDays) * 24 * time.Hour).Seconds())
	require.Greater(t, ttlSeconds(t, store, legacySetKey), retentionSeconds-60,
		"the legacy twin backs the same by-ID index and must be retained as well")
}

// TestRevokedFamilySet_NotRetainedWithoutMetadata covers the other side of the
// retention condition: with no member metadata to mark revoked, the set indexes
// nothing, so it keeps its own member horizon instead of being held for the
// retention window.
func TestRevokedFamilySet_NotRetainedWithoutMetadata(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		familyID = "fam-no-metadata"
		token    = "rt-fam-no-metadata"
	)
	familySetKey := store.familyKey(familyID)

	// A member in the set with no family metadata behind it: the state the set
	// indexes is already gone, e.g. wiped by retention cleanup.
	require.NoError(t, store.saddExtendOnlyTTL(ctx, familySetKey, token, time.Hour))

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	require.LessOrEqual(t, ttlSeconds(t, store, familySetKey), shortMemberTTLCeil,
		"an index that points at nothing must not be held for the retention window")
}
