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
// must outlive its longest-lived member, so a rotation issued under a shorter
// horizon may not shrink it. A shrunk set drops members whose family metadata
// is still live, and reuse detection then fires on a token that
// RevokeRefreshTokenFamily can no longer reach.
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
// the family SET is the by-family-ID index over the member metadata that
// markFamilyMetadataRevoked retains for RevokedFamilyRetentionDays, so it must
// live at least as long. An index that expires first turns the revoked signal
// into not-found.
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

// TestRevokedFamilySet_RetainedWhenMemberStateUnknown covers the fail-closed
// half of the retention condition: a member whose metadata cannot be parsed is
// neither revoked nor provably absent, so the set must still be held. Dropping
// the retention on anything short of a provably empty family would let a
// storage error shorten the index of a family that was just revoked.
func TestRevokedFamilySet_RetainedWhenMemberStateUnknown(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		familyID = "fam-unknown-state"
		token    = "rt-fam-unknown-state"
	)
	familySetKey := store.familyKey(familyID)

	require.NoError(t, store.saddExtendOnlyTTL(ctx, familySetKey, token, time.Hour))
	require.NoError(t, store.client.Do(ctx, store.client.B().Set().
		Key(store.refreshTokenMetaKey(token)).Value("not-json").
		ExSeconds(3600).Build()).Error())

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	retentionSeconds := int64((time.Duration(store.revokedFamilyRetentionDays) * 24 * time.Hour).Seconds())
	require.Greater(t, ttlSeconds(t, store, familySetKey), retentionSeconds-60,
		"a member whose state could not be established must still hold the set")
}

// TestRevokedFamily_StragglerMemberDoesNotUnrevoke guards the read side of the
// same index: the Revoked flag is per member, so a family whose members
// disagree must still read as revoked. A rotation that races
// RevokeRefreshTokenFamily, or a member whose revoked write failed, leaves a
// non-revoked member beside the revoked ones, and returning that member would
// re-admit the tokens the revocation was called to kill.
func TestRevokedFamily_StragglerMemberDoesNotUnrevoke(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		userID    = "user-fam-straggler"
		clientID  = "client-fam-straggler"
		familyID  = "fam-straggler"
		revokedRT = "rt-fam-straggler-revoked"
		liveRT    = "rt-fam-straggler-live"
	)

	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, revokedRT, userID, clientID, familyID, 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	// The racing rotation: a member written after the revocation walk passed.
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, liveRT, userID, clientID, familyID, 1, time.Now().Add(time.Hour)))

	meta, err := store.GetRefreshTokenFamilyByID(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.True(t, meta.Revoked, "one revoked member revokes the family")

	_, _, err = store.GetActiveRefreshTokenByFamily(ctx, familyID)
	require.ErrorIs(t, err, storage.ErrRefreshTokenFamilyRevoked,
		"the straggler must not be handed back as the family's active token")
}

// TestUnrevokedFamily_HighestGenerationIsActive guards the other direction of
// that rule: with no revoked member, GetActiveRefreshTokenByFamily still hands
// back the latest rotation.
func TestUnrevokedFamily_HighestGenerationIsActive(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()

	const (
		userID   = "user-fam-active"
		clientID = "client-fam-active"
		familyID = "fam-active-unrevoked"
		firstRT  = "rt-fam-active-gen0"
		latestRT = "rt-fam-active-gen1"
	)

	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, firstRT, userID, clientID, familyID, 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, latestRT, userID, clientID, familyID, 1, time.Now().Add(time.Hour)))

	token, gotClientID, err := store.GetActiveRefreshTokenByFamily(ctx, familyID)
	require.NoError(t, err)
	require.Equal(t, latestRT, token)
	require.Equal(t, clientID, gotClientID)
}
