package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

type countingFamilyClient struct {
	valkeygo.Client
	commands atomic.Int64
}

type familyNodeClient struct {
	valkeygo.Client
	nodes map[string]valkeygo.Client
}

func (client *familyNodeClient) Nodes() map[string]valkeygo.Client {
	return client.nodes
}

func (client *countingFamilyClient) Do(ctx context.Context, command valkeygo.Completed) valkeygo.ValkeyResult {
	client.commands.Add(1)
	return client.Client.Do(ctx, command)
}

// DoMulti sends its commands as one pipelined batch: one round trip.
func (client *countingFamilyClient) DoMulti(ctx context.Context, commands ...valkeygo.Completed) []valkeygo.ValkeyResult {
	client.commands.Add(1)
	return client.Client.DoMulti(ctx, commands...)
}

// TestUnindexedFamilyLookupHasConstantRoundTrips: before the revocation index
// is migrated, the family check reads every member's metadata. Those reads are
// batched, so the round trips do not grow with the family, and a long-lived
// family resolves within the per-operation deadline.
func TestUnindexedFamilyLookupHasConstantRoundTrips(t *testing.T) {
	const maxRoundTrips = 4 // two member sets, current-layout batch, legacy batch
	for _, generations := range []int{1, 1000} {
		t.Run(fmt.Sprint(generations), func(t *testing.T) {
			store := testStore(t)
			store.familyRevocationsIndexed.Store(false)
			for generation := range generations {
				require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), fmt.Sprintf("refresh-%d", generation),
					"person", "client", "family", generation, time.Now().Add(time.Hour)))
			}
			// The oldest member was written by a pre-migration pod.
			moveToLegacyMetadataKey(t, store, "refresh-0")
			client := &countingFamilyClient{Client: store.client}
			store.client = client

			revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.False(t, revoked)
			require.LessOrEqual(t, client.commands.Load(), int64(maxRoundTrips))

			client.commands.Store(0)
			token, _, err := store.GetActiveRefreshTokenByFamily(t.Context(), "family")
			require.NoError(t, err)
			require.Equal(t, fmt.Sprintf("refresh-%d", generations-1), token)
			require.LessOrEqual(t, client.commands.Load(), int64(maxRoundTrips))

			// A revoked member, here the legacy one, revokes the family.
			setMemberMetadata(t, store, store.legacyRefreshTokenMetaKey("refresh-0"), true)
			client.commands.Store(0)
			revoked, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.True(t, revoked)
			require.LessOrEqual(t, client.commands.Load(), int64(maxRoundTrips))
			_, _, err = store.GetActiveRefreshTokenByFamily(t.Context(), "family")
			require.ErrorIs(t, err, storage.ErrRefreshTokenFamilyRevoked)
		})
	}
}

// TestUnindexedFamilyLookupFailsClosedOnLegacyReadError: a member whose legacy
// metadata cannot be read leaves the family check failing, never "not revoked".
func TestUnindexedFamilyLookupFailsClosedOnLegacyReadError(t *testing.T) {
	store := testStore(t)
	store.familyRevocationsIndexed.Store(false)
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh", "person", "client", "family", 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(store.refreshTokenMetaKey("refresh")).Build()).Error())
	// A key of the wrong type makes the GET fail with a server error.
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(store.legacyRefreshTokenMetaKey("refresh")).Member("x").Build()).Error())
	_, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
	require.Error(t, err)
}

func moveToLegacyMetadataKey(t *testing.T, store *Store, refreshToken string) {
	t.Helper()
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Rename().
		Key(store.refreshTokenMetaKey(refreshToken)).Newkey(store.legacyRefreshTokenMetaKey(refreshToken)).Build()).Error())
}

func setMemberMetadata(t *testing.T, store *Store, key string, revoked bool) {
	t.Helper()
	metadata, err := json.Marshal(toRefreshTokenFamilyJSON(&storage.RefreshTokenFamilyMetadata{
		FamilyID: "family", UserID: "person", ClientID: "client", Revoked: revoked,
	}))
	require.NoError(t, err)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(key).Value(string(metadata)).Build()).Error())
}

func TestFamilyRevocationLookupHasConstantCost(t *testing.T) {
	for _, generations := range []int{1, 100, 1000} {
		t.Run(fmt.Sprint(generations), func(t *testing.T) {
			store := testStore(t)
			for generation := range generations {
				require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), fmt.Sprintf("refresh-%d", generation),
					"person", "client", "family", generation, time.Now().Add(time.Hour)))
			}
			client := &countingFamilyClient{Client: store.client}
			store.client = client
			revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.False(t, revoked)
			require.EqualValues(t, 1, client.commands.Load())
			require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "family"))
			client.commands.Store(0)
			revoked, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.True(t, revoked)
			require.EqualValues(t, 1, client.commands.Load())
		})
	}
}

func TestFamilyRevocationMigrationPreservesBothLayouts(t *testing.T) {
	for _, test := range []struct{ legacy, permanent bool }{{}, {legacy: true}, {permanent: true}, {legacy: true, permanent: true}} {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			store := testStore(t)
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(store.familyRevocationIndexKey()).Build()).Error())
			familyKey, metadataKey := store.familyKey("family"), store.refreshTokenMetaKey("old-refresh")
			if test.legacy {
				familyKey, metadataKey = store.legacyFamilyKey("family"), store.legacyRefreshTokenMetaKey("old-refresh")
			}
			metadata, err := json.Marshal(toRefreshTokenFamilyJSON(&storage.RefreshTokenFamilyMetadata{
				FamilyID: "family", UserID: "person", ClientID: "client", Revoked: true,
			}))
			require.NoError(t, err)
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(metadataKey).Value(string(metadata)).Build()).Error())
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(familyKey).Member("old-refresh").Build()).Error())
			if !test.permanent {
				require.NoError(t, store.client.Do(t.Context(), store.client.B().Pexpire().Key(familyKey).Milliseconds((120*24*time.Hour).Milliseconds()).Build()).Error())
			}
			store.familyRevocationsIndexed.Store(false)
			require.NoError(t, store.initializeFamilyRevocationIndex(t.Context()))
			require.False(t, store.familyRevocationsIndexed.Load())
			revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.True(t, revoked)
			require.NoError(t, store.MigrateFamilyRevocations(t.Context()))
			require.NoError(t, store.MigrateFamilyRevocations(t.Context()))
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(metadataKey).Build()).Error())
			revoked, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
			require.NoError(t, err)
			require.True(t, revoked)
			remaining, err := store.client.Do(t.Context(), store.client.B().Ttl().Key(store.familyKey("family")).Build()).AsInt64()
			require.NoError(t, err)
			if test.permanent {
				require.EqualValues(t, -1, remaining)
			} else {
				require.Greater(t, remaining, int64((119*24*time.Hour)/time.Second))
			}
			store.familyRevocationsIndexed.Store(false)
			require.NoError(t, store.initializeFamilyRevocationIndex(t.Context()))
			require.True(t, store.familyRevocationsIndexed.Load())
		})
	}
}

func TestFamilyRevocationMigrationFailsClosed(t *testing.T) {
	store := testStore(t)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(store.familyKey("family")).Member("broken").Build()).Error())
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(store.refreshTokenMetaKey("broken")).Value("not-json").Build()).Error())
	require.Error(t, store.MigrateFamilyRevocations(t.Context()))
	require.False(t, store.familyRevocationsIndexed.Load())
	ready, err := store.client.Do(t.Context(), store.client.B().Exists().Key(store.familyRevocationIndexKey()).Build()).AsInt64()
	require.NoError(t, err)
	require.Zero(t, ready)
	_, err = store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
	require.Error(t, err)
	require.False(t, errors.Is(err, storage.ErrRefreshTokenFamilyNotFound))
}

func TestFamilyRevocationMigrationScansEveryNode(t *testing.T) {
	store := testStore(t)
	first := &countingFamilyClient{Client: store.client}
	second := &countingFamilyClient{Client: store.client}
	store.client = &familyNodeClient{Client: store.client, nodes: map[string]valkeygo.Client{"first": first, "second": second}}
	require.NoError(t, store.MigrateFamilyRevocations(t.Context()))
	require.Positive(t, first.commands.Load())
	require.Positive(t, second.commands.Load())
}

func TestFamilyRevocationMigrationRequiresAvailableNodes(t *testing.T) {
	store := testStore(t)
	store.client = &familyNodeClient{Client: store.client}
	require.Error(t, store.MigrateFamilyRevocations(t.Context()))
	require.False(t, store.familyRevocationsIndexed.Load())
}

func TestFamilyRevocationMigrationTreatsPrefixAsLiteral(t *testing.T) {
	store := testStore(t)
	store.prefix += "[tenant]*?\\:"
	familyKey := store.legacyFamilyKey("family")
	metadataKey := store.legacyRefreshTokenMetaKey("refresh")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), storage.DefaultOperationTimeout)
		defer cancel()
		require.NoError(t, store.client.Do(ctx, store.client.B().Del().
			Key(familyKey, metadataKey, store.familyKey("family"), store.familyRevocationIndexKey()).Build()).Error())
	})
	metadata, err := json.Marshal(toRefreshTokenFamilyJSON(&storage.RefreshTokenFamilyMetadata{
		FamilyID: "family", UserID: "person", ClientID: "client", Revoked: true,
	}))
	require.NoError(t, err)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(metadataKey).Value(string(metadata)).Build()).Error())
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(familyKey).Member("refresh").Build()).Error())
	store.familyRevocationsIndexed.Store(false)
	require.NoError(t, store.initializeFamilyRevocationIndex(t.Context()))
	require.False(t, store.familyRevocationsIndexed.Load())
	require.NoError(t, store.MigrateFamilyRevocations(t.Context()))
	revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestFamilyRevocationMigrationPreservesMarkerWithoutMembers(t *testing.T) {
	store := testStore(t)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(store.legacyFamilyKey("family")).Member(familyRevocationMarker).Build()).Error())
	require.NoError(t, store.MigrateFamilyRevocations(t.Context()))
	revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), "family")
	require.NoError(t, err)
	require.True(t, revoked)
}
