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
