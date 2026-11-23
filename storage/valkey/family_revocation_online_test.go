package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

const testFamilyIndexPoll = 20 * time.Millisecond

func withFamilyIndexing(poll, lease time.Duration) Option {
	return func(s *Store) {
		s.familyIndexPollInterval = poll
		s.familyMigrationLease = lease
	}
}

func replica(t *testing.T, seed *Store, migrate bool, options ...Option) *Store {
	t.Helper()
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	store, err := New(Config{
		Address: addr, KeyPrefix: seed.prefix, StartupTimeout: testStartupTimeout,
		MigrateFamilyRevocationIndex: migrate,
	}, append([]Option{withFamilyIndexing(testFamilyIndexPoll, time.Minute)}, options...)...)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store
}

func seedOldRevokedFamily(t *testing.T, store *Store, familyID, member string) {
	t.Helper()
	metadata, err := json.Marshal(toRefreshTokenFamilyJSON(&storage.RefreshTokenFamilyMetadata{
		FamilyID: familyID, UserID: "person", ClientID: "client", Revoked: true,
	}))
	require.NoError(t, err)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(store.refreshTokenMetaKey(member)).Value(string(metadata)).Build()).Error())
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(store.familyKey(familyID)).Member(member).Build()).Error())
}

func unindexedSeed(t *testing.T) *Store {
	t.Helper()
	seed := testStore(t)
	seedOldRevokedFamily(t, seed, "old-revoked", "old-refresh")
	require.NoError(t, seed.SaveRefreshTokenWithFamily(t.Context(), "live-refresh", "person", "client", "live", 1, time.Now().Add(time.Hour)))
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.familyRevocationIndexKey()).Build()).Error())
	return seed
}

func indexVersion(t *testing.T, store *Store) string {
	t.Helper()
	version, err := store.client.Do(t.Context(), store.client.B().Get().Key(store.familyRevocationIndexKey()).Build()).ToString()
	if isNilError(err) {
		return ""
	}
	require.NoError(t, err)
	return version
}

func TestOnlineFamilyRevocationMigration(t *testing.T) {
	seed := unindexedSeed(t)
	follower := replica(t, seed, false)
	require.False(t, follower.familyRevocationsIndexed.Load())
	require.NoError(t, follower.SaveRefreshTokenWithFamily(t.Context(), "current-refresh", "person", "client", "current", 1, time.Now().Add(time.Hour)))
	require.NoError(t, follower.RevokeRefreshTokenFamily(t.Context(), "current"))

	require.Never(t, follower.familyRevocationsIndexed.Load, 3*testFamilyIndexPoll, testFamilyIndexPoll)
	require.Empty(t, indexVersion(t, seed))

	migrator := replica(t, seed, true)
	for _, store := range []*Store{migrator, follower} {
		require.Eventually(t, store.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
	}

	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.refreshTokenMetaKey("old-refresh")).Build()).Error())
	for _, store := range []*Store{migrator, follower} {
		for family, want := range map[string]bool{"old-revoked": true, "current": true, "live": false} {
			revoked, err := store.IsRefreshTokenFamilyRevoked(t.Context(), family)
			require.NoError(t, err)
			require.Equal(t, want, revoked, family)
		}
	}
	held, err := seed.client.Do(t.Context(), seed.client.B().Exists().Key(seed.familyMigrationLeaseKey()).Build()).AsInt64()
	require.NoError(t, err)
	require.Zero(t, held, "the migrator must release its lease")
}

func TestOnlineFamilyRevocationMigrationWaitsForLease(t *testing.T) {
	seed := unindexedSeed(t)
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Set().Key(seed.familyMigrationLeaseKey()).Value("other-replica").Build()).Error())

	migrator := replica(t, seed, true)
	require.Never(t, migrator.familyRevocationsIndexed.Load, 5*testFamilyIndexPoll, testFamilyIndexPoll)
	require.Empty(t, indexVersion(t, seed))

	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.familyMigrationLeaseKey()).Build()).Error())
	require.Eventually(t, migrator.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
}

func TestOnlineFamilyRevocationMigrationFailsClosed(t *testing.T) {
	seed := unindexedSeed(t)
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Sadd().Key(seed.familyKey("broken")).Member("broken-refresh").Build()).Error())
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Set().Key(seed.refreshTokenMetaKey("broken-refresh")).Value("not-json").Build()).Error())

	follower := replica(t, seed, false)
	published, err := follower.migrateFamilyRevocationsUnderLease(t.Context())
	require.Error(t, err)
	require.False(t, published)
	held, err := seed.client.Do(t.Context(), seed.client.B().Exists().Key(seed.familyMigrationLeaseKey()).Build()).AsInt64()
	require.NoError(t, err)
	require.Zero(t, held)

	migrator := replica(t, seed, true)
	require.Never(t, migrator.familyRevocationsIndexed.Load, 5*testFamilyIndexPoll, testFamilyIndexPoll)
	require.False(t, migrator.familyRevocationsIndexed.Load())
	require.Empty(t, indexVersion(t, seed))
	_, err = migrator.IsRefreshTokenFamilyRevoked(t.Context(), "broken")
	require.Error(t, err)

	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.refreshTokenMetaKey("broken-refresh")).Build()).Error())
	require.Eventually(t, migrator.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
}

func TestPublishFamilyRevocationIndexKeepsLegacyMarkers(t *testing.T) {
	store := testStore(t)
	require.NoError(t, store.publishFamilyRevocationIndexState(t.Context(), true))
	require.NoError(t, store.publishFamilyRevocationIndexState(t.Context(), false))
	require.Equal(t, familyRevocationIndexWithLegacyChecks, indexVersion(t, store))
	require.NoError(t, store.completeFamilyRevocationIndex(t.Context()))
	require.True(t, store.checkLegacyFamilyMarkers.Load())
}

type familyMigrationTestClient struct {
	valkeygo.Client
	mode  valkeygo.ClientMode
	after func(context.Context, []string)
}

func (client *familyMigrationTestClient) Mode() valkeygo.ClientMode {
	if client.mode != "" {
		return client.mode
	}
	return client.Client.Mode()
}

func (client *familyMigrationTestClient) Nodes() map[string]valkeygo.Client {
	nodes := client.Client.Nodes()
	for address, node := range nodes {
		nodes[address] = &familyMigrationTestClient{Client: node, mode: client.mode, after: client.after}
	}
	return nodes
}

func (client *familyMigrationTestClient) Do(ctx context.Context, command valkeygo.Completed) valkeygo.ValkeyResult {
	arguments := slices.Clone(command.Commands())
	result := client.Client.Do(ctx, command)
	if client.after != nil {
		client.after(ctx, arguments)
	}
	return result
}

func TestOnlineFamilyRevocationMigrationRequiresStandalone(t *testing.T) {
	for _, mode := range []valkeygo.ClientMode{valkeygo.ClientModeCluster, valkeygo.ClientModeSentinel} {
		t.Run(string(mode), func(t *testing.T) {
			seed := unindexedSeed(t)
			seed.familyRevocationsIndexed.Store(false)
			seed.client = &familyMigrationTestClient{Client: seed.client, mode: mode}
			published, err := seed.migrateFamilyRevocationsUnderLease(t.Context())
			require.ErrorIs(t, err, errOnlineFamilyMigrationRequiresStandalone)
			require.False(t, published)
			require.Empty(t, indexVersion(t, seed))
			revoked, err := seed.IsRefreshTokenFamilyRevoked(t.Context(), "old-revoked")
			require.NoError(t, err)
			require.True(t, revoked)

			address := os.Getenv("VALKEY_TEST_ADDR")
			if address == "" {
				address = "localhost:6379"
			}
			store, err := New(Config{Address: address, KeyPrefix: seed.prefix, MigrateFamilyRevocationIndex: true}, func(store *Store) {
				store.client = &familyMigrationTestClient{Client: store.client, mode: mode}
			})
			require.ErrorIs(t, err, errOnlineFamilyMigrationRequiresStandalone)
			require.Nil(t, store)
		})
	}
	if address := os.Getenv("VALKEY_CLUSTER_TEST_ADDR"); address != "" {
		t.Run("live-cluster", func(t *testing.T) {
			store, err := New(Config{Address: address, MigrateFamilyRevocationIndex: true})
			require.ErrorIs(t, err, errOnlineFamilyMigrationRequiresStandalone)
			require.Nil(t, store)
		})
	}
}

func TestFamilyMigrationLeaseExpiryAndReplacement(t *testing.T) {
	store := testStore(t)
	holder, acquired, err := store.acquireFamilyMigrationLease(t.Context())
	require.NoError(t, err)
	require.True(t, acquired)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Pexpire().Key(store.familyMigrationLeaseKey()).Milliseconds(1).Build()).Error())
	require.Eventually(t, func() bool {
		held, err := store.client.Do(t.Context(), store.client.B().Exists().Key(store.familyMigrationLeaseKey()).Build()).AsInt64()
		return err == nil && held == 0
	}, time.Second, testFamilyIndexPoll)
	replacement, acquired, err := store.acquireFamilyMigrationLease(t.Context())
	require.NoError(t, err)
	require.True(t, acquired)
	require.NotEqual(t, holder, replacement)
	store.releaseFamilyMigrationLease(holder)
	actual, err := store.client.Do(t.Context(), store.client.B().Get().Key(store.familyMigrationLeaseKey()).Build()).ToString()
	require.NoError(t, err)
	require.Equal(t, replacement, actual)
	store.releaseFamilyMigrationLease(replacement)
	held, err := store.client.Do(t.Context(), store.client.B().Exists().Key(store.familyMigrationLeaseKey()).Build()).AsInt64()
	require.NoError(t, err)
	require.Zero(t, held)
}

func TestOnlineFamilyRevocationMigrationPreservesConcurrentRevocation(t *testing.T) {
	seed := unindexedSeed(t)
	writer := replica(t, seed, false)
	scanned, resume := make(chan struct{}), make(chan struct{}, 1)
	defer close(resume)
	var once sync.Once
	seed.client = &familyMigrationTestClient{Client: seed.client, after: func(ctx context.Context, arguments []string) {
		if arguments[0] == "SCAN" {
			once.Do(func() {
				close(scanned)
				select {
				case <-resume:
				case <-ctx.Done():
				}
			})
		}
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := seed.migrateFamilyRevocationsUnderLease(ctx)
		result <- err
	}()
	require.Eventually(t, func() bool { return channelClosed(scanned) }, time.Second, testFamilyIndexPoll)
	require.NoError(t, writer.SaveRefreshTokenWithFamily(t.Context(), "concurrent-refresh", "person", "client", "concurrent", 1, time.Now().Add(time.Hour)))
	require.NoError(t, writer.RevokeRefreshTokenFamily(t.Context(), "concurrent"))
	resume <- struct{}{}
	require.Eventually(t, func() bool { return len(result) == 1 }, time.Second, testFamilyIndexPoll)
	require.NoError(t, <-result)
	indexed, err := seed.loadFamilyRevocationIndexState(t.Context())
	require.NoError(t, err)
	require.True(t, indexed)
	for _, family := range []string{"old-revoked", "concurrent"} {
		revoked, err := seed.IsRefreshTokenFamilyRevoked(t.Context(), family)
		require.NoError(t, err)
		require.True(t, revoked)
	}
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func TestOnlineFamilyRevocationMigrationClose(t *testing.T) {
	for _, waitingForLease := range []bool{false, true} {
		t.Run(map[bool]string{false: "active-walk", true: "waiting-for-lease"}[waitingForLease], func(t *testing.T) {
			seed := unindexedSeed(t)
			observer := replica(t, seed, false)
			t.Cleanup(func() {
				seed.stopFamilyRevocationIndexing()
				address := os.Getenv("VALKEY_TEST_ADDR")
				if address == "" {
					address = "localhost:6379"
				}
				client, err := valkeygo.NewClient(buildClientOpts(Config{Address: address}, seed.operationTimeout))
				require.NoError(t, err)
				seed.client = client
			})
			if waitingForLease {
				require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Set().Key(seed.familyMigrationLeaseKey()).Value("other-holder").Build()).Error())
			}
			started := make(chan struct{})
			var once sync.Once
			seed.client = &familyMigrationTestClient{Client: seed.client, after: func(ctx context.Context, arguments []string) {
				if arguments[0] == "SCAN" && ctx.Done() != nil || waitingForLease && arguments[0] == "SET" && arguments[1] == seed.familyMigrationLeaseKey() {
					once.Do(func() { close(started) })
					if !waitingForLease {
						<-ctx.Done()
					}
				}
			}}
			seed.familyRevocationsIndexed.Store(false)
			seed.startFamilyRevocationIndexing(true)
			require.Eventually(t, func() bool { return channelClosed(started) }, time.Second, testFamilyIndexPoll)
			closed := make(chan struct{})
			go func() {
				seed.Close()
				close(closed)
			}()
			require.Eventually(t, func() bool { return channelClosed(closed) }, time.Second, testFamilyIndexPoll)
			require.True(t, channelClosed(seed.backgroundDone))
			require.Empty(t, indexVersion(t, observer))
			holder, err := observer.client.Do(t.Context(), observer.client.B().Get().Key(observer.familyMigrationLeaseKey()).Build()).ToString()
			if waitingForLease {
				require.NoError(t, err)
				require.Equal(t, "other-holder", holder)
			} else {
				require.True(t, isNilError(err))
			}
		})
	}
}

func TestOnlineFamilyRevocationMigrationDeadlineStopsRetries(t *testing.T) {
	seed := unindexedSeed(t)
	seed.familyRevocationsIndexed.Store(false)
	seed.familyIndexPollInterval = testFamilyIndexPoll
	seed.familyMigrationLease = 100 * time.Millisecond
	var scans atomic.Int64
	seed.client = &familyMigrationTestClient{Client: seed.client, after: func(ctx context.Context, arguments []string) {
		if arguments[0] == "SCAN" && ctx.Done() != nil && scans.Add(1) == 1 {
			<-ctx.Done()
		}
	}}
	seed.startFamilyRevocationIndexing(true)
	require.Eventually(t, func() bool { return scans.Load() == 1 }, time.Second, testFamilyIndexPoll)
	require.Eventually(t, func() bool {
		held, err := seed.client.Do(t.Context(), seed.client.B().Exists().Key(seed.familyMigrationLeaseKey()).Build()).AsInt64()
		return err == nil && held == 0
	}, time.Second, testFamilyIndexPoll)
	require.Never(t, func() bool { return scans.Load() > 1 }, 10*testFamilyIndexPoll, testFamilyIndexPoll)
	require.False(t, seed.familyRevocationsIndexed.Load())
	require.Empty(t, indexVersion(t, seed))
	maintenance := replica(t, seed, false)
	require.NoError(t, maintenance.MigrateFamilyRevocations(t.Context()))
	require.Eventually(t, func() bool { return channelClosed(seed.backgroundDone) }, time.Second, testFamilyIndexPoll)
}

func TestStoppedFamilyMigrationCancelsBackgroundWorker(t *testing.T) {
	seed := unindexedSeed(t)
	seed.familyRevocationsIndexed.Store(false)
	started := make(chan struct{})
	var once sync.Once
	seed.client = &familyMigrationTestClient{Client: seed.client, after: func(ctx context.Context, arguments []string) {
		if arguments[0] == "SCAN" && ctx.Done() != nil {
			once.Do(func() {
				close(started)
				<-ctx.Done()
			})
		}
	}}
	seed.startFamilyRevocationIndexing(true)
	require.Eventually(t, func() bool { return channelClosed(started) }, time.Second, testFamilyIndexPoll)
	require.NoError(t, seed.MigrateFamilyRevocations(t.Context()))
	require.True(t, channelClosed(seed.backgroundDone))
	revoked, err := seed.IsRefreshTokenFamilyRevoked(t.Context(), "old-revoked")
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestFamilyRevocationRecoveryRebuildsCompletedIndex(t *testing.T) {
	seed := testStore(t)
	require.NoError(t, seed.completeFamilyRevocationIndex(t.Context()))
	seedOldRevokedFamily(t, seed, "rollback-revoked", "rollback-refresh")
	before := replica(t, seed, true)
	revoked, err := before.IsRefreshTokenFamilyRevoked(t.Context(), "rollback-revoked")
	require.NoError(t, err)
	require.False(t, revoked)
	before.Close()
	require.NoError(t, seed.MigrateFamilyRevocations(t.Context()))
	after := replica(t, seed, true)
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.refreshTokenMetaKey("rollback-refresh")).Build()).Error())
	revoked, err = after.IsRefreshTokenFamilyRevoked(t.Context(), "rollback-revoked")
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestFamilyRevocationMigrationBatchesMetadata(t *testing.T) {
	store := testStore(t)
	for index := range 100 {
		require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), fmt.Sprintf("refresh-%d", index), "person", "client", "family", index, time.Now().Add(time.Hour)))
	}
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Sadd().Key(store.familyKey("family")).Member(familyRevocationMarker).Build()).Error())
	client := &countingFamilyClient{Client: store.client}
	store.client = client
	legacy, err := store.indexFamilyRevocation(t.Context(), store.familyKey("family"))
	require.NoError(t, err)
	require.True(t, legacy)
	require.EqualValues(t, 3, client.commands.Load())
}
