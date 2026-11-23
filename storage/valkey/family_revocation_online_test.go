package valkey

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

const testFamilyIndexPoll = 20 * time.Millisecond

func withFamilyIndexing(poll, lease time.Duration) Option {
	return func(s *Store) {
		s.familyIndexPollInterval = poll
		s.familyMigrationLease = lease
	}
}

// replica opens another store on the seed store's key prefix, as a second
// pod of the same deployment would.
func replica(t *testing.T, seed *Store, migrate bool) *Store {
	t.Helper()
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	store, err := New(Config{
		Address: addr, KeyPrefix: seed.prefix, StartupTimeout: testStartupTimeout,
		MigrateFamilyRevocations: migrate,
	}, withFamilyIndexing(testFamilyIndexPoll, time.Minute))
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store
}

// seedOldRevokedFamily writes a family revoked by a release without the
// shared marker: the member metadata says revoked, the family set does not.
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

// TestOnlineFamilyRevocationMigration: one replica backfills the index while
// serving, and a replica without the setting switches to indexed lookups once
// the index is complete. Revocations recorded only in member metadata, and
// revocations made by a current writer before the walk, stay revoked.
func TestOnlineFamilyRevocationMigration(t *testing.T) {
	seed := unindexedSeed(t)
	follower := replica(t, seed, false)
	require.False(t, follower.familyRevocationsIndexed.Load())
	require.NoError(t, follower.SaveRefreshTokenWithFamily(t.Context(), "current-refresh", "person", "client", "current", 1, time.Now().Add(time.Hour)))
	require.NoError(t, follower.RevokeRefreshTokenFamily(t.Context(), "current"))

	time.Sleep(3 * testFamilyIndexPoll)
	require.False(t, follower.familyRevocationsIndexed.Load(), "a replica without the setting must not migrate")
	require.Empty(t, indexVersion(t, seed))

	migrator := replica(t, seed, true)
	for _, store := range []*Store{migrator, follower} {
		require.Eventually(t, store.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
	}

	// Indexed lookups read only the shared marker: drop the member metadata
	// to prove the walk recorded the old revocation there.
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

// TestOnlineFamilyRevocationMigrationWaitsForLease: a replica does not walk
// while another holds the lease, and takes over once the lease is gone.
func TestOnlineFamilyRevocationMigrationWaitsForLease(t *testing.T) {
	seed := unindexedSeed(t)
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Set().Key(seed.familyMigrationLeaseKey()).Value("other-replica").Build()).Error())

	migrator := replica(t, seed, true)
	time.Sleep(5 * testFamilyIndexPoll)
	require.False(t, migrator.familyRevocationsIndexed.Load())
	require.Empty(t, indexVersion(t, seed))

	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.familyMigrationLeaseKey()).Build()).Error())
	require.Eventually(t, migrator.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
}

// TestOnlineFamilyRevocationMigrationFailsClosed: unreadable member metadata
// keeps every replica on compatibility lookups, which refuse the family, and
// the failed walk releases its lease for a retry.
func TestOnlineFamilyRevocationMigrationFailsClosed(t *testing.T) {
	seed := unindexedSeed(t)
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Sadd().Key(seed.familyKey("broken")).Member("broken-refresh").Build()).Error())
	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Set().Key(seed.refreshTokenMetaKey("broken-refresh")).Value("not-json").Build()).Error())

	migrator := replica(t, seed, true)
	time.Sleep(5 * testFamilyIndexPoll)
	require.False(t, migrator.familyRevocationsIndexed.Load())
	require.Empty(t, indexVersion(t, seed))
	_, err := migrator.IsRefreshTokenFamilyRevoked(t.Context(), "broken")
	require.Error(t, err)
	require.Eventually(t, func() bool {
		held, err := seed.client.Do(t.Context(), seed.client.B().Exists().Key(seed.familyMigrationLeaseKey()).Build()).AsInt64()
		return err == nil && held == 0
	}, time.Second, testFamilyIndexPoll)

	require.NoError(t, seed.client.Do(t.Context(), seed.client.B().Del().Key(seed.refreshTokenMetaKey("broken-refresh")).Build()).Error())
	require.Eventually(t, migrator.familyRevocationsIndexed.Load, 5*time.Second, testFamilyIndexPoll)
}

// TestPublishFamilyRevocationIndexKeepsLegacyMarkers: a walk that saw no
// legacy markers must not hide the ones another walk recorded.
func TestPublishFamilyRevocationIndexKeepsLegacyMarkers(t *testing.T) {
	store := testStore(t)
	require.NoError(t, store.publishFamilyRevocationIndex(t.Context(), true))
	require.NoError(t, store.publishFamilyRevocationIndex(t.Context(), false))
	require.Equal(t, familyRevocationIndexWithLegacyMarkers, indexVersion(t, store))
}
