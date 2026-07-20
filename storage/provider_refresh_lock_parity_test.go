package storage_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TestProviderRefreshLock_BackendParity verifies that the memory and valkey
// backends implement storage.ProviderRefreshLockStore identically: a per-user
// single-flight try-lock with TTL self-expiry and an owner-only release.
//
// This is the lock half of the rotation-race fix
// (giantswarm/giantswarm#37164 root cause 2, mcp-oauth#513).
func TestProviderRefreshLock_BackendParity(t *testing.T) {
	backends := []struct {
		name    string
		factory func(t *testing.T) storage.Combined
	}{
		{name: storage.BackendMemory, factory: newMemoryBackend},
		{name: storage.BackendValkey, factory: newValkeyBackend},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("held_lock_excludes_second_acquire", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				lockValue, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-a", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired)
				require.NotEmpty(t, lockValue)

				_, acquired2, err := s.AcquireProviderRefreshLock(ctx, "user-a", time.Minute)
				require.NoError(t, err)
				require.False(t, acquired2, "a held lock must exclude a second acquirer")
			})

			t.Run("locks_are_per_user", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				_, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-a", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired)

				_, acquired, err = s.AcquireProviderRefreshLock(ctx, "user-b", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired, "one user's refresh lock must not block another user")
			})

			t.Run("owner_release_frees_the_lock", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				lockValue, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-rel", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired)

				require.NoError(t, s.ReleaseProviderRefreshLock(ctx, "user-rel", lockValue))

				_, acquired, err = s.AcquireProviderRefreshLock(ctx, "user-rel", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired, "the lock must be free after its owner released it")
			})

			t.Run("owner_only_release_ignores_wrong_value", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				_, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-cad", time.Minute)
				require.NoError(t, err)
				require.True(t, acquired)

				// A slow previous holder presenting a stale value must not
				// release the current holder's lock.
				require.NoError(t, s.ReleaseProviderRefreshLock(ctx, "user-cad", "stale-value-of-previous-holder"))

				_, acquired, err = s.AcquireProviderRefreshLock(ctx, "user-cad", time.Minute)
				require.NoError(t, err)
				require.False(t, acquired, "a wrong-value release must leave the lock held")
			})

			t.Run("release_of_missing_lock_is_a_noop", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))

				require.NoError(t, s.ReleaseProviderRefreshLock(t.Context(), "user-never-locked", "any-value"))
			})

			t.Run("crashed_holder_lock_expires_via_ttl", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				// Simulated crash: acquire with a tiny TTL and never release.
				_, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-crash", 20*time.Millisecond)
				require.NoError(t, err)
				require.True(t, acquired)

				// The system self-heals: once the TTL elapses the next
				// acquire succeeds without any release.
				require.Eventually(t, func() bool {
					_, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-crash", time.Minute)
					return err == nil && acquired
				}, 2*time.Second, 5*time.Millisecond, "an expired lock must become acquirable")
			})

			t.Run("exactly_one_of_n_concurrent_acquirers_wins", func(t *testing.T) {
				s := requireProviderRefreshLockStore(t, b.factory(t))
				ctx := t.Context()

				const n = 16
				start := make(chan struct{})
				wins := make(chan string, n)
				var wg sync.WaitGroup
				for range n {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						lockValue, acquired, err := s.AcquireProviderRefreshLock(ctx, "user-conc", time.Minute)
						require.NoError(t, err)
						if acquired {
							wins <- lockValue
						}
					}()
				}
				close(start)
				wg.Wait()
				close(wins)

				var values []string
				for v := range wins {
					values = append(values, v)
				}
				require.Len(t, values, 1, "exactly one concurrent acquirer must win the lock")
			})
		})
	}
}

// requireProviderRefreshLockStore asserts the backend implements the optional
// per-user refresh lock interface.
func requireProviderRefreshLockStore(t *testing.T, s storage.Combined) storage.ProviderRefreshLockStore {
	t.Helper()
	locker, ok := s.(storage.ProviderRefreshLockStore)
	require.True(t, ok, "backend must implement storage.ProviderRefreshLockStore")
	return locker
}
