package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// ============================================================
// ProviderRefreshLockStore Implementation
// ============================================================
//
// The per-user provider-refresh lock is an in-process try-lock: a map entry
// (userID -> value+deadline) guarded by s.mu. That is sufficient here — the
// memory backend is single-process by definition — while presenting the same
// acquire/release semantics as the cross-pod Valkey implementation so the
// coordination layer and the parity tests treat both identically.

// providerRefreshLock is one held per-user lock: the owner's random value and
// the instant the lock self-expires.
type providerRefreshLock struct {
	value     string
	expiresAt time.Time
}

// AcquireProviderRefreshLock attempts to acquire the per-user refresh lock
// (storage.ProviderRefreshLockStore). A held, unexpired lock makes the
// attempt fail with acquired=false; an expired one is silently replaced so a
// crashed holder self-heals.
func (s *Store) AcquireProviderRefreshLock(_ context.Context, userID string, ttl time.Duration) (string, bool, error) {
	if userID == "" {
		return "", false, fmt.Errorf("userID cannot be empty")
	}

	// 128-bit random hex token identifying this one lock acquisition,
	// enabling the owner-only compare-and-delete release.
	lockValue, err := helpers.RandomHexToken(16)
	if err != nil {
		return "", false, fmt.Errorf("failed to generate lock value: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if held, ok := s.providerRefreshLocks[userID]; ok && time.Now().Before(held.expiresAt) {
		return "", false, nil
	}
	s.providerRefreshLocks[userID] = providerRefreshLock{value: lockValue, expiresAt: time.Now().Add(ttl)}
	return lockValue, true, nil
}

// ReleaseProviderRefreshLock releases the lock iff lockValue matches the
// current holder (storage.ProviderRefreshLockStore). A mismatched, expired,
// or missing lock is left untouched: a slow previous holder must never
// release its successor's lock.
func (s *Store) ReleaseProviderRefreshLock(_ context.Context, userID, lockValue string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if held, ok := s.providerRefreshLocks[userID]; ok && held.value == lockValue {
		delete(s.providerRefreshLocks, userID)
	}
	return nil
}

// cleanupExpiredProviderRefreshLocks removes locks whose TTL elapsed (the
// acquire path already treats them as free; this only reclaims the memory).
// Must be called with s.mu held (from cleanup()).
func (s *Store) cleanupExpiredProviderRefreshLocks() int {
	cleaned := 0
	for userID, held := range s.providerRefreshLocks {
		if !time.Now().Before(held.expiresAt) {
			delete(s.providerRefreshLocks, userID)
			cleaned++
		}
	}
	return cleaned
}
