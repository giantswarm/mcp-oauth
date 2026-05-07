package memory

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// revokedJTIEntry holds the revocation expiry for a single jti so the
// cleanup loop can drop entries once the underlying token expires.
type revokedJTIEntry struct {
	expiresAt time.Time
}

// revokedJTIs is the in-memory denylist for self-issued JWT access tokens.
// Held as a separate map (rather than tucked into the main Store struct) so
// the lock granularity stays tight on the validation hot path: revocation
// reads do not contend with token / client / flow operations.
type revokedJTIs struct {
	mu      sync.RWMutex
	entries map[string]revokedJTIEntry
}

func newRevokedJTIs() *revokedJTIs {
	return &revokedJTIs{entries: make(map[string]revokedJTIEntry)}
}

// revoke records jti as revoked until expiresAt. Calling revoke again for
// the same jti is idempotent — the latest expiresAt wins, which matches the
// RFC 7009 contract that revocation has no effect after token expiry.
func (r *revokedJTIs) revoke(jti string, expiresAt time.Time) error {
	if jti == "" {
		return fmt.Errorf("jti cannot be empty")
	}
	if expiresAt.Before(time.Now()) {
		// Already expired — no point storing it. Caller treats nil error
		// as success per RFC 7009 (revocation of an already-invalid token
		// is not an error).
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[jti] = revokedJTIEntry{expiresAt: expiresAt}
	return nil
}

// isRevoked reports whether jti is on the denylist with a still-valid entry.
// Called on every JWT validation, so the read path uses RWMutex.RLock.
func (r *revokedJTIs) isRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	r.mu.RLock()
	entry, ok := r.entries[jti]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(entry.expiresAt)
}

// cleanupExpired drops entries whose expiresAt has passed. Returns the
// number removed for log accounting in cleanupLoop.
func (r *revokedJTIs) cleanupExpired() int {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	cleaned := 0
	for jti, entry := range r.entries {
		if now.After(entry.expiresAt) {
			delete(r.entries, jti)
			cleaned++
		}
	}
	return cleaned
}

// RevokeJTI implements storage.RevokedTokenStore.
func (s *Store) RevokeJTI(_ context.Context, jti string, expiresAt time.Time) error {
	return s.ensureRevokedJTIs().revoke(jti, expiresAt)
}

// IsJTIRevoked implements storage.RevokedTokenStore.
func (s *Store) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	return s.ensureRevokedJTIs().isRevoked(jti), nil
}

// ensureRevokedJTIs lazily initializes the denylist on first use and returns
// the resolved value. The Store is constructed via New / NewWithInterval
// which do not allocate this map — keeping it lazy avoids paying for the
// allocation in deployments running in opaque mode.
//
// Concurrent callers race to allocate; CompareAndSwap ensures exactly one
// allocation wins and all callers observe the same instance. Readers
// (e.g. cleanup) load via the same atomic.Pointer for race-free visibility.
func (s *Store) ensureRevokedJTIs() *revokedJTIs {
	if r := s.revokedJTIs.Load(); r != nil {
		return r
	}
	fresh := newRevokedJTIs()
	if s.revokedJTIs.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return s.revokedJTIs.Load()
}
