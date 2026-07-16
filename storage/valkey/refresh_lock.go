package valkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	vk "github.com/valkey-io/valkey-go"
)

// ============================================================
// ProviderRefreshLockStore Implementation
// ============================================================
//
// The per-user provider-refresh lock lives in its own namespace
// ({prefix}refreshlock:{sha256(userID)}). Because the key space is shared by
// every pod talking to the same Valkey, the lock is cross-pod: at most one
// pod refreshes a user's provider credential per rotation window.
//
// The primitive follows the atomic-lock precedent of the DPoP replay cache
// (dpop.go): acquisition is a single SET NX PX (no GET+SET race), release is
// a Lua compare-and-delete against the random per-acquisition value, so a
// slow holder whose lock already expired can never release a successor's
// lock. The PX TTL makes a crashed holder's lock self-expire.

func (s *Store) providerRefreshLockKey(userID string) string {
	return s.keyOf("refreshlock", hashKeyComponent(userID))
}

// AcquireProviderRefreshLock attempts to acquire the per-user refresh lock
// (storage.ProviderRefreshLockStore).
func (s *Store) AcquireProviderRefreshLock(ctx context.Context, userID string, ttl time.Duration) (lockValue string, acquired bool, err error) {
	op := s.startTracedOp(ctx, "acquire_provider_refresh_lock")
	defer op.end(&err)

	if userID == "" {
		return "", false, fmt.Errorf("userID cannot be empty")
	}
	if err = validateInputLength(userID); err != nil {
		return "", false, err
	}

	lockValue, err = randomLockValue()
	if err != nil {
		return "", false, err
	}

	millis := max(ttl.Milliseconds(), 1)
	err = s.client.Do(
		op.ctx,
		s.client.B().Set().Key(s.providerRefreshLockKey(userID)).Value(lockValue).Nx().PxMilliseconds(millis).Build(),
	).Error()
	if err == nil {
		return lockValue, true, nil
	}
	if vk.IsValkeyNil(err) {
		// SET NX returned nil — the lock is held by another owner.
		err = nil
		return "", false, nil
	}
	return "", false, fmt.Errorf("failed to acquire provider refresh lock: %w", err)
}

// luaScriptReleaseRefreshLock deletes the lock key only when its value still
// matches the caller's (owner-only compare-and-delete). GET+compare+DEL must
// be one atomic script: a non-atomic sequence could delete a successor's lock
// acquired between the compare and the delete.
//
// KEYS[1] = lock key, ARGV[1] = the caller's lock value.
const luaScriptReleaseRefreshLock = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
`

// ReleaseProviderRefreshLock releases the lock iff lockValue matches the
// current holder (storage.ProviderRefreshLockStore). A mismatched, expired,
// or missing lock is a silent no-op.
func (s *Store) ReleaseProviderRefreshLock(ctx context.Context, userID, lockValue string) (err error) {
	op := s.startTracedOp(ctx, "release_provider_refresh_lock")
	defer op.end(&err)

	err = s.client.Do(
		op.ctx,
		s.client.B().Eval().Script(luaScriptReleaseRefreshLock).
			Numkeys(1).
			Key(s.providerRefreshLockKey(userID)).
			Arg(lockValue).
			Build(),
	).Error()
	if err != nil {
		return fmt.Errorf("failed to release provider refresh lock: %w", err)
	}
	return nil
}

// randomLockValue returns a 128-bit random hex token identifying one lock
// acquisition, enabling the owner-only compare-and-delete release.
func randomLockValue() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate lock value: %w", err)
	}
	return hex.EncodeToString(b), nil
}
