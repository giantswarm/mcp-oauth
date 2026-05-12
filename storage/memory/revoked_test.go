package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRevokedTokenStore_RoundTrip(t *testing.T) {
	store := New()
	t.Cleanup(func() { store.Stop() })

	ctx := context.Background()

	// Initially nothing is revoked.
	revoked, err := store.IsJTIRevoked(ctx, "jti-1")
	require.NoError(t, err)
	require.False(t, revoked)

	// Revoke until 1h from now.
	require.NoError(t, store.RevokeJTI(ctx, "jti-1", time.Now().Add(time.Hour)))

	revoked, err = store.IsJTIRevoked(ctx, "jti-1")
	require.NoError(t, err)
	require.True(t, revoked)

	// Revoking an already-expired token is a no-op.
	require.NoError(t, store.RevokeJTI(ctx, "jti-2", time.Now().Add(-time.Minute)))
	revoked, err = store.IsJTIRevoked(ctx, "jti-2")
	require.NoError(t, err)
	require.False(t, revoked)
}

func TestRevokedTokenStore_RejectsEmptyJTI(t *testing.T) {
	store := New()
	t.Cleanup(func() { store.Stop() })
	require.Error(t, store.RevokeJTI(context.Background(), "", time.Now().Add(time.Hour)))
	revoked, err := store.IsJTIRevoked(context.Background(), "")
	require.NoError(t, err)
	require.False(t, revoked)
}

func TestRevokedTokenStore_AutoExpires(t *testing.T) {
	store := New()
	t.Cleanup(func() { store.Stop() })

	// Revoke until 50ms from now, then wait for natural expiry.
	exp := time.Now().Add(50 * time.Millisecond)
	require.NoError(t, store.RevokeJTI(context.Background(), "short-lived", exp))

	revoked, err := store.IsJTIRevoked(context.Background(), "short-lived")
	require.NoError(t, err)
	require.True(t, revoked)

	time.Sleep(80 * time.Millisecond)

	revoked, err = store.IsJTIRevoked(context.Background(), "short-lived")
	require.NoError(t, err)
	require.False(t, revoked, "expired entry must be treated as not revoked")
}

func TestRevokedTokenStore_LazilyAllocated(t *testing.T) {
	store := New()
	t.Cleanup(func() { store.Stop() })
	// In opaque-only deployments the revoked map should not be allocated
	// before any RevokeJTI / IsJTIRevoked call.
	require.Nil(t, store.revokedJTIs.Load(), "revokedJTIs must be lazy-initialized")
	_, _ = store.IsJTIRevoked(context.Background(), "any")
	require.NotNil(t, store.revokedJTIs.Load())
}
