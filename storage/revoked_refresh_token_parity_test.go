package storage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TestDeleteRefreshToken_RevocationGateParity verifies that the memory and
// valkey backends agree on the property RFC 7009 revocation now relies on in
// the unified layout (server.RevokeToken): TokenStore.DeleteRefreshToken
// hard-deletes the refresh-token record — the ONE record the refresh grant
// gates on, via GetRefreshTokenInfo on the resolve path and
// AtomicConsumeRefreshToken on the consume path — independent of family
// state. Family metadata writes are best-effort at issuance, so family-less
// refresh tokens are reachable and revocation cannot rely on family
// revocation alone (mcp-oauth#511).
func TestDeleteRefreshToken_RevocationGateParity(t *testing.T) {
	backends := []struct {
		name    string
		factory func(t *testing.T) storage.Combined
	}{
		{name: storage.BackendMemory, factory: newMemoryBackend},
		{name: storage.BackendValkey, factory: newValkeyBackend},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("delete_closes_both_refresh_grant_gates", func(t *testing.T) {
				combined := b.factory(t)
				s := requireUserProviderTokenStore(t, combined)
				ctx := t.Context()

				exp := time.Now().Add(time.Hour)
				rt := fmt.Sprintf("rt-revoke-gate-%s", b.name)

				// A family-less record, exactly as left behind when the
				// best-effort family metadata write failed at issuance.
				require.NoError(t, combined.SaveRefreshToken(ctx, rt, "user-revoke-gate", exp))
				require.NoError(t, s.SaveProviderTokenRef(ctx, rt, "user-revoke-gate", exp))

				// Sanity (non-destructive): the resolve gate is open.
				userID, err := combined.GetRefreshTokenInfo(ctx, rt)
				require.NoError(t, err)
				require.Equal(t, "user-revoke-gate", userID)

				require.NoError(t, combined.DeleteRefreshToken(ctx, rt))

				// Both refresh-grant gates must now be closed.
				_, err = combined.GetRefreshTokenInfo(ctx, rt)
				require.ErrorIs(t, err, storage.ErrTokenNotFound,
					"resolve gate (GetRefreshTokenInfo) must reject a hard-deleted refresh token")
				_, _, err = s.AtomicConsumeRefreshToken(ctx, rt)
				require.ErrorIs(t, err, storage.ErrTokenNotFound,
					"consume gate (AtomicConsumeRefreshToken) must reject a hard-deleted refresh token")
			})

			t.Run("delete_missing_token_is_idempotent", func(t *testing.T) {
				combined := b.factory(t)
				require.NoError(t, combined.DeleteRefreshToken(t.Context(), "rt-never-issued"),
					"deleting a missing refresh token must not error (RFC 7009 revocation is repeatable)")
			})
		})
	}
}
