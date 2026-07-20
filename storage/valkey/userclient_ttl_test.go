package valkey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

// ttlSeconds returns the remaining TTL of key in whole seconds. Valkey returns
// -1 for a key with no expiry and -2 for a missing key, so a value <= 0 means
// the key is either unbounded (the bug) or absent.
func ttlSeconds(t *testing.T, s *Store, key string) int64 {
	t.Helper()
	ttl, err := s.client.Do(context.Background(), s.client.B().Ttl().Key(key).Build()).ToInt64()
	require.NoError(t, err)
	return ttl
}

// TestUserClientSet_TTLBoundedAndExtendOnly is the regression guard for the
// unbounded-growth bug: the {prefix}userclient:{uid}:{cid} SET used for bulk
// revocation had no TTL and no per-member removal, so it grew forever (every
// grant added the access + refresh tokens; nothing ever removed them outside a
// wholesale RevokeAllTokensForUserClient). The fix gives the set an
// extend-only TTL on every add. This test asserts three things:
//
//  1. adding only a (short-lived) access token still bounds the set with a TTL;
//  2. adding a long-lived refresh token EXTENDS the TTL to the refresh horizon;
//  3. a later short-lived access-token add never SHRINKS the set — which would
//     otherwise drop still-live refresh-token members and break bulk revocation.
func TestUserClientSet_TTLBoundedAndExtendOnly(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-ttl"
		clientID = "client-ttl"
		familyID = "fam-ttl"
		rt       = "rt-ttl"
		at1      = "at-ttl-1"
		at2      = "at-ttl-2"
	)
	now := time.Now()
	accessExpiry := now.Add(time.Hour)
	refreshExpiry := now.Add(90 * 24 * time.Hour)

	ucKey := store.userClientKey(userID, clientID)
	const accessTTLCeil = int64(3600) + 5 // 1h access TTL plus a little slack

	// (1) Access token first (access can precede refresh within a grant, and
	// refresh-less clients only ever add access tokens). The set must still be
	// bounded rather than persisting forever.
	require.NoError(t, store.SaveTokenMetadata(ctx, at1, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access", ExpiresAt: accessExpiry, FamilyID: familyID,
	}))
	ttlAfterAccess := ttlSeconds(t, store, ucKey)
	require.Greater(t, ttlAfterAccess, int64(0), "set must carry a TTL after an access-token add (was unbounded)")
	require.LessOrEqual(t, ttlAfterAccess, accessTTLCeil, "TTL should track the access-token expiry when it is the only member")

	// (2) Long-lived refresh token joins the same set → TTL must extend.
	require.NoError(t, store.SaveRefreshTokenWithFamily(ctx, rt, userID, clientID, familyID, 0, refreshExpiry))
	require.NoError(t, store.SaveTokenMetadata(ctx, rt, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "refresh", ExpiresAt: refreshExpiry, FamilyID: familyID,
	}))
	ttlAfterRefresh := ttlSeconds(t, store, ucKey)
	require.Greater(t, ttlAfterRefresh, accessTTLCeil, "refresh-token add must extend the set TTL to the refresh horizon")

	// (3) A second short-lived access token must NOT shrink the set back down.
	require.NoError(t, store.SaveTokenMetadata(ctx, at2, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access", ExpiresAt: now.Add(time.Hour), FamilyID: familyID,
	}))
	ttlAfterSecondAccess := ttlSeconds(t, store, ucKey)
	require.Greater(t, ttlAfterSecondAccess, accessTTLCeil, "short-lived add must not shrink the set below a live refresh member")

	// Bulk revocation still sees every member.
	members, err := store.client.Do(ctx, store.client.B().Smembers().Key(ucKey).Build()).AsStrSlice()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{at1, at2, rt}, members, "all tokens must remain members for bulk revocation")
}
