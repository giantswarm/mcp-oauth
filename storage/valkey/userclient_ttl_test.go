package valkey

import (
	"context"
	"fmt"
	"sync"
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

// userClientMembers returns every member of a user+client sorted set.
func userClientMembers(t *testing.T, s *Store, key string) []string {
	t.Helper()
	members, err := s.client.Do(context.Background(), s.client.B().Zrange().Key(key).Min("0").Max("-1").Build()).AsStrSlice()
	require.NoError(t, err)
	return members
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
	members, err := userClientMembers(t, store, ucKey), error(nil)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{at1, at2, rt}, members, "all tokens must remain members for bulk revocation")
}

// TestUserClientSet_ZeroExpiryStillBounded guards the boundary case where a
// token metadata save carries a zero/unset ExpiresAt (calculateTTL then yields
// 0). The member is still added for bulk revocation, but the set must not be
// left unbounded — it falls back to the store's refresh-token TTL so the
// unbounded-growth bug cannot slip back in through a horizon-less add.
func TestUserClientSet_ZeroExpiryStillBounded(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-zero"
		clientID = "client-zero"
		tokenID  = "tok-zero"
	)
	ucKey := store.userClientKey(userID, clientID)

	// ExpiresAt deliberately left as the zero value.
	require.NoError(t, store.SaveTokenMetadata(ctx, tokenID, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access",
	}))

	require.Greater(t, ttlSeconds(t, store, ucKey), int64(0),
		"set must carry a fallback TTL even when the member has no expiry (was unbounded)")

	members, err := userClientMembers(t, store, ucKey), error(nil)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{tokenID}, members, "the horizon-less token must still be a member for bulk revocation")
}

// TestUserClientSet_ConcurrentAddsConvergeToMax guards the creation-time race
// the atomic add closes: many concurrent adds against a fresh set, mixing
// short-lived access-token and long-lived refresh-token horizons, must always
// leave the set bounded by the LONGEST horizon — never a shorter one. With the
// pre-fix non-atomic SADD + EXPIRE GT + EXPIRE NX sequence, interleaved
// first-writers could pin the set to a short access-token horizon and drop
// still-live refresh members, silently breaking bulk revocation.
func TestUserClientSet_ConcurrentAddsConvergeToMax(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-conc"
		clientID = "client-conc"
		shortTTL = time.Hour
		longTTL  = 90 * 24 * time.Hour
		workers  = 50
	)
	ucKey := store.userClientKey(userID, clientID)
	longCeil := int64(shortTTL.Seconds()) + 5 // any short-only outcome sits at/under this

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ttl := shortTTL
			if i%2 == 0 {
				ttl = longTTL
			}
			store.addToUserClientSet(ctx, userID, clientID, fmt.Sprintf("tok-%d", i), ttl)
		}(i)
	}
	wg.Wait()

	require.Greater(t, ttlSeconds(t, store, ucKey), longCeil,
		"concurrent adds must leave the set bounded by the longest horizon, never a short one")
	members, err := userClientMembers(t, store, ucKey), error(nil)
	require.NoError(t, err)
	require.Len(t, members, workers, "every concurrent add must be a member for bulk revocation")
}

// TestUserClientSet_ExpiredMembersPruned guards the accumulation the sorted set
// closes: an active user's set used to keep every token issued within its
// extend-only TTL. Tokens whose expiry has passed are dropped on the next add,
// while live members stay for bulk revocation.
func TestUserClientSet_ExpiredMembersPruned(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-prune"
		clientID = "client-prune"
		expired  = 50
	)
	ucKey := store.userClientKey(userID, clientID)

	for i := 0; i < expired; i++ {
		store.addToUserClientSet(ctx, userID, clientID, fmt.Sprintf("old-%d", i), time.Second)
	}
	require.NoError(t, store.SaveTokenMetadata(ctx, "rt-live", storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "refresh", ExpiresAt: time.Now().Add(24 * time.Hour),
	}))
	require.NoError(t, store.SaveTokenMetadata(ctx, "tok-no-expiry", storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access",
	}))
	require.Len(t, userClientMembers(t, store, ucKey), expired+2)

	time.Sleep(2100 * time.Millisecond)
	require.NoError(t, store.SaveTokenMetadata(ctx, "at-live", storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access", ExpiresAt: time.Now().Add(time.Hour),
	}))

	require.ElementsMatch(t, []string{"rt-live", "tok-no-expiry", "at-live"}, userClientMembers(t, store, ucKey),
		"expired members must be pruned; live and horizon-less members stay")
}

// TestUserClientSet_IDTokenStoredAsDigest guards that a forwarded id_token, a
// raw upstream JWT, never becomes a set member, and that bulk revocation still
// deletes its metadata while leaving it out of the provider-side token list.
func TestUserClientSet_IDTokenStoredAsDigest(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-id"
		clientID = "client-id"
		idToken  = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLWlkIn0.c2lnbmF0dXJl"
		at       = "at-id"
	)
	exp := time.Now().Add(time.Hour)
	require.NoError(t, store.SaveTokenMetadata(ctx, at, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access", ExpiresAt: exp,
	}))
	require.NoError(t, store.SaveTokenMetadata(ctx, idToken, storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "id", ExpiresAt: exp,
	}))

	members := userClientMembers(t, store, store.userClientKey(userID, clientID))
	require.ElementsMatch(t, []string{at, digestMemberPrefix + hashKeyComponent(idToken)}, members)
	for _, m := range members {
		require.NotContains(t, m, ".", "no member may be a raw JWT")
	}

	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	require.NoError(t, err)
	require.Equal(t, []string{at}, tokens, "the id_token digest is not a provider-revocable token")

	count, err := store.RevokeAllTokensForUserClient(ctx, userID, clientID)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	_, err = store.GetTokenMetadata(idToken)
	require.ErrorIs(t, err, storage.ErrTokenNotFound, "bulk revocation must delete the id_token's metadata")
	_, err = store.GetTokenMetadata(at)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

// TestUserClientSet_PreviousSetLayoutStillRevoked guards the rolling upgrade:
// members a previous release wrote to the plain SET are still listed and
// revoked, and revocation deletes that SET.
func TestUserClientSet_PreviousSetLayoutStillRevoked(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const (
		userID   = "user-prev"
		clientID = "client-prev"
	)
	setKey := store.setUserClientKey(userID, clientID)
	require.NoError(t, store.saddExtendOnlyTTL(ctx, setKey, "tok-prev", time.Hour))
	require.NoError(t, store.SaveTokenMetadata(ctx, "tok-new", storage.TokenMetadata{
		UserID: userID, ClientID: clientID, TokenType: "access", ExpiresAt: time.Now().Add(time.Hour),
	}))

	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"tok-prev", "tok-new"}, tokens)

	count, err := store.RevokeAllTokensForUserClient(ctx, userID, clientID)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, int64(-2), ttlSeconds(t, store, setKey), "the previous SET must be deleted")
}
