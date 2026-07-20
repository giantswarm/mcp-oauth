package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// Coordinated refresh of the shared per-user provider token — the
// single-flight half of the rotation-race fix (giantswarm/giantswarm#37164
// root cause 2). Providers such as dex rotate refresh tokens on first use, so
// at most ONE refresh per user may reach the provider per rotation window;
// everyone else must adopt the winner's freshly-written shared entry
// (storage.UserProviderTokenStore) without ever calling the provider.
//
// Two dedup layers, one per topology level:
//
//   - Same pod: a per-user singleflight group (Server.providerRefreshGroup)
//     coalesces every concurrent caller in this process into ONE coordinator
//     run, so N goroutines cost one lock acquisition and one poll loop
//     instead of N.
//   - Cross pod: the per-user lock (storage.ProviderRefreshLockStore) is the
//     arbiter between processes when the backend is Valkey, covering the
//     multi-replica topology.

const (
	// providerRefreshWaitTimeout bounds the whole coordinated refresh: the
	// winner's provider call and any loser's wait for the winner's write-back.
	// Sized to the provider HTTP timeout (providers/oidc.DefaultHTTPTimeout).
	providerRefreshWaitTimeout = 10 * time.Second

	// providerRefreshLockTTL is the refresh lock's self-expiry: the
	// provider-refresh timeout plus a generous margin, so a crashed holder's
	// lock always outlives a live holder's slowest legitimate refresh yet
	// still auto-expires and self-heals.
	providerRefreshLockTTL = providerRefreshWaitTimeout + 15*time.Second

	// providerRefreshPollInterval is how often a session that lost the race
	// re-checks the shared entry / retries the lock while a refresh is
	// in-flight elsewhere.
	providerRefreshPollInterval = 25 * time.Millisecond
)

// providerRefreshLocker returns the per-user refresh lock store when the
// configured backend implements storage.ProviderRefreshLockStore.
func (s *Server) providerRefreshLocker() (storage.ProviderRefreshLockStore, bool) {
	locker, ok := s.tokenStore.(storage.ProviderRefreshLockStore)
	return locker, ok
}

// isProviderTokenFresh reports whether the user's shared provider-token entry
// is already fresh — i.e. adopting it needs no provider call — relative to
// what the caller observed when it decided a refresh was needed.
//
// Three independent signals, any one suffices:
//
//   - Rotation identity: the shared entry's refresh token has rotated past
//     the one the caller observed. A sibling session refreshed in the
//     meantime; the entry is the newest credential there is.
//   - Write-back identity: the shared entry's expiry differs from the one the
//     caller observed. Every winner write-back (and every login re-issue)
//     stamps the provider's new expiry, so a changed expiry means the entry
//     was rewritten with a newer credential since the caller's read — even
//     when the provider does NOT rotate refresh tokens and issues access
//     tokens shorter than the proactive threshold, where neither of the
//     other signals can ever fire. Guarded on both expiries being non-zero
//     so an unchanged snapshot, a nil/zero observation, or a zero-expiry
//     entry never reads as fresh through this signal.
//   - Real expiry: the entry's expiry is comfortably beyond the
//     proactive-refresh threshold. This relies on the shared entry carrying
//     the provider's REAL expiry (guaranteed since the unified layout —
//     never the storage-TTL-inflated expiry the legacy copies carried).
func (s *Server) isProviderTokenFresh(shared, observed *oauth2.Token) bool {
	if shared == nil {
		return false
	}
	if observed != nil && observed.RefreshToken != "" && shared.RefreshToken != observed.RefreshToken {
		return true
	}
	if observed != nil && !observed.Expiry.IsZero() && !shared.Expiry.IsZero() &&
		!shared.Expiry.Equal(observed.Expiry) {
		return true
	}
	if shared.Expiry.IsZero() {
		return false
	}
	threshold := time.Duration(s.Config.TokenRefreshThreshold) * time.Second
	return time.Until(shared.Expiry) > threshold
}

// isContextError reports whether err is (or wraps) a context cancellation or
// deadline error.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// coordinatedRefreshByIssuedToken resolves the user behind an issued token
// (access or refresh) and refreshes that user's shared provider entry through
// the per-user single-flight coordinator. It is the entry point for the
// validation-time refresh paths, which hold an issued token rather than a
// user ID.
//
// The caller MUST have already established that the backend is unified (upts
// non-nil). refreshUserProviderToken persists the rotated token to the shared
// entry under the lock, so callers MUST NOT write it back themselves — a
// second unlocked write could clobber a token a sibling session just rotated
// in, reintroducing the very race this fixes.
func (s *Server) coordinatedRefreshByIssuedToken(ctx context.Context, upts storage.UserProviderTokenStore, issuedToken string, observed *oauth2.Token) (*oauth2.Token, error) {
	userID, err := upts.GetProviderTokenRef(ctx, issuedToken)
	if err != nil {
		return nil, fmt.Errorf("resolve issued token to user for coordinated refresh: %w", err)
	}
	return s.refreshUserProviderToken(ctx, userID, observed)
}

// refreshUserProviderToken refreshes the user's shared provider token with
// per-user single-flight coordination and double-checked locking:
//
//	coalesce same-pod callers (singleflight) → acquire the cross-pod lock →
//	re-read the shared entry → already fresh? adopt it (no provider call) :
//	refresh the provider ONCE → write back to the shared entry → release.
//
// Same-pod coalescing: all concurrent callers for one user in this process
// share ONE coordinator run (Server.providerRefreshGroup) instead of each
// acquiring/polling the backend independently. The per-user lock remains the
// cross-pod arbiter; singleflight only deduplicates within the process.
//
// Cancellation: every caller waits on its OWN context and returns the context
// error promptly when cancelled — it never keeps polling on behalf of a
// request that already went away. The shared run executes under its LEADER's
// context; when the leader goes away mid-run the run aborts with a context
// error and surviving callers transparently start (or join) a fresh run, so
// one cancelled caller can never poison the result for its siblings. Only
// the provider round-trip plus its write-back are detached from caller
// cancellation (see refreshAndStoreSharedProviderToken).
//
// observed is the provider token the caller read before deciding a refresh
// was needed; it feeds the freshness check (see isProviderTokenFresh). The
// returned token is always the shared entry's current (fresh) value.
func (s *Server) refreshUserProviderToken(ctx context.Context, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	upts, unified := s.userProviderTokenStore()
	if !unified {
		return nil, fmt.Errorf("coordinated provider refresh requires a storage.UserProviderTokenStore backend")
	}

	// Bound this caller's total wait — the winner's provider call and any
	// loser's wait for the winner's write-back, across singleflight re-joins.
	ctx, cancel := context.WithTimeout(ctx, providerRefreshWaitTimeout)
	defer cancel()

	for {
		ch := s.providerRefreshGroup.DoChan(userID, func() (any, error) {
			return s.coordinateProviderRefresh(ctx, upts, userID, observed)
		})

		select {
		case res := <-ch:
			if res.Err != nil {
				if isContextError(res.Err) && ctx.Err() == nil {
					// The run died with its leader's cancellation/deadline,
					// not ours — retry: the next iteration starts a fresh
					// run (or joins one a sibling already started).
					continue
				}
				return nil, res.Err
			}
			token, ok := res.Val.(*oauth2.Token)
			if !ok || token == nil {
				return nil, fmt.Errorf("coordinated provider refresh returned no token")
			}
			return token, nil
		case <-ctx.Done():
			// This caller is done waiting. The shared run is bound to its
			// leader's context: once past the detach point (the provider call
			// + write-back) it completes regardless, but before that it dies
			// with its leader and any surviving sibling starts a fresh run
			// via the retry loop above.
			return nil, fmt.Errorf("gave up waiting for in-flight provider refresh: %w", ctx.Err())
		}
	}
}

// coordinateProviderRefresh is the shared, singleflight-deduped coordinator
// run: acquire the per-user cross-pod lock and refresh, or poll the shared
// entry until the holder's write-back makes it fresh. It runs under the
// singleflight leader's (bounded) context; every caller's own cancellation is
// handled by the select in refreshUserProviderToken.
//
// Backends without storage.ProviderRefreshLockStore fall back to an
// uncoordinated refresh + write-back (pre-coordination behavior) — still
// deduplicated within the process by the singleflight above.
func (s *Server) coordinateProviderRefresh(ctx context.Context, upts storage.UserProviderTokenStore, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	locker, coordinated := s.providerRefreshLocker()
	if !coordinated {
		s.Logger.Debug("Storage backend has no provider refresh lock, refreshing uncoordinated", "user_id", userID)
		return s.refreshSharedProviderToken(ctx, upts, userID, observed)
	}

	for {
		lockValue, acquired, err := locker.AcquireProviderRefreshLock(ctx, userID, providerRefreshLockTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire provider refresh lock: %w", err)
		}
		if acquired {
			return s.refreshSharedProviderTokenLocked(ctx, upts, locker, userID, lockValue, observed)
		}

		// A refresh is in-flight elsewhere (another pod or a stale holder):
		// wait-and-reread. The winner's write-back makes the shared entry
		// fresh; adopt it without ever calling the provider.
		if shared, getErr := upts.GetUserProviderToken(ctx, userID); getErr == nil && s.isProviderTokenFresh(shared, observed) {
			s.Logger.Debug("Adopted provider token refreshed by a concurrent session", "user_id", userID)
			return shared, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("gave up waiting for in-flight provider refresh: %w", ctx.Err())
		case <-time.After(providerRefreshPollInterval):
		}
	}
}

// refreshSharedProviderTokenLocked is the winner's half of the double-checked
// lock: it delegates to refreshSharedProviderToken (re-read under the lock,
// adopt when already fresh, otherwise refresh the provider once and write
// back) and guarantees the lock is released on every path (owner-only,
// detached from ctx cancellation); a crashed holder is covered by the lock
// TTL.
func (s *Server) refreshSharedProviderTokenLocked(ctx context.Context, upts storage.UserProviderTokenStore, locker storage.ProviderRefreshLockStore, userID, lockValue string, observed *oauth2.Token) (*oauth2.Token, error) {
	defer func() {
		if err := locker.ReleaseProviderRefreshLock(context.WithoutCancel(ctx), userID, lockValue); err != nil {
			s.Logger.Warn("Failed to release provider refresh lock", "user_id", userID, "error", err)
		}
	}()
	return s.refreshSharedProviderToken(ctx, upts, userID, observed)
}

// refreshSharedProviderToken is the double-checked refresh body: re-read the
// shared entry, adopt it when a concurrent session already refreshed it,
// otherwise refresh the provider once and write the rotated token back so
// every sibling session sees it. It runs under the per-user lock via
// refreshSharedProviderTokenLocked, or bare as the uncoordinated fallback for
// backends without a refresh lock.
func (s *Server) refreshSharedProviderToken(ctx context.Context, upts storage.UserProviderTokenStore, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	shared, err := upts.GetUserProviderToken(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to read shared provider token: %w", err)
	}
	if s.isProviderTokenFresh(shared, observed) {
		// Double-check hit: someone refreshed between the caller's read and
		// this re-read. Adopt — the provider is NOT called.
		s.Logger.Debug("Shared provider token already fresh, skipping provider refresh", "user_id", userID)
		return shared, nil
	}
	return s.refreshAndStoreSharedProviderToken(ctx, upts, userID, shared)
}

// refreshAndStoreSharedProviderToken performs the actual provider round-trip
// and persists the rotated token as the user's shared entry. The write-back
// MUST succeed before the token is handed out: returning a rotated token that
// siblings cannot see would strand them on the rotated-away refresh token.
//
// This is the coordinated refresh's ONE detach point: once the provider is
// asked to rotate the credential, aborting on caller cancellation would risk
// a rotation that completed upstream with a result nobody stored — every
// sibling session would be stranded on the burned single-use refresh token.
// The detached work is re-bounded by the provider-refresh timeout so it can
// neither run unbounded nor outlive the refresh lock's TTL.
func (s *Server) refreshAndStoreSharedProviderToken(ctx context.Context, upts storage.UserProviderTokenStore, userID string, shared *oauth2.Token) (*oauth2.Token, error) {
	if shared.RefreshToken == "" {
		return nil, fmt.Errorf("shared provider token for user has no refresh token")
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerRefreshWaitTimeout)
	defer cancel()

	newToken, err := s.provider.RefreshToken(ctx, shared.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// RFC 6749 §5.1: carry the previous refresh token forward when the
	// provider omits it — an empty refresh token on the shared entry would
	// break every one of the user's sessions.
	newToken = preserveRefreshToken(newToken, shared.RefreshToken)

	if err := upts.SaveUserProviderToken(ctx, userID, newToken); err != nil {
		return nil, fmt.Errorf("failed to write refreshed provider token to the shared entry: %w", err)
	}

	s.Logger.Debug("Provider token refreshed and written to shared entry",
		"user_id", userID, "new_expiry", newToken.Expiry)
	return newToken, nil
}
