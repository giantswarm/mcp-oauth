package server

import (
	"context"
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
// (storage.UserProviderTokenStore) without ever calling the provider. The
// per-user lock (storage.ProviderRefreshLockStore) is cross-pod when the
// backend is Valkey, covering the multi-replica topology.

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
// Two independent signals, either suffices:
//
//   - Rotation identity: the shared entry's refresh token has rotated past
//     the one the caller observed. A sibling session refreshed in the
//     meantime; the entry is the newest credential there is.
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
	if shared.Expiry.IsZero() {
		return false
	}
	threshold := time.Duration(s.Config.TokenRefreshThreshold) * time.Second
	return time.Until(shared.Expiry) > threshold
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
//	acquire → re-read the shared entry → already fresh? adopt it (no provider
//	call) : refresh the provider ONCE → write back to the shared entry → release.
//
// A caller that finds a refresh in-flight for its user waits briefly
// (bounded by the provider-refresh timeout) re-reading the shared entry, then
// adopts the freshly-written token — it never calls the provider, never
// collides with the winner, and surfaces no client-visible error.
//
// observed is the provider token the caller read before deciding a refresh
// was needed; it feeds the freshness check (see isProviderTokenFresh). The
// returned token is always the shared entry's current (fresh) value.
//
// Backends without storage.ProviderRefreshLockStore fall back to an
// uncoordinated refresh + write-back (pre-coordination behavior).
func (s *Server) refreshUserProviderToken(ctx context.Context, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	upts, unified := s.userProviderTokenStore()
	if !unified {
		return nil, fmt.Errorf("coordinated provider refresh requires a storage.UserProviderTokenStore backend")
	}

	locker, coordinated := s.providerRefreshLocker()
	if !coordinated {
		s.Logger.Debug("Storage backend has no provider refresh lock, refreshing uncoordinated", "user_id", userID)
		return s.refreshSharedProviderToken(ctx, upts, userID, observed)
	}

	ctx, cancel := context.WithTimeout(ctx, providerRefreshWaitTimeout)
	defer cancel()

	for {
		lockValue, acquired, err := locker.AcquireProviderRefreshLock(ctx, userID, providerRefreshLockTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire provider refresh lock: %w", err)
		}
		if acquired {
			return s.refreshSharedProviderTokenLocked(ctx, upts, locker, userID, lockValue, observed)
		}

		// A refresh is in-flight elsewhere (another goroutine or another
		// pod): wait-and-reread. The winner's write-back makes the shared
		// entry fresh; adopt it without ever calling the provider.
		if shared, getErr := upts.GetUserProviderToken(ctx, userID); getErr == nil && s.isProviderTokenFresh(shared, observed) {
			s.Logger.Debug("Adopted provider token refreshed by a concurrent session", "user_id", userID)
			return shared, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for in-flight provider refresh: %w", ctx.Err())
		case <-time.After(providerRefreshPollInterval):
		}
	}
}

// refreshSharedProviderTokenLocked is the winner's half of the double-checked
// lock: re-read the shared entry under the lock, adopt it when a concurrent
// session already refreshed it, otherwise refresh the provider once and write
// the rotated token back so every sibling session sees it. The lock is
// released on every path (owner-only, detached from ctx cancellation); a
// crashed holder is covered by the lock TTL.
func (s *Server) refreshSharedProviderTokenLocked(ctx context.Context, upts storage.UserProviderTokenStore, locker storage.ProviderRefreshLockStore, userID, lockValue string, observed *oauth2.Token) (*oauth2.Token, error) {
	defer func() {
		if err := locker.ReleaseProviderRefreshLock(context.WithoutCancel(ctx), userID, lockValue); err != nil {
			s.Logger.Warn("Failed to release provider refresh lock", "user_id", userID, "error", err)
		}
	}()

	shared, err := upts.GetUserProviderToken(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to read shared provider token: %w", err)
	}
	if s.isProviderTokenFresh(shared, observed) {
		// Double-check hit: someone refreshed between the caller's read and
		// our lock acquisition. Adopt — the provider is NOT called.
		s.Logger.Debug("Shared provider token already fresh, skipping provider refresh", "user_id", userID)
		return shared, nil
	}

	return s.refreshAndStoreSharedProviderToken(ctx, upts, userID, shared)
}

// refreshSharedProviderToken is the uncoordinated fallback for backends
// without a refresh lock: same double-checked read and write-back, no
// cross-process exclusion.
func (s *Server) refreshSharedProviderToken(ctx context.Context, upts storage.UserProviderTokenStore, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	shared, err := upts.GetUserProviderToken(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to read shared provider token: %w", err)
	}
	if s.isProviderTokenFresh(shared, observed) {
		return shared, nil
	}
	return s.refreshAndStoreSharedProviderToken(ctx, upts, userID, shared)
}

// refreshAndStoreSharedProviderToken performs the actual provider round-trip
// and persists the rotated token as the user's shared entry. The write-back
// MUST succeed before the token is handed out: returning a rotated token that
// siblings cannot see would strand them on the rotated-away refresh token.
func (s *Server) refreshAndStoreSharedProviderToken(ctx context.Context, upts storage.UserProviderTokenStore, userID string, shared *oauth2.Token) (*oauth2.Token, error) {
	if shared.RefreshToken == "" {
		return nil, fmt.Errorf("shared provider token for user has no refresh token")
	}

	newToken, err := s.provider.RefreshToken(ctx, shared.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token with provider: %w", err)
	}

	// RFC 6749 §5.1: carry the previous refresh token forward when the
	// provider omits it — an empty refresh token on the shared entry would
	// break every one of the user's sessions.
	newToken = preserveRefreshToken(newToken, shared.RefreshToken)

	// Detached ctx: once the provider has rotated the credential, failing to
	// persist it because the caller went away would orphan the rotation.
	if err := upts.SaveUserProviderToken(context.WithoutCancel(ctx), userID, newToken); err != nil {
		return nil, fmt.Errorf("failed to write refreshed provider token to the shared entry: %w", err)
	}

	s.Logger.Debug("Provider token refreshed and written to shared entry",
		"user_id", userID, "new_expiry", newToken.Expiry)
	return newToken, nil
}
