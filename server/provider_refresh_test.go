package server

// Tests for the per-user single-flight provider refresh — slice 2 of the
// rotation-race fix (giantswarm/giantswarm#37164 root cause 2, mcp-oauth#513).
//
// The headline property: under N concurrent refreshes for one user — within
// one process AND across two Store instances sharing one Valkey (two pods) —
// the provider records EXACTLY ONE RefreshToken call, and every caller ends
// with the same fresh token. Losers adopt the winner's write-back; they never
// call the provider and never collide with dex's single-use rotation.
//
// Repo convention: no time.Sleep — goroutines are coordinated with channels;
// the only time-dependent test (crashed-holder TTL) relies on the coordinator's
// own bounded polling, not on test-side sleeps.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const refreshTestUserID = "refresh-user-1"

// staleProviderToken returns a provider token whose expiry is inside the
// proactive-refresh threshold (2m < the 5m threshold), holding dex's current
// refresh token — the state every session is in right before the collision.
func staleProviderToken(dex *singleUseDex) *oauth2.Token {
	dex.mu.Lock()
	defer dex.mu.Unlock()
	return &oauth2.Token{
		AccessToken:  "dex-at-login",
		TokenType:    "Bearer",
		RefreshToken: dex.currentRT,
		Expiry:       time.Now().Add(2 * time.Minute),
	}
}

// newRefreshTestServer builds a Server on the given combined store with a
// mock provider whose RefreshToken is the single-use dex emulation.
func newRefreshTestServer(t *testing.T, store storage.Combined, dex *singleUseDex) *Server {
	t.Helper()

	provider := mock.NewProvider()
	provider.RefreshTokenFunc = dex.refresh

	config := &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		ClockSkewGracePeriod:        5,
		TokenRefreshThreshold:       300, // 5m proactive threshold (production default)
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, config, nil)
	require.NoError(t, err)
	return srv
}

func newRefreshTestMemoryServer(t *testing.T) (*Server, *memory.Store, *singleUseDex) {
	t.Helper()
	store := memory.New(memory.WithCleanupInterval(time.Hour))
	t.Cleanup(store.Stop)
	dex := newSingleUseDex()
	return newRefreshTestServer(t, store, dex), store, dex
}

// runConcurrentRefreshes fires one refreshUserProviderToken per (server,
// observed) pair simultaneously and returns the resulting tokens, failing on
// any error.
func runConcurrentRefreshes(t *testing.T, servers []*Server, observed *oauth2.Token) []*oauth2.Token {
	t.Helper()
	ctx := context.Background()

	start := make(chan struct{})
	tokens := make([]*oauth2.Token, len(servers))
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func(i int, srv *Server) {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
		}(i, srv)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "caller %d: a lost refresh race must yield a valid token, not an error", i)
	}
	return tokens
}

// TestProviderRefresh_SingleFlight_Memory drives N concurrent refreshes for
// one user within a single process (memory backend): the provider is called
// exactly once and every caller adopts the same fresh token.
func TestProviderRefresh_SingleFlight_Memory(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := staleProviderToken(dex)
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	const n = 8
	servers := make([]*Server, n)
	for i := range servers {
		servers[i] = srv
	}
	tokens := runConcurrentRefreshes(t, servers, observed)

	require.Equal(t, 1, dex.callCount(), "the provider must be called exactly once per rotation window")
	for i, tok := range tokens {
		require.Equalf(t, "dex-rt-1", tok.RefreshToken, "caller %d must end with the winner's fresh token", i)
	}

	shared, err := store.GetUserProviderToken(ctx, refreshTestUserID)
	require.NoError(t, err)
	require.Equal(t, "dex-rt-1", shared.RefreshToken, "the rotated token must be written back to the shared entry")
}

// The cross-pod variant — two Server instances over two valkey.Store
// instances sharing one Valkey — lives in provider_refresh_crosspod_test.go
// (package server_test): the valkey backend imports this package for the
// DPoP replay cache, so importing it from an in-package test would cycle.

// TestProviderRefresh_DoubleCheck_FreshByExpiry: the shared entry's REAL
// expiry is beyond the proactive-refresh threshold, so the refresh is skipped
// entirely — no lock contention, no provider call.
func TestProviderRefresh_DoubleCheck_FreshByExpiry(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	fresh := &oauth2.Token{
		AccessToken:  "dex-at-fresh",
		RefreshToken: "dex-rt-0",
		Expiry:       time.Now().Add(30 * time.Minute), // well beyond the 5m threshold
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, fresh))

	got, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, fresh)
	require.NoError(t, err)
	require.Equal(t, "dex-rt-0", got.RefreshToken)
	require.Zero(t, dex.callCount(), "a fresh shared entry must be adopted without calling the provider")
}

// TestProviderRefresh_DoubleCheck_FreshByRotationIdentity: the shared entry
// has rotated past the caller's observed copy. Even though its expiry is
// still inside the proactive threshold, the rotation-identity signal marks it
// fresh — calling the provider here would burn the sibling's rotation.
func TestProviderRefresh_DoubleCheck_FreshByRotationIdentity(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := staleProviderToken(dex) // holds dex-rt-0

	rotated := &oauth2.Token{
		AccessToken:  "dex-at-1",
		RefreshToken: "dex-rt-1",
		Expiry:       time.Now().Add(2 * time.Minute), // still inside the threshold
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, rotated))

	got, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
	require.NoError(t, err)
	require.Equal(t, "dex-rt-1", got.RefreshToken, "the rotated sibling token must be adopted")
	require.Zero(t, dex.callCount(), "adopting a rotated entry must not call the provider")
}

// TestProviderRefresh_CrashedHolder_LockExpiresAndSelfHeals: a holder that
// died mid-refresh (lock acquired, never released) only delays the next
// refresh until its lock TTL elapses — the coordinator's polling picks the
// lock up afterwards and the refresh proceeds normally.
func TestProviderRefresh_CrashedHolder_LockExpiresAndSelfHeals(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := staleProviderToken(dex)
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	// Simulated crash: the lock is held with a short TTL and never released.
	_, acquired, err := store.AcquireProviderRefreshLock(ctx, refreshTestUserID, 50*time.Millisecond)
	require.NoError(t, err)
	require.True(t, acquired)

	got, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
	require.NoError(t, err, "the refresh must self-heal once the crashed holder's lock expires")
	require.Equal(t, "dex-rt-1", got.RefreshToken)
	require.Equal(t, 1, dex.callCount())
}

// TestProviderRefresh_ProviderFailure_ReleasesLock: a provider error is
// propagated to the caller, but the lock is released — the next attempt is
// not blocked behind a poisoned lock and succeeds once the provider recovers.
func TestProviderRefresh_ProviderFailure_ReleasesLock(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := staleProviderToken(dex)
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	provider := srv.provider.(*mock.Provider)
	provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
		return nil, fmt.Errorf("dex is down")
	}

	_, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
	require.ErrorContains(t, err, "dex is down")

	// The shared entry is untouched by the failed attempt …
	shared, err := store.GetUserProviderToken(ctx, refreshTestUserID)
	require.NoError(t, err)
	require.Equal(t, observed.RefreshToken, shared.RefreshToken)

	// … and the lock was released: the retry succeeds immediately once the
	// provider is back.
	provider.RefreshTokenFunc = dex.refresh
	got, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
	require.NoError(t, err)
	require.Equal(t, "dex-rt-1", got.RefreshToken)
}

// TestProviderRefresh_NoSharedEntry_Errors: with nothing to refresh the
// coordinator reports not-found instead of calling the provider.
func TestProviderRefresh_NoSharedEntry_Errors(t *testing.T) {
	srv, _, dex := newRefreshTestMemoryServer(t)

	_, err := srv.refreshUserProviderToken(context.Background(), "user-without-entry", nil)
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	require.Zero(t, dex.callCount())
}
