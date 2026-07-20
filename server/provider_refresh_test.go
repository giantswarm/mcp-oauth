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
// mock provider using the given RefreshToken implementation.
func newRefreshTestServer(t *testing.T, store storage.Combined, refresh func(context.Context, string) (*oauth2.Token, error)) *Server {
	t.Helper()

	provider := mock.NewProvider()
	provider.RefreshTokenFunc = refresh

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
	return newRefreshTestServer(t, store, dex.refresh), store, dex
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

// TestProviderRefresh_IsProviderTokenFresh pins the freshness signals down as
// a table, including the guards on the write-back-identity (expiry-change)
// signal: an unchanged snapshot, a self-comparison, a nil or zero-expiry
// observation, and a zero-expiry entry must never read as fresh through it.
func TestProviderRefresh_IsProviderTokenFresh(t *testing.T) {
	srv := &Server{Config: &Config{TokenRefreshThreshold: 300}}

	near := time.Now().Add(2 * time.Minute)    // inside the 5m threshold
	changed := time.Now().Add(3 * time.Minute) // inside the threshold, but rewritten
	far := time.Now().Add(30 * time.Minute)    // beyond the threshold

	sameSnapshot := &oauth2.Token{RefreshToken: "rt-0", Expiry: near}

	tests := []struct {
		name     string
		shared   *oauth2.Token
		observed *oauth2.Token
		want     bool
	}{
		{"nil shared entry", nil, &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, false},
		{"rotation identity: refresh token rotated", &oauth2.Token{RefreshToken: "rt-1", Expiry: near}, &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, true},
		{"real expiry: beyond threshold, nothing observed", &oauth2.Token{RefreshToken: "rt-0", Expiry: far}, nil, true},
		{"write-back identity: same RT, expiry changed inside threshold", &oauth2.Token{RefreshToken: "rt-0", Expiry: changed}, &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, true},
		{"self comparison: same snapshot twice", sameSnapshot, sameSnapshot, false},
		{"unchanged entry inside threshold", &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, false},
		{"nil observed, entry inside threshold", &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, nil, false},
		{"zero observed expiry, entry inside threshold", &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, &oauth2.Token{RefreshToken: "rt-0"}, false},
		{"zero shared expiry", &oauth2.Token{RefreshToken: "rt-0"}, &oauth2.Token{RefreshToken: "rt-0", Expiry: near}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, srv.isProviderTokenFresh(tt.shared, tt.observed))
		})
	}
}

// TestProviderRefresh_DoubleCheck_FreshByExpiryChange: the shared entry was
// rewritten since the caller observed it — SAME refresh token (the provider
// does not rotate) and an expiry still inside the proactive threshold, just
// different. Neither the rotation-identity nor the real-expiry signal can
// fire; only the write-back-identity signal marks the entry fresh, and the
// provider must not be called.
func TestProviderRefresh_DoubleCheck_FreshByExpiryChange(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := &oauth2.Token{
		AccessToken:  "dex-at-old",
		RefreshToken: "dex-rt-0",
		Expiry:       time.Now().Add(time.Minute),
	}

	// A sibling's write-back landed after the observation: same RT, a new
	// access token, and a new expiry that is still inside the 5m threshold.
	rewritten := &oauth2.Token{
		AccessToken:  "dex-at-new",
		RefreshToken: "dex-rt-0",
		Expiry:       time.Now().Add(2 * time.Minute),
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, rewritten))

	got, err := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
	require.NoError(t, err)
	require.Equal(t, "dex-at-new", got.AccessToken, "the rewritten sibling entry must be adopted")
	require.Zero(t, dex.callCount(), "adopting a rewritten entry must not call the provider")
}

// nonRotatingIdP emulates a provider that never rotates refresh tokens and
// issues access tokens whose lifetime (2m) is INSIDE the proactive-refresh
// threshold (5m): for waiters, neither the rotation-identity nor the
// real-expiry freshness signal can ever fire — only the write-back-identity
// (expiry-change) signal lets them adopt the winner's result instead of
// timing out or serializing N upstream calls.
type nonRotatingIdP struct {
	mu    sync.Mutex
	gen   int
	calls int
}

func (p *nonRotatingIdP) refresh(_ context.Context, rt string) (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if rt != "static-rt" {
		return nil, fmt.Errorf("unknown refresh token %q", rt)
	}
	p.gen++
	return &oauth2.Token{
		AccessToken:  fmt.Sprintf("short-at-%d", p.gen),
		TokenType:    "Bearer",
		RefreshToken: "static-rt", // never rotates
		Expiry:       time.Now().Add(2 * time.Minute),
	}, nil
}

func (p *nonRotatingIdP) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestProviderRefresh_NonRotatingRT_ShortAT_CrossServerSingleFlight: two
// Server instances over ONE store — two pods sharing a backend, each with its
// own in-process singleflight, so the second pod's callers are true cross-pod
// waiters. With a non-rotating refresh token and short-lived access tokens,
// waiters can only adopt through the expiry-change signal; the provider must
// still be called exactly once for N concurrent refreshes.
func TestProviderRefresh_NonRotatingRT_ShortAT_CrossServerSingleFlight(t *testing.T) {
	store := memory.New(memory.WithCleanupInterval(time.Hour))
	t.Cleanup(store.Stop)
	idp := &nonRotatingIdP{}
	podA := newRefreshTestServer(t, store, idp.refresh)
	podB := newRefreshTestServer(t, store, idp.refresh)
	ctx := context.Background()

	observed := &oauth2.Token{
		AccessToken:  "short-at-0",
		TokenType:    "Bearer",
		RefreshToken: "static-rt",
		Expiry:       time.Now().Add(90 * time.Second), // inside the 5m threshold
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	servers := []*Server{podA, podB, podA, podB, podA, podB, podA, podB}
	tokens := runConcurrentRefreshes(t, servers, observed)

	require.Equal(t, 1, idp.callCount(),
		"a non-rotating provider with short-lived access tokens must still see exactly ONE refresh per rotation window")
	for i, tok := range tokens {
		require.Equalf(t, "short-at-1", tok.AccessToken, "caller %d must adopt the winner's freshly-written entry", i)
		require.Equalf(t, "static-rt", tok.RefreshToken, "caller %d must keep the non-rotating refresh token", i)
	}
}

// TestProviderRefresh_CancelledWaiter_ReturnsPromptly: a caller that loses
// the race (the lock is held elsewhere) and whose request is cancelled must
// return the context error promptly instead of polling out the full
// provider-refresh window on behalf of a request that already went away.
func TestProviderRefresh_CancelledWaiter_ReturnsPromptly(t *testing.T) {
	srv, store, dex := newRefreshTestMemoryServer(t)
	ctx := context.Background()

	observed := staleProviderToken(dex)
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	// Another holder (e.g. another pod) owns the refresh lock for far longer
	// than any waiter would tolerate — the caller can only wait.
	_, acquired, err := store.AcquireProviderRefreshLock(ctx, refreshTestUserID, time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	waitCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, refreshErr := srv.refreshUserProviderToken(waitCtx, refreshTestUserID, observed)
		done <- refreshErr
	}()
	cancel()

	select {
	case refreshErr := <-done:
		require.ErrorIs(t, refreshErr, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled waiter kept waiting; it must return the caller's context error promptly")
	}
	require.Zero(t, dex.callCount(), "a cancelled waiter must never call the provider")
}

// TestProviderRefresh_CancelledLeader_DoesNotPoisonSiblings: the singleflight
// leader's request is cancelled while the provider round-trip is in flight.
// The leader returns its context error promptly, but the detached rotation
// completes, is written back, and the sibling caller adopts it — one caller's
// cancellation neither aborts nor poisons the refresh for the others.
func TestProviderRefresh_CancelledLeader_DoesNotPoisonSiblings(t *testing.T) {
	store := memory.New(memory.WithCleanupInterval(time.Hour))
	t.Cleanup(store.Stop)
	ctx := context.Background()

	var mu sync.Mutex
	calls := 0
	var startedOnce sync.Once
	refreshStarted := make(chan struct{})
	allowRefresh := make(chan struct{})
	refresh := func(_ context.Context, _ string) (*oauth2.Token, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		startedOnce.Do(func() { close(refreshStarted) })
		<-allowRefresh
		return &oauth2.Token{
			AccessToken:  "fresh-at",
			TokenType:    "Bearer",
			RefreshToken: "fresh-rt",
			Expiry:       time.Now().Add(30 * time.Minute),
		}, nil
	}
	srv := newRefreshTestServer(t, store, refresh)

	observed := &oauth2.Token{
		AccessToken:  "old-at",
		TokenType:    "Bearer",
		RefreshToken: "old-rt",
		Expiry:       time.Now().Add(2 * time.Minute),
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	leaderCtx, cancelLeader := context.WithCancel(ctx)
	leaderDone := make(chan error, 1)
	go func() {
		_, leaderErr := srv.refreshUserProviderToken(leaderCtx, refreshTestUserID, observed)
		leaderDone <- leaderErr
	}()
	<-refreshStarted // the leader has committed to the (detached) provider round-trip

	type joinResult struct {
		token *oauth2.Token
		err   error
	}
	joinerDone := make(chan joinResult, 1)
	go func() {
		tok, joinErr := srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
		joinerDone <- joinResult{tok, joinErr}
	}()

	cancelLeader()
	select {
	case leaderErr := <-leaderDone:
		require.ErrorIs(t, leaderErr, context.Canceled,
			"the cancelled leader must return promptly with its own context error")
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled leader did not return while the rotation was still in flight")
	}

	close(allowRefresh)
	select {
	case res := <-joinerDone:
		require.NoError(t, res.err, "a sibling caller must not inherit the cancelled leader's fate")
		require.Equal(t, "fresh-at", res.token.AccessToken)
		require.Equal(t, "fresh-rt", res.token.RefreshToken)
	case <-time.After(3 * time.Second):
		t.Fatal("sibling caller did not complete after the rotation was released")
	}

	require.Equal(t, 1, calls, "the rotation must reach the provider exactly once")

	// The detached rotation's write-back landed despite the leader's exit.
	shared, err := store.GetUserProviderToken(ctx, refreshTestUserID)
	require.NoError(t, err)
	require.Equal(t, "fresh-rt", shared.RefreshToken)
}

// unlockedStore hides the memory store's ProviderRefreshLockStore methods so
// the coordinator must take the uncoordinated fallback path — any dedup then
// comes purely from the same-pod singleflight, not from the per-user lock.
type unlockedStore struct {
	storage.Combined
	storage.UserProviderTokenStore
}

// TestProviderRefresh_SamePodCoalescing_WithoutRefreshLock: N concurrent
// same-pod callers on a backend WITHOUT a refresh lock still produce exactly
// one provider call — the per-user singleflight coalesces them within the
// process, independent of the cross-pod lock.
func TestProviderRefresh_SamePodCoalescing_WithoutRefreshLock(t *testing.T) {
	mem := memory.New(memory.WithCleanupInterval(time.Hour))
	t.Cleanup(mem.Stop)
	store := &unlockedStore{Combined: mem, UserProviderTokenStore: mem}
	ctx := context.Background()

	var mu sync.Mutex
	calls := 0
	var startedOnce sync.Once
	refreshStarted := make(chan struct{})
	allowRefresh := make(chan struct{})
	refresh := func(_ context.Context, _ string) (*oauth2.Token, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		startedOnce.Do(func() { close(refreshStarted) })
		<-allowRefresh
		return &oauth2.Token{
			AccessToken:  "fresh-at",
			TokenType:    "Bearer",
			RefreshToken: "fresh-rt",
			Expiry:       time.Now().Add(30 * time.Minute),
		}, nil
	}
	srv := newRefreshTestServer(t, store, refresh)

	// Sanity: the wrapper must NOT satisfy the lock interface, or this test
	// would silently exercise the lock instead of the singleflight.
	_, coordinated := srv.providerRefreshLocker()
	require.False(t, coordinated, "unlockedStore must hide ProviderRefreshLockStore")

	observed := &oauth2.Token{
		AccessToken:  "old-at",
		TokenType:    "Bearer",
		RefreshToken: "old-rt",
		Expiry:       time.Now().Add(2 * time.Minute),
	}
	require.NoError(t, store.SaveUserProviderToken(ctx, refreshTestUserID, observed))

	const n = 8
	start := make(chan struct{})
	tokens := make([]*oauth2.Token, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = srv.refreshUserProviderToken(ctx, refreshTestUserID, observed)
		}(i)
	}
	close(start)
	<-refreshStarted // one caller reached the provider; hold it briefly so siblings coalesce
	close(allowRefresh)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "caller %d must succeed", i)
		require.Equalf(t, "fresh-at", tokens[i].AccessToken, "caller %d must end with the shared fresh token", i)
	}
	require.Equal(t, 1, calls, "same-pod callers must coalesce into ONE provider call without any lock")
}
