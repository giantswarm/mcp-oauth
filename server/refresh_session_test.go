package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// seedFamilyForRefresh writes a refresh-token-family entry directly to the
// memory store so RefreshSession has something to look up. Returns the
// refresh token used so tests can assert it gets rotated.
func seedFamilyForRefresh(t *testing.T, store *memory.Store, userID, clientID, familyID, refreshToken string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, refreshToken, userID, clientID, familyID, 0, time.Now().Add(24*time.Hour),
	))
	// Also seed the user's shared provider-token entry (unified layout) so the
	// atomic consume + provider refresh path can run. Keyed by the same userID
	// that was recorded with the refresh token above.
	require.NoError(t, store.SaveUserProviderToken(ctx, userID, &oauth2.Token{
		AccessToken:  "provider-access",
		RefreshToken: "provider-refresh",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}))
}

func TestRefreshSession_HappyPath(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	ctx := context.Background()

	const (
		userID       = "user-1"
		clientID     = "client-x"
		familyID     = "fam-happy"
		refreshToken = "rt-happy-1"
	)
	seedFamilyForRefresh(t, store, userID, clientID, familyID, refreshToken)

	// Mock provider returns a fresh token on RefreshToken.
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}).WithExtra(map[string]any{"id_token": "new.id.token"}), nil
	}

	got, err := srv.RefreshSession(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotEmpty(t, got.AccessToken)
	require.NotEmpty(t, got.RefreshToken)
	// id_token forwarded from provider to the response.
	require.Equal(t, "new.id.token", got.Extra("id_token"))
}

func TestRefreshSession_FamilyNotFound(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	_, err := srv.RefreshSession(context.Background(), "no-such-family")
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrRefreshTokenFamilyNotFound), "want wrapped ErrRefreshTokenFamilyNotFound, got %v", err)
}

func TestRefreshSession_RevokedFamily(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)
	ctx := context.Background()

	const familyID = "fam-revoked"
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, "rt-revoked")

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	_, err := srv.RefreshSession(ctx, familyID)
	require.Error(t, err, "RefreshSession on a revoked family must fail")
	require.True(t, errors.Is(err, storage.ErrRefreshTokenFamilyRevoked),
		"want wrapped ErrRefreshTokenFamilyRevoked, got %v", err)
}

func TestRefreshSession_ProviderRefreshFails(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	ctx := context.Background()

	const familyID = "fam-provider-fail"
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, "rt-provider-fail")

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, fmt.Errorf("upstream IdP returned 500")
	}

	_, err := srv.RefreshSession(ctx, familyID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "upstream IdP returned 500")
}

func TestRefreshSession_RequiresFamilyID(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	_, err := srv.RefreshSession(context.Background(), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "familyID is required")
}

func TestRefreshSession_CoalescesConcurrentCalls(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	ctx := context.Background()

	const (
		familyID     = "fam-coalesce"
		refreshToken = "rt-coalesce" //nolint:gosec // G101 false positive — test fixture label, not a credential
	)
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, refreshToken)

	// Channel-based synchronization rather than time.Sleep:
	//   - the provider blocks on `release` until the test signals
	//   - the test launches all goroutines, waits for them to enqueue
	//     into the singleflight, then closes `release`
	// This removes any timing dependency — the test is correct under
	// arbitrary scheduler load.
	const concurrent = 8
	var providerCalls atomic.Int32
	release := make(chan struct{})
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		providerCalls.Add(1)
		<-release
		return &oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	var wg sync.WaitGroup
	started := make(chan struct{}, concurrent)
	results := make([]*oauth2.Token, concurrent)
	errs := make([]error, concurrent)

	for i := range concurrent {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			results[i], errs[i] = srv.RefreshSession(ctx, familyID)
		}(i)
	}

	// Wait for all goroutines to have entered RefreshSession. The
	// first one will be inside the provider RefreshTokenFunc waiting
	// on release; the others will be queued on the singleflight Do.
	for range concurrent {
		<-started
	}
	// Tiny grace period so the first call has reached the blocked
	// provider func before the rest pile into singleflight; without it
	// the very first goroutine could still be in setup and the second
	// could overtake into a second singleflight execution. Bounded by
	// the sync we just did, this is not a wall-clock dependence.
	require.Eventually(t, func() bool {
		return providerCalls.Load() == 1
	}, time.Second, 5*time.Millisecond, "first call should reach provider before others queue")

	close(release)
	wg.Wait()

	require.Equal(t, int32(1), providerCalls.Load(), "singleflight should coalesce concurrent calls into one provider hit")
	for i := range concurrent {
		require.NoError(t, errs[i], "call %d", i)
		require.NotNil(t, results[i], "call %d", i)
	}
}

// TestRefreshSession_SingleflightIgnoresCanceledLeaderContext pins the
// leader-detach contract on the refreshSessionGroup: a cancelled caller's
// context must not propagate into the upstream RefreshToken call, otherwise
// the joiner of a coalesced refresh would observe a spurious cancellation
// error.
func TestRefreshSession_SingleflightIgnoresCanceledLeaderContext(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	const (
		familyID     = "fam-canceled-leader"
		refreshToken = "rt-canceled-leader"
	)
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, refreshToken)

	provider.RefreshTokenFunc = func(ctx context.Context, _ string) (*oauth2.Token, error) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("refresh context unexpectedly canceled: %w", ctx.Err())
		}
		return &oauth2.Token{
			AccessToken:  "provider-access-new",
			RefreshToken: "provider-refresh-new",
			Expiry:       time.Now().Add(30 * time.Minute),
			TokenType:    "Bearer",
		}, nil
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := srv.RefreshSession(canceledCtx, familyID)
	require.NoError(t, err, "RefreshSession must complete the underlying provider refresh even when the caller's ctx is already canceled")
}
