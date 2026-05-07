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
	// Also seed the provider token so the Atomic delete + provider refresh path can run.
	require.NoError(t, store.SaveToken(ctx, refreshToken, &oauth2.Token{
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
	// After revoke, GetActiveRefreshTokenByFamily returns
	// ErrRefreshTokenFamilyNotFound (no non-revoked entry); the family
	// metadata lookup also flags Revoked. Either path produces an error.
	require.NotContains(t, err.Error(), "no error", "sanity")
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
		refreshToken = "rt-coalesce"
	)
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, refreshToken)

	var providerCalls atomic.Int32
	// Block briefly inside the provider call so concurrent callers all
	// arrive at the singleflight before the first one finishes.
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		providerCalls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return &oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	const concurrent = 8
	var wg sync.WaitGroup
	results := make([]*oauth2.Token, concurrent)
	errs := make([]error, concurrent)

	for i := range concurrent {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = srv.RefreshSession(ctx, familyID)
		}(i)
	}
	wg.Wait()

	require.Equal(t, int32(1), providerCalls.Load(), "singleflight should coalesce concurrent calls into one provider hit")
	for i := range concurrent {
		require.NoError(t, errs[i], "call %d", i)
		require.NotNil(t, results[i], "call %d", i)
	}
}
