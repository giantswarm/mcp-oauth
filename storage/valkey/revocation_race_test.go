package valkey

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	vk "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

type pausedFamilySnapshotClient struct {
	vk.Client
	familyKey string
	paused    chan struct{}
	resume    chan struct{}
	used      atomic.Bool
}

func (c *pausedFamilySnapshotClient) Do(ctx context.Context, command vk.Completed) vk.ValkeyResult {
	arguments := command.Commands()
	pause := len(arguments) == 2 && strings.EqualFold(arguments[0], "SMEMBERS") && arguments[1] == c.familyKey && c.used.CompareAndSwap(false, true)
	result := c.Client.Do(ctx, command)
	if pause {
		close(c.paused)
		select {
		case <-c.resume:
		case <-ctx.Done():
		}
	}
	return result
}

func TestFamilyRevocationRejectsConcurrentRefreshSuccessor(t *testing.T) {
	store := testStore(t)
	provider := mock.NewProvider()
	oauthServer, err := server.New(provider, store, store, store, &server.Config{Issuer: "https://auth.example.com"}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, oauthServer.Shutdown(context.WithoutCancel(t.Context()))) })
	expiresAt := time.Now().Add(time.Hour)
	providerToken := &oauth2.Token{AccessToken: "upstream-access", RefreshToken: "upstream-refresh", Expiry: expiresAt}
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", providerToken))
	for generation, refreshToken := range []string{"historical-refresh", "active-refresh"} {
		require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), refreshToken, "person", "client", "family", generation, expiresAt))
		require.NoError(t, store.SaveProviderTokenRef(t.Context(), refreshToken, "person", expiresAt))
		require.NoError(t, store.SaveTokenMetadata(t.Context(), refreshToken, storage.TokenMetadata{
			UserID: "person", ClientID: "client", TokenType: "refresh", FamilyID: "family",
			Audience: oauthServer.Config.GetResourceIdentifier(), ExpiresAt: expiresAt,
		}))
	}
	_, _, err = store.AtomicConsumeRefreshToken(t.Context(), "historical-refresh")
	require.NoError(t, err)
	wrapped := &pausedFamilySnapshotClient{
		Client: store.client, familyKey: store.familyKey("family"), paused: make(chan struct{}), resume: make(chan struct{}),
	}
	store.client = wrapped
	resumed := false
	defer func() {
		if !resumed {
			close(wrapped.resume)
		}
	}()
	revocationResult := make(chan error, 1)
	go func() {
		revocationResult <- oauthServer.RevokeToken(t.Context(), "historical-refresh", "client", "192.0.2.1")
	}()
	select {
	case <-wrapped.paused:
	case err := <-revocationResult:
		t.Fatalf("revocation returned before its snapshot: %v", err)
	case <-t.Context().Done():
		t.Fatal("revocation did not read its family snapshot")
	}
	successor, refreshError := oauthServer.RefreshAccessToken(t.Context(), "active-refresh", "client")
	close(wrapped.resume)
	resumed = true
	require.NoError(t, <-revocationResult)
	if refreshError != nil {
		require.ErrorContains(t, refreshError, "invalid_grant")
		return
	}
	require.NotNil(t, successor)
	_, accessError := oauthServer.ValidateToken(t.Context(), successor.AccessToken)
	_, nextRefreshError := oauthServer.RefreshAccessToken(t.Context(), successor.RefreshToken, "client")
	require.Error(t, accessError, "a successful family revocation must invalidate a concurrent opaque access successor")
	require.Error(t, nextRefreshError, "a successful family revocation must invalidate a concurrent refresh successor")
}

func TestFamilyRevocationFenceOutlivesLongLivedMembers(t *testing.T) {
	store := testStore(t)
	store.revokedFamilyRetentionDays = 1
	expiresAt := time.Now().Add(72 * time.Hour)
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "long-lived-refresh", "person", "client", "long-family", 0, expiresAt))
	require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "long-family"))
	remaining, err := store.client.Do(t.Context(), store.client.B().Ttl().Key(store.familyKey("long-family")).Build()).AsInt64()
	require.NoError(t, err)
	require.Greater(t, remaining, int64((71 * time.Hour).Seconds()))
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(store.refreshTokenMetaKey("long-lived-refresh")).Build()).Error())
	metadata, err := store.GetRefreshTokenFamilyByID(t.Context(), "long-family")
	require.NoError(t, err)
	require.True(t, metadata.Revoked)
	require.ErrorIs(t, store.SaveRefreshTokenWithFamily(t.Context(), "late-refresh", "person", "client", "long-family", 1, expiresAt), storage.ErrRefreshTokenFamilyRevoked)
	_, err = store.GetRefreshTokenInfo(t.Context(), "late-refresh")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestFamilyRevocationFenceIncludesAccessTokenAcceptanceHorizon(t *testing.T) {
	store := testStore(t)
	store.revokedFamilyRetentionDays = 1
	expiresAt := time.Now().Add(72 * time.Hour)
	retainUntil := expiresAt.Add(2 * time.Minute)
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "long-access", storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access", FamilyID: "access-family",
		ExpiresAt: expiresAt, RetainUntil: retainUntil,
	}))
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "short-refresh", "person", "client", "access-family", 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.RevokeRefreshTokenFamily(t.Context(), "access-family"))
	remaining, err := store.client.Do(t.Context(), store.client.B().Pttl().Key(store.familyKey("access-family")).Build()).AsInt64()
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Duration(remaining)*time.Millisecond+time.Millisecond, time.Until(retainUntil))
	_, err = store.GetTokenMetadata("long-access")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(store.refreshTokenMetaKey("short-refresh")).Build()).Error())
	family, err := store.GetRefreshTokenFamilyByID(t.Context(), "access-family")
	require.NoError(t, err)
	require.True(t, family.Revoked)
}
