package storage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TestUserProviderToken_BackendParity verifies that the memory and valkey
// backends implement storage.UserProviderTokenStore identically: one shared
// provider-token entry per user, token-key → user references instead of
// copies, and an atomic refresh-token consume that feeds OAuth 2.1 reuse
// detection without requiring a provider-token copy at the refresh-token key.
//
// This is the storage half of the rotation-race fix
// (giantswarm/giantswarm#37164 root cause 2, mcp-oauth#512).
func TestUserProviderToken_BackendParity(t *testing.T) {
	backends := []struct {
		name    string
		factory func(t *testing.T) storage.Combined
	}{
		{name: storage.BackendMemory, factory: newMemoryBackend},
		{name: storage.BackendValkey, factory: newValkeyBackend},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("shared_entry_roundtrip_preserves_fields", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))
				ctx := t.Context()

				expiry := time.Now().Add(30 * time.Minute).Truncate(time.Second)
				token := (&oauth2.Token{
					AccessToken:  "dex-at-1",
					RefreshToken: "dex-rt-1",
					TokenType:    "Bearer",
					Expiry:       expiry,
				}).WithExtra(map[string]interface{}{"id_token": "id-token-jwt"})

				require.NoError(t, s.SaveUserProviderToken(ctx, "user-a", token))

				got, err := s.GetUserProviderToken(ctx, "user-a")
				require.NoError(t, err)
				require.Equal(t, "dex-at-1", got.AccessToken)
				require.Equal(t, "dex-rt-1", got.RefreshToken)
				require.Equal(t, "id-token-jwt", got.Extra("id_token"))
				require.WithinDuration(t, expiry, got.Expiry, time.Second,
					"the shared entry must carry the provider's REAL expiry")
			})

			t.Run("expired_entry_with_refresh_token_still_readable", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))
				ctx := t.Context()

				require.NoError(t, s.SaveUserProviderToken(ctx, "user-expired-rt", &oauth2.Token{
					AccessToken:  "dex-at-old",
					RefreshToken: "dex-rt-old",
					Expiry:       time.Now().Add(-10 * time.Minute),
				}))

				got, err := s.GetUserProviderToken(ctx, "user-expired-rt")
				require.NoError(t, err,
					"an expired entry with a refresh token must be returned so the caller can refresh it")
				require.Equal(t, "dex-rt-old", got.RefreshToken)
			})

			t.Run("missing_entry_returns_not_found", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))

				_, err := s.GetUserProviderToken(t.Context(), "user-unknown")
				require.ErrorIs(t, err, storage.ErrTokenNotFound)
			})

			t.Run("delete_entry", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))
				ctx := t.Context()

				require.NoError(t, s.SaveUserProviderToken(ctx, "user-del", &oauth2.Token{
					AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour),
				}))
				require.NoError(t, s.DeleteUserProviderToken(ctx, "user-del"))

				_, err := s.GetUserProviderToken(ctx, "user-del")
				require.ErrorIs(t, err, storage.ErrTokenNotFound)
			})

			t.Run("refs_resolve_to_single_shared_entry_after_rotation", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))
				ctx := t.Context()
				exp := time.Now().Add(time.Hour)

				// Two sessions of one user: each token is a reference, not a copy.
				require.NoError(t, s.SaveUserProviderToken(ctx, "user-rot", &oauth2.Token{
					AccessToken: "dex-at-0", RefreshToken: "dex-rt-0", Expiry: time.Now().Add(30 * time.Minute),
				}))
				require.NoError(t, s.SaveProviderTokenRef(ctx, "mcp-at-session1", "user-rot", exp))
				require.NoError(t, s.SaveProviderTokenRef(ctx, "mcp-at-session2", "user-rot", exp))

				// Session 1 rotates: writes back to the ONE shared entry.
				require.NoError(t, s.SaveUserProviderToken(ctx, "user-rot", &oauth2.Token{
					AccessToken: "dex-at-1", RefreshToken: "dex-rt-1", Expiry: time.Now().Add(30 * time.Minute),
				}))

				// BOTH sessions immediately see the fresh token — no stale copy remains.
				for _, tokenID := range []string{"mcp-at-session1", "mcp-at-session2"} {
					userID, err := s.GetProviderTokenRef(ctx, tokenID)
					require.NoError(t, err)
					require.Equal(t, "user-rot", userID)

					got, err := s.GetUserProviderToken(ctx, userID)
					require.NoError(t, err)
					require.Equal(t, "dex-rt-1", got.RefreshToken,
						"reader via %s must see the rotated token", tokenID)
				}
			})

			t.Run("ref_missing_returns_not_found_and_delete_is_idempotent", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))
				ctx := t.Context()

				_, err := s.GetProviderTokenRef(ctx, "ref-unknown")
				require.ErrorIs(t, err, storage.ErrTokenNotFound)
				require.NoError(t, s.DeleteProviderTokenRef(ctx, "ref-unknown"))
			})

			t.Run("atomic_consume_single_use_and_reuse_detection_parity", func(t *testing.T) {
				combined := b.factory(t)
				s := requireUserProviderTokenStore(t, combined)
				family, ok := combined.(storage.RefreshTokenFamilyStore)
				require.True(t, ok, "backend must support refresh token families")
				ctx := t.Context()

				rt := fmt.Sprintf("mcp-rt-consume-%s", b.name)
				exp := time.Now().Add(time.Hour)
				require.NoError(t, family.SaveRefreshTokenWithFamily(ctx, rt, "user-consume", "client-1", "family-1", 0, exp))
				require.NoError(t, s.SaveProviderTokenRef(ctx, rt, "user-consume", exp))

				userID, clientID, err := s.AtomicConsumeRefreshToken(ctx, rt)
				require.NoError(t, err)
				require.Equal(t, "user-consume", userID)
				require.Equal(t, "client-1", clientID)

				// Single use: the second consume fails with not-found …
				_, _, err = s.AtomicConsumeRefreshToken(ctx, rt)
				require.ErrorIs(t, err, storage.ErrTokenNotFound)

				// … and its ref is gone,
				_, err = s.GetProviderTokenRef(ctx, rt)
				require.ErrorIs(t, err, storage.ErrTokenNotFound)

				// … while the family metadata persists for reuse detection.
				meta, err := family.GetRefreshTokenFamily(ctx, rt)
				require.NoError(t, err, "family metadata must survive the consume for OAuth 2.1 reuse detection")
				require.Equal(t, "family-1", meta.FamilyID)
				require.False(t, meta.Revoked)
			})

			t.Run("atomic_consume_unknown_token_not_found", func(t *testing.T) {
				s := requireUserProviderTokenStore(t, b.factory(t))

				_, _, err := s.AtomicConsumeRefreshToken(t.Context(), "rt-never-issued")
				require.ErrorIs(t, err, storage.ErrTokenNotFound)
			})

			t.Run("revoke_all_for_user_client_deletes_refs", func(t *testing.T) {
				combined := b.factory(t)
				s := requireUserProviderTokenStore(t, combined)
				metaStore, ok := combined.(storage.TokenMetadataStore)
				require.True(t, ok)
				revocation, ok := combined.(storage.TokenRevocationStore)
				require.True(t, ok)
				ctx := t.Context()

				exp := time.Now().Add(time.Hour)
				require.NoError(t, s.SaveUserProviderToken(ctx, "user-nuke", &oauth2.Token{
					AccessToken: "dex-at", RefreshToken: "dex-rt", Expiry: time.Now().Add(30 * time.Minute),
				}))
				require.NoError(t, s.SaveProviderTokenRef(ctx, "mcp-at-nuke", "user-nuke", exp))
				require.NoError(t, metaStore.SaveTokenMetadata(ctx, "mcp-at-nuke", storage.TokenMetadata{
					UserID: "user-nuke", ClientID: "client-nuke", TokenType: "access",
					IssuedAt: time.Now(), ExpiresAt: exp,
				}))

				_, err := revocation.RevokeAllTokensForUserClient(ctx, "user-nuke", "client-nuke")
				require.NoError(t, err)

				_, err = s.GetProviderTokenRef(ctx, "mcp-at-nuke")
				require.ErrorIs(t, err, storage.ErrTokenNotFound,
					"user+client revocation must delete the token's provider reference")
			})
		})
	}
}

// requireUserProviderTokenStore asserts the backend implements the optional
// unified store interface.
func requireUserProviderTokenStore(t *testing.T, s storage.Combined) storage.UserProviderTokenStore {
	t.Helper()
	upts, ok := s.(storage.UserProviderTokenStore)
	require.True(t, ok, "backend must implement storage.UserProviderTokenStore")
	return upts
}
