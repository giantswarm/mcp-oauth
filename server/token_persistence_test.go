package server

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

func useLegacyGrantStore(fixture *faultyGrantFixture) {
	fixture.srv.tokenStore = legacyLayoutStore{
		Combined: fixture.faulty, RefreshTokenFamilyStore: fixture.faulty,
		TokenRevocationStore: fixture.faulty, TokenFamilyRevocationStore: fixture.faulty,
		TokenMetadataStore: fixture.faulty, TokenMetadataGetter: fixture.faulty,
		ProviderRefreshLockStore: fixture.faulty,
	}
}

func TestTokenGrant_WriteFailurePreservesGrant(t *testing.T) {
	for _, format := range []AccessTokenFormat{AccessTokenFormatOpaque, AccessTokenFormatJWT} {
		for _, legacy := range []bool{false, true} {
			for _, grant := range []string{"authorization_code", "refresh_token"} {
				for _, operation := range []string{"save_token_metadata", "save_provider_token_ref", "save_token", "save_refresh_token_with_family"} {
					if legacy && operation == "save_provider_token_ref" || !legacy && operation == "save_token" {
						continue
					}
					for _, failedWrite := range []int{1, 2} {
						if operation == "save_refresh_token_with_family" && failedWrite == 2 {
							continue
						}
						name := string(format) + "/legacy=" + strconv.FormatBool(legacy) + "/" + grant + "/" + operation + "/" + strconv.Itoa(failedWrite)
						t.Run(name, func(t *testing.T) {
							fixture := newFaultyFixture(t, format)
							if legacy {
								useLegacyGrantStore(fixture)
							}
							var exchange func() (*oauth2.Token, error)
							if grant == "authorization_code" {
								code, verifier := fixture.issueCode(t)
								exchange = func() (*oauth2.Token, error) {
									pair, _, err := fixture.srv.ExchangeAuthorizationCode(t.Context(), code, fixture.clientID, "https://example.com/callback", "", verifier, "bound-key")
									return pair, err
								}
							} else {
								pair := fixture.login(t)
								exchange = func() (*oauth2.Token, error) {
									return fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
								}
							}
							calls := 0
							fixture.faulty.Fail(storagemock.OnOperation(operation, func(ctx context.Context, operation string) error {
								calls++
								if calls == failedWrite {
									return storagemock.ConnectionRefused(ctx, operation)
								}
								return nil
							}))
							pair, err := exchange()
							require.ErrorIs(t, err, ErrStorageUnavailable)
							require.Nil(t, pair)
							fixture.faulty.Heal()
							pair, err = exchange()
							require.NoError(t, err, "the same grant must succeed after storage recovers")
							_, err = fixture.srv.ValidateToken(t.Context(), pair.AccessToken)
							require.NoError(t, err)
							metadata, err := fixture.srv.TokenMetadata(t.Context(), pair.AccessToken)
							require.NoError(t, err)
							require.Equal(t, fixture.srv.Config.GetResourceIdentifier(), metadata.Audience)
							require.ElementsMatch(t, []string{"openid", "email"}, metadata.Scopes)
							if grant == "authorization_code" {
								require.Equal(t, "bound-key", metadata.JKT)
							}
							_, err = fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
							require.NoError(t, err)
						})
					}
				}
			}
		}
	}
}

func TestRefreshAccessToken_MetadataFailureAfterProviderRotation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("legacy="+strconv.FormatBool(legacy), func(t *testing.T) {
			fixture := newFaultyFixture(t, AccessTokenFormatOpaque)
			if legacy {
				useLegacyGrantStore(fixture)
			}
			pair := fixture.login(t)
			metadata, err := fixture.srv.TokenMetadata(t.Context(), pair.RefreshToken)
			require.NoError(t, err)
			oldMetadata := *metadata
			oldMetadata.JKT = "bound-key"
			require.NoError(t, fixture.store.SaveTokenMetadata(t.Context(), pair.RefreshToken, oldMetadata))
			providerToken := testProviderToken()
			providerToken.Expiry = time.Now().Add(-time.Minute)
			if legacy {
				require.NoError(t, fixture.store.SaveToken(t.Context(), pair.RefreshToken, providerToken))
			} else {
				require.NoError(t, fixture.store.SaveUserProviderToken(t.Context(), metadata.UserID, providerToken))
			}
			var refreshCalls atomic.Int32
			fixture.provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
				if refreshCalls.Add(1) != 1 {
					return nil, errors.New("provider refresh credential was reused")
				}
				return &oauth2.Token{AccessToken: "rotated-provider-access", RefreshToken: "rotated-provider-refresh", Expiry: time.Now().Add(time.Hour)}, nil
			}
			fixture.faulty.Fail(storagemock.OnOperation("save_token_metadata", storagemock.ConnectionRefused))
			_, err = fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
			require.ErrorIs(t, err, ErrStorageUnavailable)
			fixture.faulty.Heal()
			refreshed, err := fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
			require.NoError(t, err)
			require.Equal(t, int32(1), refreshCalls.Load())
			for _, tokenID := range []string{refreshed.AccessToken, refreshed.RefreshToken} {
				metadata, err := fixture.srv.TokenMetadata(t.Context(), tokenID)
				require.NoError(t, err)
				require.Equal(t, "bound-key", metadata.JKT)
				require.Equal(t, oldMetadata.FamilyID, metadata.FamilyID)
				require.Equal(t, oldMetadata.Audience, metadata.Audience)
				require.ElementsMatch(t, oldMetadata.Scopes, metadata.Scopes)
			}
		})
	}
}

func TestNew_RequiresGrantPersistenceCapabilities(t *testing.T) {
	fixture := newFaultyFixture(t, AccessTokenFormatOpaque)
	for _, test := range []struct {
		name       string
		store      storage.TokenStore
		capability string
	}{
		{"metadata writes", struct {
			storage.TokenStore
			storage.TokenMetadataGetter
			storage.UserProviderTokenStore
		}{fixture.store, fixture.store, fixture.store}, "storage.TokenMetadataStore"},
		{"metadata reads", struct {
			storage.TokenStore
			storage.TokenMetadataStore
			storage.UserProviderTokenStore
		}{fixture.store, fixture.store, fixture.store}, "storage.TokenMetadataGetter"},
		{"legacy refresh lock", struct {
			storage.TokenStore
			storage.TokenMetadataStore
			storage.TokenMetadataGetter
		}{fixture.store, fixture.store, fixture.store}, "storage.ProviderRefreshLockStore"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := *fixture.srv.Config
			_, err := New(fixture.provider, test.store, fixture.store, fixture.store, &configuration, nil)
			require.ErrorContains(t, err, test.capability)
		})
	}
}

type codeReadHookStore struct {
	storage.FlowStore
	hook   func()
	called atomic.Bool
}

func (store *codeReadHookStore) GetAuthorizationCode(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	authorizationCode, err := store.FlowStore.GetAuthorizationCode(ctx, code)
	if err == nil && store.called.CompareAndSwap(false, true) {
		store.hook()
	}
	return authorizationCode, err
}

func TestExchangeAuthorizationCode_InvalidPKCERacingCommitRevokesFamily(t *testing.T) {
	fixture := newFaultyFixture(t, AccessTokenFormatOpaque)
	code, verifier := fixture.issueCode(t)
	var committed *oauth2.Token
	flowStore := &codeReadHookStore{FlowStore: fixture.faulty}
	flowStore.hook = func() {
		var err error
		committed, _, err = fixture.srv.ExchangeAuthorizationCode(t.Context(), code, fixture.clientID, "https://example.com/callback", "", verifier, "")
		require.NoError(t, err)
	}
	fixture.srv.flowStore = flowStore
	pair, _, err := fixture.srv.ExchangeAuthorizationCode(t.Context(), code, fixture.clientID, "https://example.com/callback", "", "invalid-verifier", "")
	require.Error(t, err)
	require.Nil(t, pair)
	require.NotNil(t, committed)
	_, err = fixture.srv.ValidateToken(t.Context(), committed.AccessToken)
	require.Error(t, err, "a competing code presentation must revoke the committed family")
}

func TestRefreshAccessToken_LegacyConcurrentServersRotateProviderOnce(t *testing.T) {
	fixture := newFaultyFixture(t, AccessTokenFormatOpaque)
	useLegacyGrantStore(fixture)
	pair := fixture.login(t)
	metadata, err := fixture.srv.TokenMetadata(t.Context(), pair.RefreshToken)
	require.NoError(t, err)
	providerToken := testProviderToken()
	providerToken.Expiry = time.Now().Add(-time.Minute)
	require.NoError(t, fixture.store.SaveToken(t.Context(), pair.RefreshToken, providerToken))
	configuration := *fixture.srv.Config
	second, err := New(fixture.provider, fixture.srv.tokenStore, fixture.faulty, fixture.faulty, &configuration, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Shutdown(t.Context()) })
	started := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	var refreshCalls atomic.Int32
	fixture.provider.RefreshTokenFunc = func(ctx context.Context, _ string) (*oauth2.Token, error) {
		if refreshCalls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &oauth2.Token{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	}
	results := make(chan error, 2)
	initialReads := fixture.faulty.Calls("get_refresh_token_info")
	go func() {
		_, err := fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
		results <- err
	}()
	<-started
	go func() {
		_, err := second.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
		results <- err
	}()
	require.Eventually(t, func() bool { return fixture.faulty.Calls("get_refresh_token_info") >= initialReads+2 }, time.Second, time.Millisecond)
	releaseOnce()
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, errInvalidGrant)
		}
	}
	require.LessOrEqual(t, successes, 1)
	require.Equal(t, int32(1), refreshCalls.Load())
	family, err := fixture.store.GetRefreshTokenFamilyByID(t.Context(), metadata.FamilyID)
	require.NoError(t, err)
	require.True(t, family.Revoked)
}
