package server

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestValidateToken_UnsecuredJWTNeverReachesUserinfo(t *testing.T) {
	harness := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(harness)
	encode := base64.RawURLEncoding.EncodeToString
	bearer := encode([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + encode([]byte(`{"iss":"https://other.example","aud":"other-resource","exp":1}`)) + "."
	calls := harness.provider.GetCallCount("ValidateToken")

	userInfo, err := harness.srv.ValidateToken(t.Context(), bearer)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Equal(t, calls, harness.provider.GetCallCount("ValidateToken"))
}

func TestValidateToken_StoredBearerRequiresAccessTokenMetadata(t *testing.T) {
	for _, test := range []struct {
		name          string
		tokenType     string
		metadata      bool
		audience      string
		accepted      bool
		emptyProvider bool
		hideMetadata  bool
	}{
		{name: "missing metadata"},
		{name: "missing token type", metadata: true, audience: "https://auth.example.com"},
		{name: "refresh token", tokenType: "refresh", metadata: true, audience: "https://auth.example.com"},
		{name: "ID token", tokenType: "id", metadata: true, audience: "https://auth.example.com"},
		{name: "missing audience", tokenType: "access", metadata: true},
		{name: "foreign audience", tokenType: "access", metadata: true, audience: "https://other.example.com"},
		{name: "empty provider access token", tokenType: "access", metadata: true, audience: "https://auth.example.com", emptyProvider: true},
		{name: "store without metadata support", tokenType: "access", metadata: true, audience: "https://auth.example.com", hideMetadata: true},
		{name: "issued access token", tokenType: "access", metadata: true, audience: "https://auth.example.com", accepted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, layout := range []struct {
				name   string
				legacy bool
			}{{"unified", false}, {"legacy", true}} {
				t.Run(layout.name, func(t *testing.T) {
					srv, store, provider := setupFlowTestServer(t)
					const bearer = "stored-bearer"
					providerToken := testProviderToken()
					if test.emptyProvider {
						providerToken.AccessToken = ""
					}
					if layout.legacy {
						srv.tokenStore = struct {
							storage.TokenStore
							storage.TokenMetadataGetter
						}{store, store}
						require.NoError(t, store.SaveToken(t.Context(), bearer, providerToken))
					} else {
						require.NoError(t, store.SaveUserProviderToken(t.Context(), testUserID, providerToken))
						require.NoError(t, store.SaveProviderTokenRef(t.Context(), bearer, testUserID, time.Now().Add(time.Hour)))
					}
					if test.metadata {
						require.NoError(t, store.SaveTokenMetadata(t.Context(), bearer, storage.TokenMetadata{
							UserID: testUserID, ClientID: "client", TokenType: test.tokenType, ExpiresAt: time.Now().Add(time.Hour), Audience: test.audience,
						}))
					}
					if test.hideMetadata {
						if layout.legacy {
							srv.tokenStore = struct{ storage.TokenStore }{store}
						} else {
							srv.tokenStore = struct {
								storage.TokenStore
								storage.UserProviderTokenStore
							}{store, store}
						}
					}
					calls := provider.GetCallCount("ValidateToken")
					refreshCalls := provider.GetCallCount("RefreshToken")

					userInfo, err := srv.ValidateToken(t.Context(), bearer)

					if test.accepted {
						require.NoError(t, err)
						require.NotNil(t, userInfo)
						require.Equal(t, calls+1, provider.GetCallCount("ValidateToken"))
					} else {
						require.Error(t, err)
						require.NotErrorIs(t, err, ErrStorageUnavailable)
						require.Nil(t, userInfo)
						require.Equal(t, calls, provider.GetCallCount("ValidateToken"))
					}
					require.Equal(t, refreshCalls, provider.GetCallCount("RefreshToken"))
				})
			}
		})
	}
}

func TestValidateToken_IssuedRefreshTokenRejectedAsBearer(t *testing.T) {
	for _, format := range []AccessTokenFormat{AccessTokenFormatOpaque, AccessTokenFormatJWT} {
		t.Run(string(format), func(t *testing.T) {
			fixture := newFaultyFixture(t, format)
			pair := fixture.login(t)
			metadata, err := fixture.srv.TokenMetadata(t.Context(), pair.AccessToken)
			require.NoError(t, err)
			require.Equal(t, fixture.srv.Config.GetResourceIdentifier(), metadata.Audience)
			providerCalls := fixture.provider.GetCallCount("ValidateToken")
			refreshCalls := fixture.provider.GetCallCount("RefreshToken")

			userInfo, err := fixture.srv.ValidateToken(t.Context(), pair.RefreshToken)

			require.ErrorIs(t, err, errInvalidAccessToken)
			require.Nil(t, userInfo)
			require.Equal(t, providerCalls, fixture.provider.GetCallCount("ValidateToken"))
			require.Equal(t, refreshCalls, fixture.provider.GetCallCount("RefreshToken"))
			_, err = fixture.srv.ValidateToken(t.Context(), pair.AccessToken)
			require.NoError(t, err)
			refreshed, err := fixture.srv.RefreshAccessToken(t.Context(), pair.RefreshToken, fixture.clientID)
			require.NoError(t, err)
			metadata, err = fixture.srv.TokenMetadata(t.Context(), refreshed.AccessToken)
			require.NoError(t, err)
			require.Equal(t, fixture.srv.Config.GetResourceIdentifier(), metadata.Audience)
		})
	}
}

func TestValidateToken_AccessTokenExpiryDoesNotFollowProviderRefresh(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	const bearer = "expired-local-access-token"
	seedProviderToken(t, store, bearer, testUserID, &oauth2.Token{
		AccessToken: "live-provider-token", RefreshToken: "live-provider-refresh", Expiry: time.Now().Add(time.Hour),
	})
	require.NoError(t, store.SaveTokenMetadata(t.Context(), bearer, storage.TokenMetadata{
		UserID: testUserID, ClientID: "client", TokenType: "access", ExpiresAt: time.Now().Add(-time.Hour), Audience: srv.Config.GetResourceIdentifier(),
	}))
	calls := provider.GetCallCount("ValidateToken")
	refreshCalls := provider.GetCallCount("RefreshToken")

	_, err := srv.ValidateToken(t.Context(), bearer)

	require.ErrorIs(t, err, errInvalidAccessToken)
	require.ErrorContains(t, err, "expired")
	require.Equal(t, calls, provider.GetCallCount("ValidateToken"))
	require.Equal(t, refreshCalls, provider.GetCallCount("RefreshToken"))
}
