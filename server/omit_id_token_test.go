package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage"
)

const omitTestIDToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.signature" //nolint:gosec // test value

// TestOmitIDTokenInTokenResponse_AuthorizationCode checks that the option
// removes the upstream id_token from the authorization_code response and
// keeps it in the stored provider token.
func TestOmitIDTokenInTokenResponse_AuthorizationCode(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[omit], func(t *testing.T) {
			ctx := context.Background()
			srv, store, _ := setupFlowTestServer(t)
			srv.Config.OmitIDTokenInTokenResponse = omit

			client, _, err := srv.RegisterClient(ctx, "Test Client", ClientTypeConfidential, "",
				[]string{"https://example.com/callback"}, []string{"openid"}, "192.168.1.100", 10)
			require.NoError(t, err)

			verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
			hash := sha256.Sum256([]byte(verifier))

			userID := "omit-id-token-user"
			providerToken := (&oauth2.Token{
				AccessToken:  "provider-access-token",
				RefreshToken: "provider-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			}).WithExtra(map[string]any{"id_token": omitTestIDToken})
			// The provider callback stores the provider token before the code exchange.
			require.NoError(t, store.SaveUserProviderToken(ctx, userID, providerToken))

			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            client.ClientID,
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid",
				CodeChallenge:       base64.RawURLEncoding.EncodeToString(hash[:]),
				CodeChallengeMethod: PKCEMethodS256,
				UserID:              userID,
				ProviderToken:       providerToken,
				CreatedAt:           time.Now(),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}
			require.NoError(t, store.SaveAuthorizationCode(ctx, authCode))

			token, _, err := srv.ExchangeAuthorizationCode(ctx, authCode.Code, client.ClientID,
				"https://example.com/callback", "", verifier, "")
			require.NoError(t, err)

			if omit {
				require.Empty(t, ExtractIDToken(token), "token response must not carry the upstream id_token")
			} else {
				require.Equal(t, omitTestIDToken, ExtractIDToken(token))
			}

			stored, err := srv.resolveProviderToken(ctx, token.AccessToken)
			require.NoError(t, err)
			require.Equal(t, omitTestIDToken, ExtractIDToken(stored), "stored provider token must keep the id_token")
		})
	}
}

// TestOmitIDTokenInTokenResponse_RefreshToken checks that the option removes
// the upstream id_token from the refresh_token response and keeps it in the
// stored provider token.
func TestOmitIDTokenInTokenResponse_RefreshToken(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[omit], func(t *testing.T) {
			ctx := context.Background()
			srv, store, provider := setupFlowTestServer(t)
			srv.Config.OmitIDTokenInTokenResponse = omit

			provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
				return (&oauth2.Token{
					AccessToken:  "new-provider-access-token",
					RefreshToken: "new-provider-refresh-token",
					Expiry:       time.Now().Add(time.Hour),
				}).WithExtra(map[string]any{"id_token": omitTestIDToken}), nil
			}

			clientID := "test-client"
			userID := "omit-id-token-user"
			refreshToken := "omit-id-token-refresh-token"
			require.NoError(t, store.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, "family-omit", 0, time.Now().Add(time.Hour)))
			// Expired, so the grant refreshes upstream.
			require.NoError(t, store.SaveUserProviderToken(ctx, userID, &oauth2.Token{
				AccessToken:  "provider-access-token",
				RefreshToken: "provider-refresh-token",
				Expiry:       time.Now().Add(-time.Minute),
			}))

			token, err := srv.RefreshAccessToken(ctx, refreshToken, clientID)
			require.NoError(t, err)

			if omit {
				require.Empty(t, ExtractIDToken(token), "token response must not carry the upstream id_token")
			} else {
				require.Equal(t, omitTestIDToken, ExtractIDToken(token))
			}

			stored, err := store.GetUserProviderToken(ctx, userID)
			require.NoError(t, err)
			require.Equal(t, omitTestIDToken, ExtractIDToken(stored), "stored provider token must keep the id_token")
		})
	}
}
