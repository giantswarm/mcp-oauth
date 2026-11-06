package server

import (
	"context"
	"encoding/base64"
	"testing"
	"testing/synctest"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

// userinfoAcceptsAnything makes the provider answer userinfo for any bearer.
func userinfoAcceptsAnything(h *forwardedTokenHarness) {
	h.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		return &providers.UserInfo{ID: "user-subject-123", Email: "user@test.example"}, nil
	}
}

// tokenForAnotherClient is a provider-signed ID token whose audience is
// neither this server nor a TrustedAudiences entry.
func tokenForAnotherClient(t *testing.T, h *forwardedTokenHarness) string {
	t.Helper()
	claims := h.validClaims()
	claims.Audience = josejwt.Audience{"another-client"}
	return h.signToken(t, claims)
}

// expiredForwardedToken is a provider-signed ID token for a TrustedAudiences
// entry whose exp has passed.
func expiredForwardedToken(t *testing.T, h *forwardedTokenHarness) string {
	t.Helper()
	claims := h.validClaims()
	claims.IssuedAt = josejwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	claims.Expiry = josejwt.NewNumericDate(time.Now().Add(-time.Hour))
	return h.signToken(t, claims)
}

func TestValidateToken_RefusesJWTFromAnotherIssuer(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	audit := captureAudit(h.srv)

	calls := h.provider.GetCallCount("ValidateToken")
	claims := h.validClaims()
	claims.Issuer = "https://another-issuer.example"
	claims.Audience = josejwt.Audience{"another-client"}
	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, claims))

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"), "the bearer must not reach userinfo")
	line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
	require.Equal(t, auditReasonUnknownJWTBearer, line.Details["reason"])
}

func TestValidateToken_RefusesJWTForAnotherClient(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	audit := captureAudit(h.srv)

	calls := h.provider.GetCallCount("ValidateToken")
	userInfo, err := h.srv.ValidateToken(t.Context(), tokenForAnotherClient(t, h))

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"), "the bearer must not reach userinfo")
	line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
	require.Equal(t, auditReasonUnknownJWTBearer, line.Details["reason"])
}

func TestValidateToken_RefusesCompactJWE(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	enc := base64.RawURLEncoding.EncodeToString
	jwe := enc([]byte(`{"alg":"dir","enc":"A256GCM"}`)) + ".." + enc([]byte("iv")) + "." + enc([]byte("ciphertext")) + "." + enc([]byte("tag"))

	calls := h.provider.GetCallCount("ValidateToken")
	_, err := h.srv.ValidateToken(t.Context(), jwe)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
}

func TestValidateToken_AcceptsReturnedIDToken(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	idToken := tokenForAnotherClient(t, h)
	require.NoError(t, h.srv.tokenStore.(storage.RefreshTokenFamilyStore).SaveRefreshTokenWithFamily(
		t.Context(), "refresh-1", "user-subject-123", "client-1", "family-1", 0, time.Now().Add(time.Hour)))
	h.srv.saveIDTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
		UserID: "user-subject-123", ClientID: "client-1", FamilyID: "family-1",
	})

	userInfo, err := h.srv.ValidateToken(t.Context(), idToken)

	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
}

func TestValidateToken_RefusesExpiredReturnedIDToken(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	idToken := tokenForAnotherClient(t, h)
	require.NoError(t, h.srv.tokenStore.(storage.TokenMetadataStore).SaveTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
		UserID: "user-subject-123", ClientID: "client-1", FamilyID: "family-1",
		TokenType: "id", ExpiresAt: time.Now().Add(-time.Minute),
	}))

	_, err := h.srv.ValidateToken(t.Context(), idToken)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
}

func TestValidateToken_RefusesJWTWithOtherMetadata(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	bearer := tokenForAnotherClient(t, h)
	require.NoError(t, h.srv.tokenStore.(storage.TokenMetadataStore).SaveTokenMetadata(t.Context(), bearer, storage.TokenMetadata{
		UserID: "user-subject-123", ClientID: "client-1", TokenType: "access",
	}))

	_, err := h.srv.ValidateToken(t.Context(), bearer)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
}

func TestValidateToken_KeepsTrustedAudienceForwarding(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)

	calls := h.provider.GetCallCount("ValidateToken")
	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, h.validClaims()))

	require.NoError(t, err)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
}

func TestValidateToken_InvalidForwardedIDToken(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	audit := captureAudit(h.srv)

	calls := h.provider.GetCallCount("ValidateToken")
	_, err := h.srv.ValidateToken(t.Context(), expiredForwardedToken(t, h))

	require.ErrorContains(t, err, "forwarded ID token validation failed")
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"), "the bearer must not reach userinfo")
	line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
	require.Equal(t, auditReasonForwardedIDTokenInvalid, line.Details["reason"])
}

func TestValidateToken_OpaqueBearerUnchanged(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)

	calls := h.provider.GetCallCount("ValidateToken")
	userInfo, err := h.srv.ValidateToken(t.Context(), "opaque-provider-token")

	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, calls+1, h.provider.GetCallCount("ValidateToken"))
}

func TestSaveIDTokenMetadata_KeepsPairDPoPBinding(t *testing.T) {
	h := newForwardedTokenHarness(t)
	idToken := tokenForAnotherClient(t, h)
	h.srv.saveIDTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
		UserID: "user-subject-123", ClientID: "client-1", FamilyID: "family-1", JKT: "pair-jkt",
	})

	metadata, err := h.srv.TokenMetadata(t.Context(), idToken)

	require.NoError(t, err)
	require.Equal(t, "id", metadata.TokenType)
	require.Equal(t, "pair-jkt", metadata.JKT)
}

// TestValidateToken_RevokedPairEndsReturnedIDToken:
// revoking the refresh token (RFC 7009) revokes its family, and the id_token
// returned with that family's pair is refused from then on.
func TestValidateToken_RevokedPairEndsReturnedIDToken(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	idToken := makeIDTokenWithExpiry(t, "user-id-meta", time.Now().Add(30*time.Minute))
	token, clientID := mintTokensWithIDToken(t, srv, store, provider, idToken)
	provider.ValidateTokenFunc = setupValidTokenProvider()

	_, err := srv.ValidateToken(t.Context(), idToken)
	require.NoError(t, err)

	require.NoError(t, srv.RevokeToken(t.Context(), token.RefreshToken, clientID, "192.168.1.100"))

	_, err = srv.ValidateToken(t.Context(), idToken)
	require.ErrorIs(t, err, ErrUnknownJWTBearer)
}

func TestValidateToken_ReturnedIDTokenStaysRevokedAfterFamilyRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := memory.New(memory.WithRevokedFamilyRetentionDays(1), memory.WithCleanupInterval(time.Hour))
		t.Cleanup(store.Stop)
		provider := mock.NewProvider()
		srv, err := New(provider, store, store, store, &Config{
			Issuer:                      "https://auth.example.com",
			DisableNonceEchoRequirement: true,
			DisableDNSValidation:        true,
		}, nil)
		require.NoError(t, err)
		idToken := makeIDTokenWithExpiry(t, "user-id-meta", time.Now().Add(48*time.Hour))
		token, clientID := mintTokensWithIDToken(t, srv, store, provider, idToken)
		provider.ValidateTokenFunc = setupValidTokenProvider()

		_, err = srv.ValidateToken(t.Context(), idToken)
		require.NoError(t, err)
		require.NoError(t, srv.RevokeToken(t.Context(), token.RefreshToken, clientID, "192.168.1.100"))
		_, err = srv.ValidateToken(t.Context(), idToken)
		require.ErrorIs(t, err, ErrUnknownJWTBearer)

		time.Sleep(26 * time.Hour)
		synctest.Wait()
		metadata, err := store.GetTokenMetadata(idToken)
		require.NoError(t, err)
		_, err = store.GetRefreshTokenFamilyByID(t.Context(), metadata.FamilyID)
		require.ErrorIs(t, err, storage.ErrRefreshTokenFamilyNotFound)

		_, err = srv.ValidateToken(t.Context(), idToken)
		require.ErrorIs(t, err, ErrUnknownJWTBearer)
		audit := captureAudit(srv)
		_, err = srv.ValidateToken(t.Context(), idToken)
		require.ErrorIs(t, err, ErrUnknownJWTBearer)
		line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
		require.Equal(t, auditReasonIDTokenFamilyRevoked, line.Details["reason"])
	})
}

func TestValidateToken_ReturnedIDTokenSurvivesAccessRevocationAndRefreshRotation(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.TokenRefreshThreshold = 7200
	idToken := makeIDTokenWithExpiry(t, "user-rotation", time.Now().Add(30*time.Minute))
	token, clientID := mintTokensWithIDToken(t, srv, store, provider, idToken)
	provider.ValidateTokenFunc = setupValidTokenProvider()
	require.NoError(t, srv.RevokeToken(t.Context(), token.AccessToken, clientID, "192.168.1.100"))
	_, err := srv.ValidateToken(t.Context(), idToken)
	require.NoError(t, err)

	rotatedIDToken := makeIDTokenWithExpiry(t, "user-rotation", time.Now().Add(time.Hour))
	provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken: "rotated-provider-access", RefreshToken: "rotated-provider-refresh",
			Expiry: time.Now().Add(time.Hour),
		}).WithExtra(map[string]any{"id_token": rotatedIDToken}), nil
	}
	refreshed, err := srv.RefreshAccessToken(t.Context(), token.RefreshToken, clientID)
	require.NoError(t, err)
	require.NotEqual(t, token.RefreshToken, refreshed.RefreshToken)
	for _, bearer := range []string{idToken, rotatedIDToken} {
		_, err = srv.ValidateToken(t.Context(), bearer)
		require.NoError(t, err)
	}
	require.NoError(t, srv.RevokeToken(t.Context(), refreshed.RefreshToken, clientID, "192.168.1.100"))
	for _, bearer := range []string{idToken, rotatedIDToken} {
		_, err = srv.ValidateToken(t.Context(), bearer)
		require.ErrorIs(t, err, ErrUnknownJWTBearer)
	}
}

func TestValidateToken_ReturnedIDTokenRequiresKnownFamily(t *testing.T) {
	for _, familyID := range []string{"", "missing-family"} {
		t.Run("family="+familyID, func(t *testing.T) {
			h := newForwardedTokenHarness(t)
			userinfoAcceptsAnything(h)
			idToken := tokenForAnotherClient(t, h)
			h.srv.saveIDTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
				UserID: "user-subject-123", ClientID: "client-1", FamilyID: familyID,
			})
			_, err := h.srv.ValidateToken(t.Context(), idToken)
			require.ErrorIs(t, err, ErrUnknownJWTBearer)
		})
	}
}

func TestValidateToken_ReturnedIDTokenFamilyReadFailureIsUnavailable(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	store := storagemock.NewFaultyStore(h.srv.tokenStore.(*memory.Store), time.Millisecond)
	h.srv.tokenStore = store
	idToken := tokenForAnotherClient(t, h)
	h.srv.saveIDTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
		UserID: "user-subject-123", ClientID: "client-1", FamilyID: "family-1",
	})
	store.Fail(storagemock.OnOperation("get_refresh_token_family_by_id", storagemock.ConnectionRefused))
	_, err := h.srv.ValidateToken(t.Context(), idToken)
	require.ErrorIs(t, err, ErrStorageUnavailable)
}
