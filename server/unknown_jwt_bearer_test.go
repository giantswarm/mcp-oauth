package server

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func userinfoAcceptsAnything(h *forwardedTokenHarness) {
	h.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		return &providers.UserInfo{ID: "user-subject-123", Email: "user@test.example"}, nil
	}
}

func tokenForAnotherClient(t *testing.T, h *forwardedTokenHarness) string {
	t.Helper()
	claims := h.validClaims()
	claims.Audience = josejwt.Audience{"another-client"}
	return h.signToken(t, claims)
}

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
	claims := h.validClaims()
	claims.Issuer = "https://another-issuer.example"
	claims.Audience = josejwt.Audience{"another-client"}
	calls := h.provider.GetCallCount("ValidateToken")

	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, claims))

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
	line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
	require.Equal(t, auditReasonUnknownJWTBearer, line.Details["reason"])
}

func TestValidateToken_RefusesJWTForAnotherClient(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	calls := h.provider.GetCallCount("ValidateToken")

	userInfo, err := h.srv.ValidateToken(t.Context(), tokenForAnotherClient(t, h))

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
}

func TestValidateToken_RefusesCompactJWE(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoAcceptsAnything(h)
	encode := base64.RawURLEncoding.EncodeToString
	jwe := encode([]byte(`{"alg":"dir","enc":"A256GCM"}`)) + ".." + encode([]byte("iv")) + "." + encode([]byte("ciphertext")) + "." + encode([]byte("tag"))
	calls := h.provider.GetCallCount("ValidateToken")

	_, err := h.srv.ValidateToken(t.Context(), jwe)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
}

func TestValidateToken_ReturnedIDTokenMetadataDoesNotAuthorize(t *testing.T) {
	for _, test := range []struct {
		name        string
		expiresAt   time.Time
		otherServer bool
	}{
		{name: "live session", expiresAt: time.Now().Add(time.Hour)},
		{name: "another resource", expiresAt: time.Now().Add(time.Hour), otherServer: true},
		{name: "already expired", expiresAt: time.Now().Add(-time.Hour)},
		{name: "missing expiry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv, store, provider := setupFlowTestServer(t)
			idToken := makeIDTokenWithExpiry(t, "user-id-meta", test.expiresAt)
			_, _ = mintTokensWithIDToken(t, srv, store, provider, idToken)
			metadata, err := srv.TokenMetadata(t.Context(), idToken)
			require.NoError(t, err)
			require.NotEmpty(t, metadata.FamilyID)
			family, err := store.GetRefreshTokenFamilyByID(t.Context(), metadata.FamilyID)
			require.NoError(t, err)
			require.False(t, family.Revoked)
			if test.otherServer {
				otherMetadata := *metadata
				otherMetadata.Audience = "https://another-resource.example/mcp"
				require.NoError(t, store.SaveTokenMetadata(t.Context(), idToken, otherMetadata))
			}
			if test.expiresAt.IsZero() || test.expiresAt.Before(time.Now()) {
				require.True(t, metadata.ExpiresAt.After(time.Now()))
			}
			provider.ValidateTokenFunc = setupValidTokenProvider()
			calls := provider.GetCallCount("ValidateToken")

			userInfo, err := srv.ValidateToken(t.Context(), idToken)

			require.ErrorIs(t, err, ErrUnknownJWTBearer)
			require.Nil(t, userInfo)
			require.Equal(t, calls, provider.GetCallCount("ValidateToken"))
		})
	}
}

func TestValidateToken_SharedIDTokenCannotBypassDPoP(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	firstIDToken := makeIDTokenWithExpiry(t, "user-id-meta", time.Now().Add(time.Hour))
	bearerPair, bearerClientID := mintTokensWithIDToken(t, srv, store, provider, firstIDToken)
	sharedIDToken := makeIDTokenWithExpiry(t, "user-id-meta", time.Now().Add(2*time.Hour))
	boundPair, _ := mintTokensWithIDTokenAndDPoP(t, srv, store, provider, sharedIDToken, "bound-key")
	provider.ValidateTokenFunc = setupValidTokenProvider()

	_, err := srv.ValidateToken(t.Context(), sharedIDToken)
	require.ErrorIs(t, err, ErrUnknownJWTBearer)

	refreshed, err := srv.RefreshAccessToken(t.Context(), bearerPair.RefreshToken, bearerClientID)
	require.NoError(t, err)
	require.Equal(t, sharedIDToken, ExtractIDToken(refreshed))
	_, err = srv.ValidateToken(t.Context(), sharedIDToken)
	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	boundMetadata, err := srv.TokenMetadata(t.Context(), boundPair.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "bound-key", boundMetadata.JKT)
	idMetadata, err := srv.TokenMetadata(t.Context(), sharedIDToken)
	require.NoError(t, err)
	require.Empty(t, idMetadata.JKT)
	_, err = srv.ValidateToken(t.Context(), boundPair.AccessToken)
	require.NoError(t, err)
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
	require.Equal(t, calls, h.provider.GetCallCount("ValidateToken"))
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
