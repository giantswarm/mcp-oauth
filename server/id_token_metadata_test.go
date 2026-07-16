package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// makeIDTokenWithExpiry builds a JWS with the given exp claim, or omits the
// claim when expiresAt is the zero time. Signature is a placeholder.
func makeIDTokenWithExpiry(t *testing.T, subject string, expiresAt time.Time) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"}
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)

	payload := map[string]any{
		"sub":   subject,
		"iss":   "https://upstream.example.com",
		"aud":   "test-client",
		"email": "test@example.com",
	}
	if !expiresAt.IsZero() {
		payload["exp"] = expiresAt.Unix()
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	encode := base64.RawURLEncoding.EncodeToString
	return encode(headerBytes) + "." + encode(payloadBytes) + ".sig"
}

// mintTokensWithIDToken runs the full authorization-code flow with the mock
// provider returning idToken alongside its access/refresh pair, and returns
// the token response together with the registered client ID.
func mintTokensWithIDToken(t *testing.T, srv *Server, store *memory.Store, provider *mock.Provider, idToken string) (*oauth2.Token, string) {
	t.Helper()
	ctx := t.Context()

	provider.ExchangeCodeFunc = func(_ context.Context, _ string, _ string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken:  "provider-access-token",
			TokenType:    "Bearer",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}).WithExtra(map[string]any{
			"id_token": idToken,
		}), nil
	}

	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	require.NoError(t, err)

	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err = srv.StartAuthorizationFlow(ctx, client.ClientID, mustParseURL(t, "https://example.com/callback"), "openid email", "", codeChallenge, PKCEMethodS256, clientState, nil)
	require.NoError(t, err)

	authState, err := store.GetAuthorizationState(ctx, clientState)
	require.NoError(t, err)

	authCode, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "code-"+testutil.GenerateRandomString(10))
	require.NoError(t, err)

	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCode.Code, client.ClientID, "https://example.com/callback", "", codeVerifier, "")
	require.NoError(t, err)

	return token, client.ClientID
}

func TestExchangeAuthorizationCode_IDTokenMetadataSharesFamilySession(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	idTokenExpiry := time.Now().Add(30 * time.Minute)
	issuedIDToken := makeIDTokenWithExpiry(t, "user-id-meta", idTokenExpiry)
	token, _ := mintTokensWithIDToken(t, srv, store, provider, issuedIDToken)

	require.Equal(t, issuedIDToken, token.Extra("id_token"))

	accessMeta, err := store.GetTokenMetadata(token.AccessToken)
	require.NoError(t, err)
	require.NotEmpty(t, accessMeta.FamilyID)

	idMeta, err := store.GetTokenMetadata(issuedIDToken)
	require.NoError(t, err)
	require.Equal(t, accessMeta.FamilyID, idMeta.FamilyID)
	require.Equal(t, accessMeta.UserID, idMeta.UserID)
	require.Equal(t, accessMeta.ClientID, idMeta.ClientID)
	require.Equal(t, accessMeta.Scopes, idMeta.Scopes)
	require.Equal(t, "id", idMeta.TokenType)
	require.Empty(t, idMeta.JKT)
	require.Equal(t, idTokenExpiry.Unix(), idMeta.ExpiresAt.Unix())
}

func TestExchangeAuthorizationCode_IDTokenMetadataExpiryFallsBackToAccessToken(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	issuedIDToken := makeIDTokenWithExpiry(t, "user-no-exp", time.Time{})
	token, _ := mintTokensWithIDToken(t, srv, store, provider, issuedIDToken)

	accessMeta, err := store.GetTokenMetadata(token.AccessToken)
	require.NoError(t, err)

	idMeta, err := store.GetTokenMetadata(issuedIDToken)
	require.NoError(t, err)
	require.Equal(t, accessMeta.ExpiresAt, idMeta.ExpiresAt)
}

func TestRefreshAccessToken_IDTokenMetadataStableAcrossRotation(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	firstIDToken := makeIDTokenWithExpiry(t, "user-rotation", time.Now().Add(30*time.Minute))
	token, clientID := mintTokensWithIDToken(t, srv, store, provider, firstIDToken)

	firstIDMeta, err := store.GetTokenMetadata(firstIDToken)
	require.NoError(t, err)
	require.NotEmpty(t, firstIDMeta.FamilyID)

	rotatedIDToken := makeIDTokenWithExpiry(t, "user-rotation", time.Now().Add(90*time.Minute))
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken:  "new-provider-access-token",
			TokenType:    "Bearer",
			RefreshToken: "new-provider-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}).WithExtra(map[string]any{
			"id_token": rotatedIDToken,
		}), nil
	}

	refreshed, err := srv.RefreshAccessToken(t.Context(), token.RefreshToken, clientID)
	require.NoError(t, err)
	require.Equal(t, rotatedIDToken, refreshed.Extra("id_token"))

	rotatedIDMeta, err := store.GetTokenMetadata(rotatedIDToken)
	require.NoError(t, err)
	require.Equal(t, firstIDMeta.FamilyID, rotatedIDMeta.FamilyID)
	require.Equal(t, "id", rotatedIDMeta.TokenType)

	refreshedAccessMeta, err := store.GetTokenMetadata(refreshed.AccessToken)
	require.NoError(t, err)
	require.Equal(t, firstIDMeta.FamilyID, refreshedAccessMeta.FamilyID)
}
