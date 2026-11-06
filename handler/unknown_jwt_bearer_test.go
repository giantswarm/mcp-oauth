package handler

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// serveBearer runs the ValidateToken middleware for one request carrying
// bearer and reports the status and whether the next handler ran.
func serveBearer(t *testing.T, h *Handler, bearer string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.ValidateToken(next).ServeHTTP(w, req)
	return w, called
}

func TestHandler_ValidateToken_ReturnedIDTokenOfDPoPPairNeedsProof(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)
	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer,
	}, nil)
	require.NoError(t, err)
	h := New(srv, nil)

	idToken := unsignedJWT(`{"sub":"mock-user-123"}`)
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh-1", "mock-user-123", "client-1", "family-dpop", 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.SaveTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
		UserID:    "mock-user-123",
		ClientID:  "client-1",
		TokenType: "id",
		FamilyID:  "family-dpop",
		JKT:       "pair-jkt",
	}))

	w, called := serveBearer(t, h, idToken)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "DPoP")
	require.False(t, called)
}

// TestHandler_ValidateToken_ForwardedIDTokenOfDPoPPairStaysBearer: the same
// id_token forwarded and accepted as an SSO token (TrustedAudiences) is not
// held to the pair's DPoP binding, so a service it was forwarded to can
// present it back without the pair's key.
func TestHandler_ValidateToken_ForwardedIDTokenOfDPoPPairStaysBearer(t *testing.T) {
	h, token, _ := newForwardedTokenHandler(t, slog.LevelInfo)
	metadataStore, ok := h.server.TokenStore().(storage.TokenMetadataStore)
	require.True(t, ok)
	require.NoError(t, metadataStore.SaveTokenMetadata(t.Context(), token, storage.TokenMetadata{
		UserID:    "user-subject-123",
		ClientID:  "client-1",
		TokenType: "id",
		FamilyID:  "family-dpop",
		JKT:       "pair-jkt",
	}))

	w, called := serveBearer(t, h, token)

	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, called)
}

func TestHandler_ValidateToken_JWTForAnotherClientRefused(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)
	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer,
	}, nil)
	require.NoError(t, err)
	h := New(srv, nil)

	w, called := serveBearer(t, h, unsignedJWT(`{"sub":"mock-user-123","aud":"other"}`))

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.False(t, called)
}

func TestHandler_ValidateToken_JWTRejectionsHaveSameResponse(t *testing.T) {
	h, forwardedToken, _ := newForwardedTokenHandler(t, slog.LevelInfo)
	var responseBody, challenge string
	for _, bearer := range []string{
		unsignedJWT(`{"sub":"user-subject-123","aud":"other"}`),
		forwardedToken + "invalid-signature",
	} {
		response, called := serveBearer(t, h, bearer)
		require.Equal(t, http.StatusUnauthorized, response.Code)
		require.False(t, called)
		if responseBody == "" {
			responseBody = response.Body.String()
			challenge = response.Header().Get("WWW-Authenticate")
		}
		require.Equal(t, responseBody, response.Body.String())
		require.Equal(t, challenge, response.Header().Get("WWW-Authenticate"))
	}
}

// unsignedJWT is a JWT-shaped bearer with the given payload and no valid
// signature, for paths that only look at the token's shape.
func unsignedJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + ".sig"
}
