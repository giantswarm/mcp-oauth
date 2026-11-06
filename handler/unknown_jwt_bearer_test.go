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
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	response := httptest.NewRecorder()
	h.ValidateToken(next).ServeHTTP(response, request)
	return response, called
}

func TestHandler_ValidateToken_ReturnedIDTokenMetadataDoesNotAuthorize(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)
	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer,
	}, nil)
	require.NoError(t, err)
	h := New(srv, nil)

	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh-1", "mock-user-123", "client-1", "family-dpop", 0, time.Now().Add(time.Hour)))
	for _, test := range []struct {
		name    string
		payload string
		jkt     string
	}{
		{"bearer", `{"sub":"mock-user-123"}`, ""},
		{"DPoP pair", `{"sub":"mock-user-123"}`, "pair-jkt"},
		{"expired ID token", `{"sub":"mock-user-123","exp":1}`, ""},
		{"another resource", `{"sub":"mock-user-123","aud":"other-resource"}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			idToken := unsignedJWT(test.payload)
			require.NoError(t, store.SaveTokenMetadata(t.Context(), idToken, storage.TokenMetadata{
				UserID: "mock-user-123", ClientID: "client-1", TokenType: "id",
				FamilyID: "family-dpop", JKT: test.jkt, ExpiresAt: time.Now().Add(time.Hour),
			}))

			response, called := serveBearer(t, h, idToken)

			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.Contains(t, response.Body.String(), "Token validation failed")
			require.False(t, called)
		})
	}
}

func TestHandler_ValidateToken_TrustedIssuerTokenDoesNotInheritStoredBinding(t *testing.T) {
	h, token, _ := newTrustedIssuerTokenHandler(t, slog.LevelInfo)
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
