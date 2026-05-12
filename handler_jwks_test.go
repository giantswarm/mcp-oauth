package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func newJWTModeHandler(t *testing.T) *Handler {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &server.Config{
		Issuer:                      testIssuer,
		AccessTokenFormat:           server.AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-handler-test",
		AccessTokenSigningAlgorithm: server.SigningAlgorithmRS256,
	}
	srv, err := server.New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)
	return NewHandler(srv, nil)
}

func TestServeJWKS_OpaqueModeReturns404(t *testing.T) {
	handler, _ := setupTestHandler(t) // setupTestHandler uses opaque mode
	req := httptest.NewRequest(http.MethodGet, server.EndpointPathJWKS, nil)
	w := httptest.NewRecorder()
	handler.ServeJWKS(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestServeJWKS_JWTModeReturnsKey(t *testing.T) {
	handler := newJWTModeHandler(t)
	req := httptest.NewRequest(http.MethodGet, server.EndpointPathJWKS, nil)
	w := httptest.NewRecorder()
	handler.ServeJWKS(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/jwk-set+json", w.Header().Get("Content-Type"))
	require.Contains(t, w.Header().Get("Cache-Control"), "max-age=3600")

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Len(t, body.Keys, 1)
	got := body.Keys[0]
	require.Equal(t, "kid-handler-test", got["kid"])
	require.Equal(t, "RS256", got["alg"])
	require.Equal(t, "RSA", got["kty"])
	require.Equal(t, "sig", got["use"])
	require.NotEmpty(t, got["n"])
	require.NotEmpty(t, got["e"])
	// public-only — never serve d (private exponent)
	require.NotContains(t, got, "d")
}

func TestServeJWKS_RejectsNonGET(t *testing.T) {
	handler := newJWTModeHandler(t)
	req := httptest.NewRequest(http.MethodPost, server.EndpointPathJWKS, nil)
	w := httptest.NewRecorder()
	handler.ServeJWKS(w, req)
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServeAuthorizationServerMetadata_JWTModeIncludesJWKSUri(t *testing.T) {
	handler := newJWTModeHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorizationServerMetadata(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Equal(t, testIssuer+server.EndpointPathJWKS, body["jwks_uri"])
	algs, ok := body["access_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	require.Equal(t, []any{"RS256"}, algs)
}

func TestServeAuthorizationServerMetadata_OpaqueModeOmitsJWKSUri(t *testing.T) {
	handler, _ := setupTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorizationServerMetadata(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	_, hasJWKS := body["jwks_uri"]
	require.False(t, hasJWKS, "jwks_uri must be absent in opaque mode")
}
