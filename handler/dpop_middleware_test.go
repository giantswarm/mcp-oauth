package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func newTestDPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func buildDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, htu, jti string) string {
	t.Helper()
	return buildDPoPProofWithATH(t, key, method, htu, jti, "")
}

func buildDPoPProofWithATH(t *testing.T, key *ecdsa.PrivateKey, method, htu, jti, accessToken string) string {
	t.Helper()
	pubJWK := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256)}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", pubJWK),
	)
	require.NoError(t, err)
	claims := map[string]any{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	raw, err := josejwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func athFor(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestDPoPMiddleware_BearerPassthrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(nil)(next)

	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_DPoPValid(t *testing.T) {
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache)(next)

	const accessToken = "some-access-token"
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	proof := buildDPoPProofWithATH(t, key, "GET", "http://api.example.com/resource", "jti-valid-1", accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_DPoPMissingProof(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(nil)(next)

	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "DPoP some-access-token")
	// No DPoP proof header.
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid_request")
}

func TestDPoPMiddleware_DPoPInvalidProof(t *testing.T) {
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache)(next)

	const accessToken = "some-access-token"
	// Proof has htm=POST but request is GET — validation rejects before ath check.
	proof := buildDPoPProofWithATH(t, key, "POST", "http://api.example.com/resource", "jti-bad-method", accessToken)

	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid_dpop_proof")
}
