package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

func buildDPoPProofWithNonce(t *testing.T, key *ecdsa.PrivateKey, method, htu, jti, nonce, accessToken string) string {
	t.Helper()
	pubJWK := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256)}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", pubJWK),
	)
	require.NoError(t, err)
	claims := map[string]any{
		"jti":   jti,
		"htm":   method,
		"htu":   htu,
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	raw, err := josejwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func TestDPoPMiddleware_BearerPassthrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(nil, nil, nil)(next)

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

	mw := DPoPMiddleware(cache, nil, nil)(next)

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

	mw := DPoPMiddleware(nil, nil, nil)(next)

	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "DPoP some-access-token")
	// No DPoP proof header.
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), "invalid_request")
	// RFC 9449 §7.1: WWW-Authenticate must be present on every 401.
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "DPoP")
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_request")
}

func TestDPoPMiddleware_DPoPInvalidProof(t *testing.T) {
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nil, nil)(next)

	const accessToken = "some-access-token"
	// Proof has htm=POST but request is GET — validation rejects before ath check.
	proof := buildDPoPProofWithATH(t, key, "POST", "http://api.example.com/resource", "jti-bad-method", accessToken)

	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), "invalid_dpop_proof")
	// RFC 9449 §7.1: WWW-Authenticate must be present on every 401.
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "DPoP")
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_dpop_proof")
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "algs=")
}

func TestDPoPMiddleware_TrustedProxyHTU(t *testing.T) {
	_, proxyNet, _ := net.ParseCIDR("10.0.0.0/8")
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nil, []*net.IPNet{proxyNet})(next)

	// The DPoP proof is bound to the external HTTPS URL that the client sees.
	const accessToken = "some-access-token"
	const externalHTU = "https://api.example.com/resource"
	proof := buildDPoPProofWithATH(t, key, "GET", externalHTU, "jti-proxy-1", accessToken)

	// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234" by default, which is
	// NOT in 10.0.0.0/8, so we override it to a trusted proxy address.
	r := httptest.NewRequest(http.MethodGet, "http://internal-svc/resource", nil)
	r.RemoteAddr = "10.0.0.1:4000"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "api.example.com")
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", proof)

	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_UntrustedProxyHeadersIgnored(t *testing.T) {
	_, proxyNet, _ := net.ParseCIDR("10.0.0.0/8")
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nil, []*net.IPNet{proxyNet})(next)

	// Proof bound to the external URL. Remote address is NOT in trusted CIDR,
	// so X-Forwarded-* are ignored and htu is derived from the raw request URL.
	// This should fail because the proof htu won't match.
	const accessToken = "some-access-token"
	proof := buildDPoPProofWithATH(t, key, "GET", "https://api.example.com/resource", "jti-untrusted-1", accessToken)

	r := httptest.NewRequest(http.MethodGet, "http://internal-svc/resource", nil)
	r.RemoteAddr = "1.2.3.4:4000" // not in 10.0.0.0/8
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "api.example.com")
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", proof)

	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid_dpop_proof")
}

func TestDPoPMiddleware_NonceRequired(t *testing.T) {
	now := time.Now().UTC()
	nonceProvider := server.NewHMACNonceProvider([]byte("test-key"), time.Minute, func() time.Time { return now })
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nonceProvider, nil)(next)

	const accessToken = "some-access-token"

	t.Run("missing nonce returns use_dpop_nonce with DPoP-Nonce header", func(t *testing.T) {
		proof := buildDPoPProofWithATH(t, key, "GET", "http://api.example.com/resource", "jti-no-nonce", accessToken)
		r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
		r.Header.Set("Authorization", "DPoP "+accessToken)
		r.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()

		mw.ServeHTTP(w, r)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "use_dpop_nonce")
		// RFC 9449 §8: DPoP-Nonce response header required.
		require.NotEmpty(t, w.Header().Get("DPoP-Nonce"))
		// RFC 9449 §7.1: WWW-Authenticate required on 401.
		require.Contains(t, w.Header().Get("WWW-Authenticate"), "use_dpop_nonce")
	})

	t.Run("valid nonce accepted", func(t *testing.T) {
		called := false
		next2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		mw2 := DPoPMiddleware(cache, nonceProvider, nil)(next2)

		nonce := nonceProvider.Nonce(t.Context())
		proof := buildDPoPProofWithNonce(t, key, "GET", "http://api.example.com/resource", "jti-with-nonce", nonce, accessToken)
		r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
		r.Header.Set("Authorization", "DPoP "+accessToken)
		r.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()

		mw2.ServeHTTP(w, r)

		require.True(t, called)
		require.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDPoPMiddleware_ProofJKTStoredInContext(t *testing.T) {
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()

	var capturedJKT string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedJKT = dpopProofJKTFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nil, nil)(next)

	const accessToken = "some-access-token"
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	proof := buildDPoPProofWithATH(t, key, "GET", "http://api.example.com/resource", "jti-ctx-1", accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, capturedJKT, "proof JKT must be stored in context after successful validation")
}

func TestDPoPMiddleware_NormalizesAuthorizationToBearer(t *testing.T) {
	key := newTestDPoPKey(t)
	cache := server.NewMemoryDPoPReplayCache()

	var capturedAuthHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	mw := DPoPMiddleware(cache, nil, nil)(next)

	const accessToken = "some-access-token"
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	proof := buildDPoPProofWithATH(t, key, "GET", "http://api.example.com/resource", "jti-norm-1", accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, strings.HasPrefix(capturedAuthHeader, "Bearer "),
		"Authorization header must be normalized to Bearer scheme, got: %s", capturedAuthHeader)
	require.Contains(t, capturedAuthHeader, accessToken)
}

func TestHandlerDPoPMiddleware_Method(t *testing.T) {
	h, store := setupTestHandler(t)
	defer store.Stop()

	key := newTestDPoPKey(t)

	var capturedJKT string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedJKT = dpopProofJKTFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := h.DPoPMiddleware()(next)

	const accessToken = "some-access-token"
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	proof := buildDPoPProofWithATH(t, key, "GET", "http://api.example.com/resource", "jti-handler-1", accessToken)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, capturedJKT)
}
