package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func newDPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func signDPoPProof(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	pubJWK := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256)}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", pubJWK),
	)
	require.NoError(t, err)
	raw, err := josejwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func dpopJKTFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: key.Public()}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(thumb)
}

func TestValidateDPoPProof_Valid(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()

	proof := signDPoPProof(t, key, map[string]any{
		"jti": "unique-jti-1",
		"htm": "POST",
		"htu": "https://auth.example.com/oauth/token",
		"iat": now.Unix(),
	})

	got, err := ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.NoError(t, err)
	require.Equal(t, dpopJKTFor(t, key), got.JKT)
}

func TestValidateDPoPProof_WrongMethod(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()

	proof := signDPoPProof(t, key, map[string]any{
		"jti": "jti-wrong-method",
		"htm": "GET",
		"htu": "https://auth.example.com/oauth/token",
		"iat": now.Unix(),
	})

	_, err := ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "htm")
}

func TestValidateDPoPProof_WrongURI(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()

	proof := signDPoPProof(t, key, map[string]any{
		"jti": "jti-wrong-uri",
		"htm": "POST",
		"htu": "https://auth.example.com/oauth/token",
		"iat": now.Unix(),
	})

	_, err := ValidateDPoPProof(t.Context(), proof, "POST", "https://other.example.com/oauth/token", "", cache, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "htu")
}

func TestValidateDPoPProof_Expired(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()
	stale := now.Add(-(dpopMaxClockSkew + time.Second))

	proof := signDPoPProof(t, key, map[string]any{
		"jti": "jti-expired",
		"htm": "POST",
		"htu": "https://auth.example.com/oauth/token",
		"iat": stale.Unix(),
	})

	_, err := ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "clock skew")
}

func TestValidateDPoPProof_Replay(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()

	proof := signDPoPProof(t, key, map[string]any{
		"jti": "jti-replay",
		"htm": "POST",
		"htu": "https://auth.example.com/oauth/token",
		"iat": now.Unix(),
	})

	_, err := ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.NoError(t, err)

	// Second call with the same proof must fail.
	_, err = ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "replay")
}

func TestValidateDPoPProof_MissingJWK(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()

	// Build a proof without the jwk header (use a plain ES256 signer, no jwk header).
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("dpop+jwt"),
	)
	require.NoError(t, err)
	proof, err := josejwt.Signed(sig).Claims(map[string]any{
		"jti": "jti-no-jwk",
		"htm": "POST",
		"htu": "https://auth.example.com/oauth/token",
		"iat": now.Unix(),
	}).Serialize()
	require.NoError(t, err)

	_, err = ValidateDPoPProof(t.Context(), proof, "POST", "https://auth.example.com/oauth/token", "", cache, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "jwk")
}

func TestValidateDPoPProof_ATH(t *testing.T) {
	key := newDPoPKey(t)
	cache := NewMemoryDPoPReplayCache()
	now := time.Now().UTC()
	accessToken := "some-access-token"

	hash := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(hash[:])

	t.Run("correct ath", func(t *testing.T) {
		proof := signDPoPProof(t, key, map[string]any{
			"jti": "jti-ath-ok",
			"htm": "GET",
			"htu": "https://api.example.com/resource",
			"iat": now.Unix(),
			"ath": ath,
		})
		_, err := ValidateDPoPProof(t.Context(), proof, "GET", "https://api.example.com/resource", accessToken, cache, now)
		require.NoError(t, err)
	})

	t.Run("wrong ath", func(t *testing.T) {
		proof := signDPoPProof(t, key, map[string]any{
			"jti": "jti-ath-bad",
			"htm": "GET",
			"htu": "https://api.example.com/resource",
			"iat": now.Unix(),
			"ath": "wrong-hash",
		})
		_, err := ValidateDPoPProof(t.Context(), proof, "GET", "https://api.example.com/resource", accessToken, cache, now)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ath")
	})
}

func TestMemoryDPoPReplayCache(t *testing.T) {
	cache := NewMemoryDPoPReplayCache()

	t.Run("first call returns false", func(t *testing.T) {
		seen, err := cache.Seen(t.Context(), "jti-new", 5*time.Minute)
		require.NoError(t, err)
		require.False(t, seen)
	})

	t.Run("second call returns true", func(t *testing.T) {
		seen, err := cache.Seen(t.Context(), "jti-new", 5*time.Minute)
		require.NoError(t, err)
		require.True(t, seen)
	})

	t.Run("evicts after TTL", func(t *testing.T) {
		// Record with a tiny TTL that is already expired.
		seen, err := cache.Seen(t.Context(), "jti-expired-evict", -time.Millisecond)
		require.NoError(t, err)
		require.False(t, seen)

		// Next call should find the entry expired and evicted, so returns false again.
		seen, err = cache.Seen(t.Context(), "jti-expired-evict", 5*time.Minute)
		require.NoError(t, err)
		require.False(t, seen)
	})
}
