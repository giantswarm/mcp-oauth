package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func assertionKey(t *testing.T, algorithm jose.SignatureAlgorithm) jose.JSONWebKey {
	t.Helper()
	var key any
	var err error
	if algorithm == jose.ES256 {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	require.NoError(t, err)
	return jose.JSONWebKey{Key: key, KeyID: "primary", Algorithm: string(algorithm), Use: "sig"}
}

func assertionClient(t *testing.T, key jose.JSONWebKey) *storage.Client {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.Public()}})
	require.NoError(t, err)
	return &storage.Client{ClientID: "key-client", ClientType: ClientTypeConfidential, TokenEndpointAuthMethod: TokenEndpointAuthMethodPrivateKeyJWT, JWKS: raw, TokenEndpointAuthSigningAlg: key.Algorithm}
}

func signedAssertion(t *testing.T, key jose.JSONWebKey, claims jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key}, nil)
	require.NoError(t, err)
	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return assertion
}

func validAssertionClaims() jwt.Claims {
	now := time.Now()
	return jwt.Claims{Issuer: "key-client", Subject: "key-client", Audience: jwt.Audience{"https://auth.example.com"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)), ID: "unique"}
}

func TestClientAssertion(t *testing.T) {
	for _, algorithm := range []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.PS256} {
		t.Run(string(algorithm), func(t *testing.T) {
			key := assertionKey(t, algorithm)
			client := assertionClient(t, key)
			tests := []struct {
				name   string
				mutate func(*jwt.Claims)
				reason string
			}{
				{"valid", func(*jwt.Claims) {}, ""},
				{"token endpoint audience", func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://auth.example.com/oauth/token"} }, "assertion_audience"},
				{"multiple audiences", func(c *jwt.Claims) {
					c.Audience = jwt.Audience{"https://auth.example.com", "https://other.example.com"}
				}, "assertion_audience"},
				{"duplicate issuer audience", func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://auth.example.com", "https://auth.example.com"} }, "assertion_audience"},
				{"normalized issuer audience", func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://AUTH.example.com/"} }, "assertion_audience"},
				{"wrong issuer", func(c *jwt.Claims) { c.Issuer = "other" }, "assertion_identity"},
				{"wrong subject", func(c *jwt.Claims) { c.Subject = "other" }, "assertion_identity"},
				{"wrong audience", func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://other"} }, "assertion_audience"},
				{"expired", func(c *jwt.Claims) {
					c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
					c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
				}, "assertion_expired"},
				{"long lifetime", func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(6 * time.Minute)) }, "assertion_lifetime"},
				{"future iat", func(c *jwt.Claims) {
					c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
					c.Expiry = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
				}, "assertion_future_iat"},
				{"future nbf", func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Minute)) }, "assertion_future_nbf"},
				{"missing jti", func(c *jwt.Claims) { c.ID = "" }, "assertion_jti_missing"},
				{"missing exp", func(c *jwt.Claims) { c.Expiry = nil }, "assertion_time_missing"},
				{"missing iat", func(c *jwt.Claims) { c.IssuedAt = nil }, "assertion_time_missing"},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					srv := &Server{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: NewMemoryClientAssertionReplayStore()}
					claims := validAssertionClaims()
					test.mutate(&claims)
					err := srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, key, claims))
					if test.reason == "" {
						require.NoError(t, err)
					} else {
						require.EqualError(t, err, test.reason)
					}
				})
			}
			srv := &Server{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: NewMemoryClientAssertionReplayStore()}
			wrong := assertionKey(t, algorithm)
			require.EqualError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, wrong, validAssertionClaims())), "assertion_signature")
		})
	}
}

func TestClientAssertionSharedReplay(t *testing.T) {
	key := assertionKey(t, jose.ES256)
	client := assertionClient(t, key)
	store := NewMemoryClientAssertionReplayStore()
	servers := []*Server{
		{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: store},
		{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: store},
	}
	assertion := signedAssertion(t, key, validAssertionClaims())
	var accepted atomic.Int32
	var group sync.WaitGroup
	for i := range 30 {
		group.Go(func() {
			if servers[i%2].ValidateClientAssertion(t.Context(), client, assertion) == nil {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	require.EqualValues(t, 1, accepted.Load())
}

func TestClientKeyMetadata(t *testing.T) {
	key := assertionKey(t, jose.ES256)
	public := assertionClient(t, key).JWKS
	private, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		raw       json.RawMessage
		algorithm string
		valid     bool
	}{
		{"public", public, "ES256", true}, {"private", private, "ES256", false}, {"unsupported", public, "HS256", false}, {"none", public, "none", false}, {"incompatible", public, "RS256", false}, {"empty", json.RawMessage(`{"keys":[]}`), "ES256", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateClientKeyMetadata(TokenEndpointAuthMethodPrivateKeyJWT, test.raw, test.algorithm, "")
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestClientAssertionRotation(t *testing.T) {
	old := assertionKey(t, jose.ES256)
	old.KeyID = "old"
	next := assertionKey(t, jose.ES256)
	next.KeyID = "new"
	client := assertionClient(t, old)
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{old.Public(), next.Public()}})
	require.NoError(t, err)
	client.JWKS = raw
	srv := &Server{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: NewMemoryClientAssertionReplayStore()}
	for _, key := range []jose.JSONWebKey{old, next} {
		claims := validAssertionClaims()
		claims.ID = key.KeyID
		require.NoError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, key, claims)))
	}
	client.JWKS = assertionClient(t, next).JWKS
	claims := validAssertionClaims()
	claims.ID = "removed"
	require.EqualError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, old, claims)), "assertion_kid")
	claims.ID = "retained"
	require.NoError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, next, claims)))
	next.KeyID = ""
	claims.ID = "no-kid"
	require.NoError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, next, claims)))
}

func TestClientAssertionPinnedAlgorithm(t *testing.T) {
	key := assertionKey(t, jose.RS256)
	client := assertionClient(t, key)
	key.Algorithm = "PS256"
	srv := &Server{Config: &Config{Issuer: "https://auth.example.com"}, clientAssertionReplayStore: NewMemoryClientAssertionReplayStore()}
	require.EqualError(t, srv.ValidateClientAssertion(t.Context(), client, signedAssertion(t, key, validAssertionClaims())), "assertion_signature")
	require.EqualError(t, srv.ValidateClientAssertion(t.Context(), client, strings.Join([]string{base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)), base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"key-client"}`)), ""}, ".")), "assertion_signature")
}

type unavailableAssertionStore struct{}

func (unavailableAssertionStore) Seen(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("unavailable")
}

func TestClientAssertionReplayStoreFailure(t *testing.T) {
	key := assertionKey(t, jose.ES256)
	srv := &Server{Config: &Config{Issuer: "https://auth.example.com"}, Logger: slog.Default(), Auditor: testAuditor(), clientAssertionReplayStore: unavailableAssertionStore{}}
	require.ErrorIs(t, srv.ValidateClientAssertion(t.Context(), assertionClient(t, key), signedAssertion(t, key, validAssertionClaims())), ErrStorageUnavailable)
}

func TestClientKeyConstraints(t *testing.T) {
	private := assertionKey(t, jose.ES256)
	key := private.Public()
	missing := key
	missing.KeyID = ""
	wrongUse := key
	wrongUse.Use = "enc"
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Weak key fixture exercises registration rejection.
	require.NoError(t, err)
	curve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		keys      []jose.JSONWebKey
		algorithm string
	}{
		{"duplicate kid", []jose.JSONWebKey{key, key}, "ES256"},
		{"missing kid", []jose.JSONWebKey{key, missing}, "ES256"},
		{"encryption key", []jose.JSONWebKey{wrongUse}, "ES256"},
		{"weak RSA", []jose.JSONWebKey{{Key: &weak.PublicKey}}, "RS256"},
		{"unsupported curve", []jose.JSONWebKey{{Key: &curve.PublicKey}}, "ES256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(jose.JSONWebKeySet{Keys: test.keys})
			require.NoError(t, err)
			require.Error(t, ValidateClientKeyMetadata(TokenEndpointAuthMethodPrivateKeyJWT, raw, test.algorithm, ""))
		})
	}
}
