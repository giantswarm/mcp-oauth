package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// testKeyID is a constant for the test key ID used across tests.
const testKeyID = "test-key-1"

// signTestToken signs a JWT for use in test fixtures using go-jose. It
// mirrors the signing path used by the production server-issued JWT path
// so the test exercises the real verification logic.
func signTestToken(t *testing.T, key crypto.Signer, alg jose.SignatureAlgorithm, kid string, claims any) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: string(alg),
			Use:       "sig",
		},
	}
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	signed, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// publicJWKS builds a one-key jose.JSONWebKeySet from a private signer for
// use with FetchJWKS test fixtures.
func publicJWKS(t *testing.T, key crypto.Signer, alg, kid string) jose.JSONWebKeySet {
	t.Helper()
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: alg,
		Use:       "sig",
	}
	if !jwk.IsPublic() {
		t.Fatalf("derived JWK is not public-only")
	}
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
}

func TestJWKSClient_Creation(t *testing.T) {
	client := NewJWKSClient(nil, 0, nil)
	if client == nil {
		t.Fatal("NewJWKSClient returned nil")
	}
	if client.cacheTTL != DefaultCacheTTL {
		t.Errorf("Expected default cacheTTL %v, got %v", DefaultCacheTTL, client.cacheTTL)
	}

	customHTTP := &http.Client{Timeout: 5 * time.Second}
	customClient := NewJWKSClient(customHTTP, 30*time.Minute, slog.Default())
	if customClient == nil {
		t.Fatal("NewJWKSClient with custom values returned nil")
	}
	if customClient.httpClient != customHTTP {
		t.Error("Expected custom HTTP client to be used")
	}
	if customClient.cacheTTL != 30*time.Minute {
		t.Errorf("Expected cacheTTL 30m, got %v", customClient.cacheTTL)
	}
}

func TestJWKSClientWithOptions_AllowPrivateIP(t *testing.T) {
	t.Run("default client has AllowPrivateIP false", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, nil)
		if client.allowPrivateIP {
			t.Error("Expected allowPrivateIP to be false by default")
		}
	})

	t.Run("client with AllowPrivateIP true", func(t *testing.T) {
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			AllowPrivateIP: true,
			Logger:         slog.Default(),
		})
		if !client.allowPrivateIP {
			t.Error("Expected allowPrivateIP to be true")
		}
	})

	t.Run("client respects custom cacheTTL", func(t *testing.T) {
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			CacheTTL: 5 * time.Minute,
		})
		if client.cacheTTL != 5*time.Minute {
			t.Errorf("Expected cacheTTL 5m, got %v", client.cacheTTL)
		}
	})

	t.Run("client uses custom HTTPClient", func(t *testing.T) {
		customHTTP := &http.Client{Timeout: 1 * time.Second}
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			HTTPClient: customHTTP,
		})
		if client.httpClient != customHTTP {
			t.Error("Expected custom HTTP client to be used")
		}
	})
}

func TestFetchJWKS_AllowPrivateIP(t *testing.T) {
	t.Run("private IP URL rejected without AllowPrivateIP", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "https://192.168.1.1/jwks")
		if err == nil {
			t.Error("Expected error when fetching from private IP without AllowPrivateIP")
		}
		if !strings.Contains(err.Error(), "private IP") && !strings.Contains(err.Error(), "JWKS URI") {
			t.Errorf("Expected error about private IP, got: %v", err)
		}
	})

	t.Run("private IP URL validation bypassed with AllowPrivateIP", func(t *testing.T) {
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			AllowPrivateIP: true,
			Logger:         slog.Default(),
		})

		_, err := client.FetchJWKS(context.Background(), "https://192.168.1.1/jwks")
		if err == nil {
			t.Log("Fetch unexpectedly succeeded (maybe host is reachable?)")
			return
		}

		if strings.Contains(err.Error(), "private IP") {
			t.Errorf("Expected private IP check to be bypassed, got: %v", err)
		}
	})

	t.Run("HTTPS still required with AllowPrivateIP", func(t *testing.T) {
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			AllowPrivateIP: true,
			Logger:         slog.Default(),
		})

		_, err := client.FetchJWKS(context.Background(), "http://192.168.1.1/jwks")
		if err == nil {
			t.Error("Expected error for HTTP URL even with AllowPrivateIP")
		}
		if !strings.Contains(err.Error(), "HTTPS") {
			t.Errorf("Expected HTTPS requirement error, got: %v", err)
		}
	})

	t.Run("loopback URL rejected without AllowPrivateIP", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "https://127.0.0.1/jwks")
		if err == nil {
			t.Error("Expected error when fetching from loopback without AllowPrivateIP")
		}
	})

	t.Run("loopback URL validation bypassed with AllowPrivateIP", func(t *testing.T) {
		client := NewJWKSClientWithOptions(JWKSClientOptions{
			AllowPrivateIP: true,
			Logger:         slog.Default(),
		})

		_, err := client.FetchJWKS(context.Background(), "https://127.0.0.1/jwks")
		if err != nil && strings.Contains(err.Error(), "loopback") {
			t.Errorf("Expected loopback check to be bypassed, got: %v", err)
		}
	})
}

func TestValidateIDToken_Integration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwks := publicJWKS(t, privateKey, "RS256", testKeyID)

	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("Failed to encode JWKS: %v", err)
		}
	}))
	defer jwksServer.Close()

	client := &JWKSClient{
		httpClient:   jwksServer.Client(),
		cacheTTL:     1 * time.Minute,
		timeProvider: realTime{},
		logger:       slog.Default(),
	}
	// Manually pre-populate cache because httptest's URL is localhost,
	// which the SSRF guard would otherwise block.
	client.cache.Store(jwksServer.URL, &cachedJWKS{
		keys:      &jwks,
		fetchedAt: time.Now(),
	})

	validClaims := IDTokenClaims{
		Claims: josejwt.Claims{
			Subject:  "user123",
			Issuer:   "https://auth.example.com",
			Audience: josejwt.Audience{"client-a", "client-b"},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}
	signedToken := signTestToken(t, privateKey, jose.RS256, testKeyID, validClaims)

	t.Run("valid token", func(t *testing.T) {
		validatedClaims, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err != nil {
			t.Errorf("ValidateIDToken() error: %v", err)
			return
		}

		if validatedClaims.Subject != "user123" {
			t.Errorf("Subject = %q, want %q", validatedClaims.Subject, "user123")
		}
		if validatedClaims.Email != "user@example.com" {
			t.Errorf("Email = %q, want %q", validatedClaims.Email, "user@example.com")
		}
	})

	t.Run("audience mismatch", func(t *testing.T) {
		_, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"untrusted-client"},
		)

		if err == nil {
			t.Error("Expected error for audience mismatch")
		}
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		_, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://wrong.issuer.com",
			[]string{"client-a"},
		)

		if err == nil {
			t.Error("Expected error for issuer mismatch")
		}
	})

	t.Run("nbf within leeway accepted", func(t *testing.T) {
		nbfClaims := IDTokenClaims{
			Claims: josejwt.Claims{
				Subject:   "user-nbf",
				Issuer:    "https://auth.example.com",
				Audience:  josejwt.Audience{"client-a"},
				Expiry:    josejwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  josejwt.NewNumericDate(time.Now()),
				NotBefore: josejwt.NewNumericDate(time.Now().Add(10 * time.Second)),
			},
			Email: "nbf-user@example.com",
		}

		signedNbfToken := signTestToken(t, privateKey, jose.RS256, testKeyID, nbfClaims)

		validatedClaims, err := ValidateIDToken(
			context.Background(),
			signedNbfToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err != nil {
			t.Errorf("ValidateIDToken() should accept token with nbf within leeway, got error: %v", err)
			return
		}

		if validatedClaims.Subject != "user-nbf" {
			t.Errorf("Subject = %q, want %q", validatedClaims.Subject, "user-nbf")
		}
	})

	t.Run("nbf outside leeway rejected", func(t *testing.T) {
		nbfClaims := IDTokenClaims{
			Claims: josejwt.Claims{
				Subject:   "user-nbf-future",
				Issuer:    "https://auth.example.com",
				Audience:  josejwt.Audience{"client-a"},
				Expiry:    josejwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  josejwt.NewNumericDate(time.Now()),
				NotBefore: josejwt.NewNumericDate(time.Now().Add(60 * time.Second)),
			},
		}

		signedNbfToken := signTestToken(t, privateKey, jose.RS256, testKeyID, nbfClaims)

		_, err = ValidateIDToken(
			context.Background(),
			signedNbfToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)

		if err == nil {
			t.Error("Expected error for token with nbf 60 seconds in the future")
		}
	})

	t.Run("expired within leeway accepted", func(t *testing.T) {
		expiredClaims := IDTokenClaims{
			Claims: josejwt.Claims{
				Subject:  "user-expired-leeway",
				Issuer:   "https://auth.example.com",
				Audience: josejwt.Audience{"client-a"},
				Expiry:   josejwt.NewNumericDate(time.Now().Add(-10 * time.Second)),
				IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		}

		signedExpiredToken := signTestToken(t, privateKey, jose.RS256, testKeyID, expiredClaims)

		validatedClaims, err := ValidateIDToken(
			context.Background(),
			signedExpiredToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err != nil {
			t.Errorf("ValidateIDToken() should accept token expired within leeway, got error: %v", err)
			return
		}

		if validatedClaims.Subject != "user-expired-leeway" {
			t.Errorf("Subject = %q, want %q", validatedClaims.Subject, "user-expired-leeway")
		}
	})

	t.Run("expired outside leeway rejected", func(t *testing.T) {
		expiredClaims := IDTokenClaims{
			Claims: josejwt.Claims{
				Subject:  "user-expired",
				Issuer:   "https://auth.example.com",
				Audience: josejwt.Audience{"client-a"},
				Expiry:   josejwt.NewNumericDate(time.Now().Add(-60 * time.Second)),
				IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		}

		signedExpiredToken := signTestToken(t, privateKey, jose.RS256, testKeyID, expiredClaims)

		_, err = ValidateIDToken(
			context.Background(),
			signedExpiredToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)

		if err == nil {
			t.Error("Expected error for token expired 60 seconds ago")
		}
	})

	t.Run("HS256 alg-confusion rejected", func(t *testing.T) {
		// An attacker who has the public key signs with HS256 using the
		// public key bytes as the HMAC secret. josejwt.ParseSigned must
		// reject the token at parse time because HS256 is not in the
		// asymmetric allowlist.
		hmacSigner, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.HS256, Key: []byte("any-shared-secret-of-sufficient-length-32+")},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		if err != nil {
			t.Fatalf("create HMAC signer: %v", err)
		}
		forged, err := josejwt.Signed(hmacSigner).Claims(validClaims).Serialize()
		if err != nil {
			t.Fatalf("sign forged token: %v", err)
		}
		_, err = ValidateIDToken(
			context.Background(),
			forged,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err == nil {
			t.Error("Expected HS256 forge to be rejected")
		}
	})

	t.Run("ES256 with EC key succeeds", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		ecJWKS := publicJWKS(t, ecKey, "ES256", "ec-kid")
		ecClient := &JWKSClient{
			httpClient:   jwksServer.Client(),
			cacheTTL:     1 * time.Minute,
			timeProvider: realTime{},
			logger:       slog.Default(),
		}
		const ecJWKSURL = "https://ec-test/jwks"
		ecClient.cache.Store(ecJWKSURL, &cachedJWKS{keys: &ecJWKS, fetchedAt: time.Now()})

		ecClaims := IDTokenClaims{
			Claims: josejwt.Claims{
				Subject:  "ec-user",
				Issuer:   "https://auth.example.com",
				Audience: josejwt.Audience{"client-a"},
				Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		ecToken := signTestToken(t, ecKey, jose.ES256, "ec-kid", ecClaims)

		validatedClaims, err := ValidateIDToken(
			context.Background(),
			ecToken,
			ecClient,
			ecJWKSURL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err != nil {
			t.Errorf("ValidateIDToken() with EC key error: %v", err)
		}
		if validatedClaims != nil && validatedClaims.Subject != "ec-user" {
			t.Errorf("Subject = %q, want %q", validatedClaims.Subject, "ec-user")
		}
	})

	t.Run("unknown kid rejected", func(t *testing.T) {
		// Token signed with a different key whose kid does not exist in
		// the published JWKS.
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate other key: %v", err)
		}
		otherToken := signTestToken(t, otherKey, jose.RS256, "unknown-kid", validClaims)

		_, err = ValidateIDToken(
			context.Background(),
			otherToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err == nil {
			t.Error("Expected unknown kid to be rejected")
		}
	})

	t.Run("multiple keys at same kid (rotation overlap) accepted", func(t *testing.T) {
		// RFC 7517 §4.5 allows multiple keys with the same kid. The
		// rotation-overlap pattern: publish both old and new under the
		// same kid for a brief window so verifiers caching either key
		// still pass while the rotation propagates. The validator must
		// try each in turn and succeed on the matching one.
		oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate old key: %v", err)
		}
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate new key: %v", err)
		}

		const overlapKid = "rotating-kid"
		jwksWithBoth := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			// Old key first — keys[0] wouldn't match a token signed with the new key.
			{Key: oldKey.Public(), KeyID: overlapKid, Algorithm: "RS256", Use: "sig"},
			{Key: newKey.Public(), KeyID: overlapKid, Algorithm: "RS256", Use: "sig"},
		}}
		const overlapURL = "https://overlap-test/jwks"
		client.cache.Store(overlapURL, &cachedJWKS{keys: &jwksWithBoth, fetchedAt: time.Now()})

		// Sign with the SECOND key — keys[0] (old) won't verify; the
		// loop must fall through to keys[1].
		signedByNew := signTestToken(t, newKey, jose.RS256, overlapKid, validClaims)
		got, err := ValidateIDToken(
			context.Background(), signedByNew, client, overlapURL,
			"https://auth.example.com", []string{"client-a"},
		)
		if err != nil {
			t.Errorf("multi-key rotation: validation should succeed when second key matches, got %v", err)
		}
		if got != nil && got.Subject != "user123" {
			t.Errorf("Subject = %q, want user123", got.Subject)
		}

		// Sign with neither key (signature mismatch on every kid match) — must reject.
		strangerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate stranger key: %v", err)
		}
		signedByStranger := signTestToken(t, strangerKey, jose.RS256, overlapKid, validClaims)
		if _, err := ValidateIDToken(
			context.Background(), signedByStranger, client, overlapURL,
			"https://auth.example.com", []string{"client-a"},
		); err == nil {
			t.Error("multi-key rotation: validation must reject a token whose signature matches none of the keys")
		}
	})
}

// TestValidateIDToken_RefetchOnUnknownKid covers the rotation-safety fix: a
// token whose kid is absent from the cached JWKS triggers a single bounded
// refetch (the issuer rotated its signing key), and genuinely bogus kids are
// rate-limited so they can't hammer the JWKS endpoint.
func TestValidateIDToken_RefetchOnUnknownKid(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	oldJWKS := publicJWKS(t, oldKey, "RS256", "old-kid")
	newJWKS := publicJWKS(t, newKey, "RS256", "new-kid")

	var (
		mu       sync.Mutex
		served   = oldJWKS
		fetchCnt int
	)
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fetchCnt++
		cur := served
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(cur); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}))
	defer jwksServer.Close()

	// allowPrivateIP lets the forced refetch reach the loopback httptest server
	// (production fetches go to a public Dex hostname). The cache is
	// pre-populated with the pre-rotation JWKS, fresh, so the refetch is
	// triggered by the unknown kid and not by cache-TTL expiry.
	newClient := func(tp timeProvider, backoff time.Duration) *JWKSClient {
		c := &JWKSClient{
			httpClient:     jwksServer.Client(),
			cacheTTL:       1 * time.Hour,
			timeProvider:   tp,
			logger:         slog.Default(),
			allowPrivateIP: true,
			refetchBackoff: backoff,
		}
		c.cache.Store(jwksServer.URL, &cachedJWKS{keys: &oldJWKS, fetchedAt: tp.Now()})
		return c
	}

	validClaims := IDTokenClaims{
		Claims: josejwt.Claims{
			Subject:  "rotated-user",
			Issuer:   "https://auth.example.com",
			Audience: josejwt.Audience{"client-a"},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	t.Run("token signed by rotated key validates after refetch", func(t *testing.T) {
		mu.Lock()
		served = newJWKS
		fetchCnt = 0
		mu.Unlock()

		client := newClient(realTime{}, DefaultJWKSRefetchBackoff)
		token := signTestToken(t, newKey, jose.RS256, "new-kid", validClaims)

		got, err := ValidateIDToken(context.Background(), token, client, jwksServer.URL,
			"https://auth.example.com", []string{"client-a"})
		if err != nil {
			t.Fatalf("expected validation to succeed after refetch, got: %v", err)
		}
		if got.Subject != "rotated-user" {
			t.Errorf("Subject = %q, want rotated-user", got.Subject)
		}
		mu.Lock()
		n := fetchCnt
		mu.Unlock()
		if n != 1 {
			t.Errorf("expected exactly 1 refetch, got %d", n)
		}
	})

	t.Run("bogus kid triggers at most one refetch per backoff window", func(t *testing.T) {
		// Server keeps serving the old JWKS, so the bogus kid never appears:
		// every validation misses and would refetch if not rate-limited.
		mu.Lock()
		served = oldJWKS
		fetchCnt = 0
		mu.Unlock()

		mt := &mockTime{now: time.Now()}
		client := newClient(mt, time.Minute)
		bogusKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate bogus key: %v", err)
		}
		bogus := signTestToken(t, bogusKey, jose.RS256, "bogus-kid", validClaims)

		for i := 0; i < 3; i++ {
			if _, err := ValidateIDToken(context.Background(), bogus, client, jwksServer.URL,
				"https://auth.example.com", []string{"client-a"}); err == nil {
				t.Fatal("expected validation to fail for bogus kid")
			}
		}
		mu.Lock()
		n := fetchCnt
		mu.Unlock()
		if n != 1 {
			t.Fatalf("expected exactly 1 refetch within backoff window, got %d", n)
		}

		// Advance past the backoff window: the next miss may refetch again.
		mt.now = mt.now.Add(2 * time.Minute)
		if _, err := ValidateIDToken(context.Background(), bogus, client, jwksServer.URL,
			"https://auth.example.com", []string{"client-a"}); err == nil {
			t.Fatal("expected validation to fail for bogus kid")
		}
		mu.Lock()
		n = fetchCnt
		mu.Unlock()
		if n != 2 {
			t.Errorf("expected a second refetch after backoff elapsed, got %d total", n)
		}
	})
}

func TestFetchJWKS(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	testJWKS := publicJWKS(t, privateKey, "RS256", "test-key")

	t.Run("successful cache hit", func(t *testing.T) {
		client := &JWKSClient{
			httpClient:   http.DefaultClient,
			cacheTTL:     1 * time.Hour,
			timeProvider: realTime{},
			logger:       slog.Default(),
		}
		const url = "https://example.com/jwks"
		client.cache.Store(url, &cachedJWKS{
			keys:      &testJWKS,
			fetchedAt: time.Now(),
		})

		jwks, err := client.FetchJWKS(context.Background(), url)
		if err != nil {
			t.Errorf("FetchJWKS() error: %v", err)
			return
		}
		if len(jwks.Keys) != 1 {
			t.Errorf("Expected 1 key, got %d", len(jwks.Keys))
		}
	})

	t.Run("invalid JWKS URI - not HTTPS", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, nil)

		_, err := client.FetchJWKS(context.Background(), "http://insecure.example.com/jwks")
		if err == nil {
			t.Error("Expected error for non-HTTPS URI")
		}
	})
}

func TestClearCache(t *testing.T) {
	client := NewJWKSClient(nil, 0, slog.Default())

	client.cache.Store("https://example1.com/jwks", &cachedJWKS{
		keys:      &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "key1"}}},
		fetchedAt: time.Now(),
	})
	client.cache.Store("https://example2.com/jwks", &cachedJWKS{
		keys:      &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "key2"}}},
		fetchedAt: time.Now(),
	})

	_, ok1 := client.cache.Load("https://example1.com/jwks")
	_, ok2 := client.cache.Load("https://example2.com/jwks")
	if !ok1 || !ok2 {
		t.Fatal("Expected cache entries to exist before clearing")
	}

	client.ClearCache()

	_, ok1 = client.cache.Load("https://example1.com/jwks")
	_, ok2 = client.cache.Load("https://example2.com/jwks")
	if ok1 || ok2 {
		t.Error("Expected cache to be empty after clearing")
	}
}

// TestFetchJWKS_SecurityLimits tests the security limits on JWKS fetching.
func TestFetchJWKS_SecurityLimits(t *testing.T) {
	t.Run("SSRF protection - reject private IP", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "https://192.168.1.1/jwks")
		if err == nil {
			t.Error("Expected error for private IP JWKS URI")
		}
		if err != nil && !strings.Contains(err.Error(), "private IP") {
			t.Errorf("Expected error about private IP, got: %v", err)
		}
	})

	t.Run("SSRF protection - reject loopback", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "https://127.0.0.1/jwks")
		if err == nil {
			t.Error("Expected error for loopback JWKS URI")
		}
		if err != nil && !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Expected error about loopback, got: %v", err)
		}
	})

	t.Run("SSRF protection - reject link-local (metadata service)", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "https://169.254.169.254/jwks")
		if err == nil {
			t.Error("Expected error for link-local JWKS URI")
		}
		if err != nil && !strings.Contains(err.Error(), "link-local") {
			t.Errorf("Expected error about link-local, got: %v", err)
		}
	})

	t.Run("reject HTTP (not HTTPS)", func(t *testing.T) {
		client := NewJWKSClient(nil, 0, slog.Default())

		_, err := client.FetchJWKS(context.Background(), "http://example.com/jwks")
		if err == nil {
			t.Error("Expected error for HTTP JWKS URI")
		}
		if err != nil && !strings.Contains(err.Error(), "HTTPS") {
			t.Errorf("Expected error about HTTPS, got: %v", err)
		}
	})

	t.Run("max key count constant is correct", func(t *testing.T) {
		if maxJWKSKeyCount != 100 {
			t.Errorf("maxJWKSKeyCount = %d, want 100", maxJWKSKeyCount)
		}
	})

	t.Run("accept JWKS at key limit", func(t *testing.T) {
		maxKeys := make([]jose.JSONWebKey, maxJWKSKeyCount)
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		for i := range maxKeys {
			maxKeys[i] = jose.JSONWebKey{
				Key:       privateKey.Public(),
				KeyID:     "key-" + string(rune('0'+i%10)),
				Algorithm: "RS256",
				Use:       "sig",
			}
		}
		maxJWKS := jose.JSONWebKeySet{Keys: maxKeys}

		client := NewJWKSClient(nil, 0, slog.Default())
		client.cache.Store("https://example.com/jwks", &cachedJWKS{
			keys:      &maxJWKS,
			fetchedAt: time.Now(),
		})

		jwks, err := client.FetchJWKS(context.Background(), "https://example.com/jwks")
		if err != nil {
			t.Errorf("FetchJWKS() unexpected error for JWKS at limit: %v", err)
		}
		if jwks != nil && len(jwks.Keys) != maxJWKSKeyCount {
			t.Errorf("Expected %d keys, got %d", maxJWKSKeyCount, len(jwks.Keys))
		}
	})
}
