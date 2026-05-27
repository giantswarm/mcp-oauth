package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testAudience = "https://mcp.example.com"
	testSubject  = "repo:org/repo:ref:refs/heads/main"
)

// newTestECKey generates an ephemeral P-256 key for test fixtures.
func newTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// signSubjectToken creates a signed JWT with the given claims using ES256.
func signSubjectToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims josejwt.Claims) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key: jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

// serveStaticJWKS starts an httptest.Server that serves the public key as a JWKS.
// The returned JWKSClient is configured to allow private IPs so it can reach localhost.
func serveStaticJWKS(t *testing.T, key *ecdsa.PrivateKey, kid string) (jwksURL string, client *oidc.JWKSClient) {
	t.Helper()
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key.Public(),
				KeyID:     kid,
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	jwksClient := oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
		HTTPClient:     srv.Client(),
		AllowPrivateIP: true,
	})
	return srv.URL, jwksClient
}

func TestOIDCValidator_ValidToken(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
	}}, jwksClient)
	require.NoError(t, err)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	for _, tt := range []struct{ name, tokenType string }{
		{"id_token type", SubjectTokenTypeIDToken},
		{"access_token type", SubjectTokenTypeAccessToken},
	} {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := v.Validate(t.Context(), token, tt.tokenType)
			require.NoError(t, err)
			require.Equal(t, testSubject, identity.Subject)
			require.Equal(t, testIssuer, identity.Issuer)
		})
	}
}

func TestOIDCValidator_WrongIssuer(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
	}}, jwksClient)
	require.NoError(t, err)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   "https://attacker.example.com",
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeIDToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "untrusted issuer")
}

func TestOIDCValidator_ExpiredToken(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
	}}, jwksClient)
	require.NoError(t, err)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now().Add(-3 * time.Hour)),
	})

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeIDToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestOIDCValidator_WrongAudience(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
	}}, jwksClient)
	require.NoError(t, err)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{"https://wrong.example.com"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeIDToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "audience")
}

func TestOIDCValidator_UnsupportedTokenType(t *testing.T) {
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:  testIssuer,
		JwksURL: "https://example.com/jwks",
	}}, oidc.NewJWKSClient(nil, 0, nil))
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), "sometoken", "urn:ietf:params:oauth:token-type:saml2")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported subject_token_type")
}

func TestNewOIDCValidator_Errors(t *testing.T) {
	t.Run("empty issuers", func(t *testing.T) {
		_, err := NewOIDCValidator(nil)
		require.Error(t, err)
	})
	t.Run("empty Issuer field", func(t *testing.T) {
		_, err := NewOIDCValidator([]TrustedIssuer{{JwksURL: "https://example.com/jwks"}})
		require.Error(t, err)
	})
	t.Run("empty JwksURL field", func(t *testing.T) {
		_, err := NewOIDCValidator([]TrustedIssuer{{Issuer: testIssuer}})
		require.Error(t, err)
	})
}

// TestMatchClaimPattern covers matchClaimPattern in isolation so the matrix
// of pattern/value combinations is cheap (no JWT signing overhead).
func TestMatchClaimPattern(t *testing.T) {
	// testSubject = "repo:org/repo:ref:refs/heads/main"
	for _, tc := range []struct {
		pattern string
		value   string
		wantErr bool
	}{
		// exact match
		{"repo:org/repo:ref:refs/heads/main", "repo:org/repo:ref:refs/heads/main", false},
		// exact mismatch
		{"repo:org/repo:ref:refs/heads/main", "repo:org/repo:ref:refs/heads/feat", true},
		// * spans the whole string including /
		{"repo:org/repo:*", "repo:org/repo:ref:refs/heads/main", false},
		// * at start
		{"*:refs/heads/main", "repo:org/repo:ref:refs/heads/main", false},
		// * in the middle
		{"repo:org/repo:ref:*/main", "repo:org/repo:ref:refs/heads/main", false},
		// * does not match when prefix is wrong
		{"repo:org/other:*", "repo:org/repo:ref:refs/heads/main", true},
		// ? matches a single character
		{"repo:org/repo:ref:refs/heads/mai?", "repo:org/repo:ref:refs/heads/main", false},
		// ? does not match two characters
		{"repo:org/repo:ref:refs/heads/ma?", "repo:org/repo:ref:refs/heads/main", true},
		// K8s SA glob
		{"system:serviceaccount:ai-platform:*", "system:serviceaccount:ai-platform:my-svc", false},
		// K8s SA glob: wrong namespace
		{"system:serviceaccount:ai-platform:*", "system:serviceaccount:other:my-svc", true},
		// absent claim value (empty string)
		{"somevalue", "", true},
		// wildcard matches empty remainder
		{"repo:org/repo:*", "repo:org/repo:", false},
		// character class
		{"repo:org/repo:ref:refs/heads/mai[mn]", "repo:org/repo:ref:refs/heads/main", false},
		{"repo:org/repo:ref:refs/heads/mai[mn]", "repo:org/repo:ref:refs/heads/maix", true},
	} {
		err := matchClaimPattern(tc.pattern, tc.value)
		if tc.wantErr {
			require.Error(t, err, "pattern=%q value=%q", tc.pattern, tc.value)
		} else {
			require.NoError(t, err, "pattern=%q value=%q", tc.pattern, tc.value)
		}
	}
}

func TestOIDCValidator_AllowedClaims(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	makeToken := func(sub string) string {
		return signSubjectToken(t, key, kid, josejwt.Claims{
			Issuer:   testIssuer,
			Subject:  sub,
			Audience: josejwt.Audience{testAudience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		})
	}

	for _, tc := range []struct {
		name             string
		allowedClaims    map[string]string
		sub              string
		wantErr          bool
		wantErrContains  string
	}{
		{
			name:          "exact match",
			allowedClaims: map[string]string{"sub": testSubject},
			sub:           testSubject,
		},
		{
			name:            "exact mismatch",
			allowedClaims:   map[string]string{"sub": "repo:org/other:ref:refs/heads/main"},
			sub:             testSubject,
			wantErr:         true,
			wantErrContains: "does not match allowed pattern",
		},
		{
			name:          "glob across slash",
			allowedClaims: map[string]string{"sub": "repo:org/repo:*"},
			sub:           testSubject,
		},
		{
			name:            "glob wrong org",
			allowedClaims:   map[string]string{"sub": "repo:org/other:*"},
			sub:             testSubject,
			wantErr:         true,
			wantErrContains: "does not match allowed pattern",
		},
		{
			name:            "absent claim is rejected",
			allowedClaims:   map[string]string{"nonexistent_claim": "somevalue"},
			sub:             testSubject,
			wantErr:         true,
			wantErrContains: "not present in token",
		},
		{
			name:          "no AllowedClaims — no restriction",
			allowedClaims: nil,
			sub:           testSubject,
		},
		{
			name:          "K8s SA glob — allowed namespace",
			allowedClaims: map[string]string{"sub": "system:serviceaccount:ai-platform:*"},
			sub:           "system:serviceaccount:ai-platform:my-svc",
		},
		{
			name:            "K8s SA glob — wrong namespace",
			allowedClaims:   map[string]string{"sub": "system:serviceaccount:ai-platform:*"},
			sub:             "system:serviceaccount:other:my-svc",
			wantErr:         true,
			wantErrContains: "does not match allowed pattern",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
				Issuer:           testIssuer,
				JwksURL:          jwksURL,
				AllowedAudiences: []string{testAudience},
				AllowedClaims:    tc.allowedClaims,
			}}, jwksClient)
			require.NoError(t, err)

			identity, err := v.Validate(t.Context(), makeToken(tc.sub), SubjectTokenTypeIDToken)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrContains)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.sub, identity.Subject)
			}
		})
	}
}

func TestOIDCValidator_AllowedClaims_NonStringValue(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	// Build a token with a numeric custom claim alongside the standard fields.
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key: jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	require.NoError(t, err)

	token, err := josejwt.Signed(signer).
		Claims(josejwt.Claims{
			Issuer:   testIssuer,
			Subject:  testSubject,
			Audience: josejwt.Audience{testAudience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		}).
		Claims(map[string]any{"numeric_claim": 42}).
		Serialize()
	require.NoError(t, err)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
		AllowedClaims:    map[string]string{"numeric_claim": "42"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeIDToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-string type")
}

func TestWithTrustedIssuers_RegistersValidators(t *testing.T) {
	key := newTestECKey(t)
	const kid = "test-key-1"
	jwksURL, _ := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	// Apply option directly (mirrors what New() does when opts are passed).
	WithTrustedIssuers([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testAudience},
	}})(srv)

	require.NotNil(t, srv.SubjectValidatorFor(SubjectTokenTypeIDToken))
	require.NotNil(t, srv.SubjectValidatorFor(SubjectTokenTypeAccessToken))
	require.NotNil(t, srv.SubjectValidatorFor(SubjectTokenTypeJWT))
}
