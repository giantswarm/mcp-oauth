package server

import (
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestExchangeSubjectToken_IssuedToken(t *testing.T) {
	key := newTestECKey(t)
	const kid = "exchange-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	ti := TrustedIssuer{
		Issuer:  testIssuer,
		JwksURL: jwksURL,
	}

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	signingKey := generateRSAKey(t)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"read", "write"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "test-kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{ti}, jwksClient)
	require.NoError(t, err)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: v,
	}

	subjectToken := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	result, err := srv.ExchangeSubjectToken(
		t.Context(),
		subjectToken,
		SubjectTokenTypeIDToken,
		"https://api.example.com",
		"read",
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)
	require.Equal(t, SubjectTokenTypeAccessToken, result.IssuedTokenType)
	require.False(t, result.ExpiresAt.IsZero())

	// Parse and verify claims.
	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var standard josejwt.Claims
	var private rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &standard, &private))

	require.Equal(t, testSubject, standard.Subject)
	require.Equal(t, josejwt.Audience{"https://api.example.com"}, standard.Audience)
	require.NotNil(t, private.Act)
	require.Equal(t, testIssuer, private.Act["iss"])
	require.Equal(t, testSubject, private.Act["sub"])
	require.Equal(t, "read", private.Scope)
}

func TestExchangeSubjectToken_ScopeIntersection(t *testing.T) {
	key := newTestECKey(t)
	const kid = "scope-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	ti := TrustedIssuer{
		Issuer:        testIssuer,
		JwksURL:       jwksURL,
		AllowedScopes: []string{"read", "write"},
	}

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	signingKey := generateRSAKey(t)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "test-kid-scope",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{ti}, jwksClient)
	require.NoError(t, err)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: v,
	}

	makeToken := func() string {
		return signSubjectToken(t, key, kid, josejwt.Claims{
			Issuer:   testIssuer,
			Subject:  testSubject,
			Audience: josejwt.Audience{testAudience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		})
	}

	t.Run("requested scope within allowed", func(t *testing.T) {
		result, err := srv.ExchangeSubjectToken(t.Context(), makeToken(), SubjectTokenTypeIDToken, "https://api.example.com", "read")
		require.NoError(t, err)
		require.Equal(t, "read", result.Scope)
	})

	t.Run("requested scope outside allowed", func(t *testing.T) {
		result, err := srv.ExchangeSubjectToken(t.Context(), makeToken(), SubjectTokenTypeIDToken, "https://api.example.com", "admin")
		require.NoError(t, err)
		// intersection of [admin] ∩ [read write] = empty
		require.Equal(t, "", result.Scope)
	})
}

func TestExchangeSubjectToken_NoAllowedScopes(t *testing.T) {
	key := newTestECKey(t)
	const kid = "noscope-key-1"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	ti := TrustedIssuer{
		Issuer:        testIssuer,
		JwksURL:       jwksURL,
		AllowedScopes: nil, // no restriction
	}

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	signingKey := generateRSAKey(t)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "test-kid-noscope",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{ti}, jwksClient)
	require.NoError(t, err)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: v,
	}

	subjectToken := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	result, err := srv.ExchangeSubjectToken(t.Context(), subjectToken, SubjectTokenTypeIDToken, "https://api.example.com", "read write admin")
	require.NoError(t, err)
	// Full requested scope granted when no per-issuer restriction.
	scopes := strings.Fields(result.Scope)
	require.ElementsMatch(t, []string{"read", "write", "admin"}, scopes)
}

func TestExchangeSubjectToken_UnknownTokenType(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	signingKey := generateRSAKey(t)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "test-kid-unknown",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)
	// No validators registered.

	_, err = srv.ExchangeSubjectToken(t.Context(), "sometoken", "urn:ietf:params:oauth:token-type:saml2", "https://api.example.com", "")
	require.Error(t, err)

	var unsupported *TokenExchangeUnsupportedTypeError
	require.ErrorAs(t, err, &unsupported)
	require.Equal(t, "urn:ietf:params:oauth:token-type:saml2", unsupported.TokenType())
}

func TestExchangeSubjectToken_RequiresJWTMode(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t) // opaque mode

	_, err := srv.ExchangeSubjectToken(t.Context(), "tok", SubjectTokenTypeIDToken, "https://api.example.com", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT access token mode")
}
