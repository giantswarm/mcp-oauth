package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
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
		"",
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
	require.Equal(t, testIssuer, private.Act.Iss)
	require.Equal(t, testSubject, private.Act.Sub)
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
		result, err := srv.ExchangeSubjectToken(t.Context(), makeToken(), SubjectTokenTypeIDToken, "https://api.example.com", "read", "")
		require.NoError(t, err)
		require.Equal(t, "read", result.Scope)
	})

	t.Run("requested scope outside allowed", func(t *testing.T) {
		result, err := srv.ExchangeSubjectToken(t.Context(), makeToken(), SubjectTokenTypeIDToken, "https://api.example.com", "admin", "")
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

	result, err := srv.ExchangeSubjectToken(t.Context(), subjectToken, SubjectTokenTypeIDToken, "https://api.example.com", "read write admin", "")
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

	_, err = srv.ExchangeSubjectToken(t.Context(), "sometoken", "urn:ietf:params:oauth:token-type:saml2", "https://api.example.com", "", "")
	require.Error(t, err)

	var unsupported *TokenExchangeUnsupportedTypeError
	require.ErrorAs(t, err, &unsupported)
	require.Equal(t, "urn:ietf:params:oauth:token-type:saml2", unsupported.TokenType())
}

func TestExchangeSubjectToken_RequiresJWTMode(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t) // opaque mode

	_, err := srv.ExchangeSubjectToken(t.Context(), "tok", SubjectTokenTypeIDToken, "https://api.example.com", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT access token mode")
}

// failingAccessTokenIssuer always returns an error from Issue. Used to drive
// the post-validation issuance branch of ExchangeSubjectToken in tests.
type failingAccessTokenIssuer struct{ err error }

func (f failingAccessTokenIssuer) Issue(context.Context, AccessTokenClaims) (string, error) {
	return "", f.err
}

const auditExchangeKID = "audit-exchange-key"

// newAuditExchangeTestServer builds an exchange-ready Server wired to a
// buffer-backed slog logger so audit emissions can be asserted from log
// output. The returned EC key matches the registered SubjectTokenValidator
// so callers can mint subject tokens that pass validation.
func newAuditExchangeTestServer(t *testing.T) (*Server, *bytes.Buffer, *ecdsa.PrivateKey) {
	t.Helper()

	ecKey := newTestECKey(t)
	jwksURL, jwksClient := serveStaticJWKS(t, ecKey, auditExchangeKID)

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	logger, buf := captureLogger()

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"read", "write"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "audit-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)

	v, err := newOIDCValidatorWithClient(
		[]TrustedIssuer{{Issuer: testIssuer, JwksURL: jwksURL}},
		jwksClient,
	)
	require.NoError(t, err)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: v,
	}

	return srv, buf, ecKey
}

func makeAuditSubjectToken(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	return signSubjectToken(t, key, auditExchangeKID, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})
}

func TestExchangeSubjectToken_Audit_Success(t *testing.T) {
	srv, buf, key := newAuditExchangeTestServer(t)

	result, err := srv.ExchangeSubjectToken(
		t.Context(),
		makeAuditSubjectToken(t, key),
		SubjectTokenTypeIDToken,
		"https://api.example.com",
		"read",
		"",
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)

	out := buf.String()
	require.True(t, containsAuditEvent(out, security.EventTokenIssued),
		"expected token_issued audit event, got: %s", out)
	require.Contains(t, out, GrantTypeTokenExchange,
		"audit event must carry grant_type so dashboards can split exchange issuances")
	require.Contains(t, out, "https://api.example.com",
		"audit event must record the audience")
	require.Contains(t, out, "act_iss")
}

func TestExchangeSubjectToken_Audit_JWTModeRequired(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	logger, buf := captureLogger()

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)

	_, err = srv.ExchangeSubjectToken(t.Context(), "tok", SubjectTokenTypeIDToken,
		"https://api.example.com", "", "")
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "token_exchange_jwt_mode_required"),
		"missing jwt-mode-required audit failure in: %s", out)
	require.Contains(t, out, GrantTypeTokenExchange,
		"audit event must carry grant_type for dashboarding")
}

func TestExchangeSubjectToken_Audit_UnsupportedSubjectTokenType(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	logger, buf := captureLogger()

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "audit-unsupported-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)

	const badType = "urn:ietf:params:oauth:token-type:saml2"
	_, err = srv.ExchangeSubjectToken(t.Context(), "tok", badType,
		"https://api.example.com", "", "")
	require.Error(t, err)
	var unsupported *TokenExchangeUnsupportedTypeError
	require.ErrorAs(t, err, &unsupported)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "unsupported_subject_token_type"),
		"missing unsupported_subject_token_type audit failure in: %s", out)
	require.Contains(t, out, badType,
		"audit event must carry the rejected subject_token_type for dashboarding")
	require.Contains(t, out, GrantTypeTokenExchange,
		"audit event must carry grant_type for dashboarding")
}

func TestExchangeSubjectToken_Audit_SubjectTokenValidationFailure(t *testing.T) {
	srv, buf, _ := newAuditExchangeTestServer(t)

	_, err := srv.ExchangeSubjectToken(t.Context(), "not-a-real-token",
		SubjectTokenTypeIDToken, "https://api.example.com", "", "")
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "subject_token_validation_failed"),
		"missing subject_token_validation_failed audit failure in: %s", out)
	require.Contains(t, out, SubjectTokenTypeIDToken,
		"audit event must carry the subject_token_type for dashboarding")
}

func TestExchangeSubjectToken_Audit_AccessTokenIssueFailure(t *testing.T) {
	srv, buf, key := newAuditExchangeTestServer(t)

	srv.accessTokenIssuer = failingAccessTokenIssuer{err: fmt.Errorf("signer down")}

	_, err := srv.ExchangeSubjectToken(t.Context(), makeAuditSubjectToken(t, key),
		SubjectTokenTypeIDToken, "https://api.example.com", "read", "")
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "access_token_issue_failed"),
		"missing access_token_issue_failed audit failure in: %s", out)
	require.Contains(t, out, "https://api.example.com",
		"audit event must record the audience on issuance failure")
	require.Contains(t, out, "act_iss",
		"audit event must record the upstream actor issuer on issuance failure")
}

func TestExchangeSubjectToken_DPoP(t *testing.T) {
	key := newTestECKey(t)
	const kid = "dpop-exchange-key"
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
		SupportedScopes:             []string{"read"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "dpop-kid",
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

	dpopKey := newDPoPKey(t)
	jkt := dpopJKTFor(t, dpopKey)

	result, err := srv.ExchangeSubjectToken(
		t.Context(),
		subjectToken,
		SubjectTokenTypeIDToken,
		"https://api.example.com",
		"read",
		jkt,
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &claims))

	require.NotNil(t, claims.Cnf, "cnf claim must be present for DPoP-bound token")
	require.Equal(t, jkt, claims.Cnf.JKT, "cnf.jkt must match the DPoP key thumbprint")
}
