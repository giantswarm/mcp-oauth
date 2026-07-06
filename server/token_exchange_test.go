package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
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

func TestSelfIssuedExchange_IssuedToken(t *testing.T) {
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

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
	})
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
	require.Nil(t, private.Act, "act claim must be absent when no actor_token is provided")
	require.Equal(t, "read", private.Scope)
}

func TestSelfIssuedExchange_ScopeIntersection(t *testing.T) {
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
		result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: makeToken(), Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com", Scope: "read"}})
		require.NoError(t, err)
		require.Equal(t, "read", result.Scope)
	})

	t.Run("requested scope outside allowed", func(t *testing.T) {
		result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: makeToken(), Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com", Scope: "admin"}})
		require.NoError(t, err)
		// intersection of [admin] ∩ [read write] = empty
		require.Equal(t, "", result.Scope)
	})
}

func TestSelfIssuedExchange_NoAllowedScopes(t *testing.T) {
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

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com", Scope: "read write admin"}})
	require.NoError(t, err)
	// Full requested scope granted when no per-issuer restriction.
	scopes := strings.Fields(result.Scope)
	require.ElementsMatch(t, []string{"read", "write", "admin"}, scopes)
}

func TestSelfIssuedExchange_UnknownTokenType(t *testing.T) {
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

	_, err = srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "sometoken", Type: "urn:ietf:params:oauth:token-type:saml2"}, Resource: "https://api.example.com"}})
	require.Error(t, err)

	var unsupported *TokenExchangeUnsupportedTypeError
	require.ErrorAs(t, err, &unsupported)
	require.Equal(t, "urn:ietf:params:oauth:token-type:saml2", unsupported.TokenType())
}

func TestSelfIssuedExchange_RequiresJWTMode(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t) // opaque mode

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "tok", Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT access token mode")
}

// failingAccessTokenIssuer always returns an error from Issue.
type failingAccessTokenIssuer struct{ err error }

func (f failingAccessTokenIssuer) Issue(context.Context, AccessTokenClaims) (string, error) {
	return "", f.err
}

const auditExchangeKID = "audit-exchange-key"

// newAuditExchangeTestServer builds an exchange-ready Server wired to a
// buffer-backed slog logger. The returned EC key matches the registered
// SubjectTokenValidator so callers can create subject tokens that pass
// validation.
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

func TestSelfIssuedExchange_Audit_Success(t *testing.T) {
	srv, buf, key := newAuditExchangeTestServer(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: makeAuditSubjectToken(t, key), Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)

	out := buf.String()
	require.True(t, containsAuditEvent(out, security.EventTokenIssued),
		"expected token_issued audit event, got: %s", out)
	require.Contains(t, out, GrantTypeTokenExchange,
		"audit event must carry grant_type so dashboards can split exchange issuances")
	require.Contains(t, out, "https://api.example.com",
		"audit event must record the audience")
	require.Contains(t, out, "jti",
		"audit event must record the issued token's jti for correlation")
}

func TestSelfIssuedExchange_Audit_JWTModeRequired(t *testing.T) {
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

	_, err = srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "tok", Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com"}})
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "token_exchange_jwt_mode_required"),
		"missing jwt-mode-required audit failure in: %s", out)
	require.Contains(t, out, GrantTypeTokenExchange,
		"audit event must carry grant_type for dashboarding")
}

func TestSelfIssuedExchange_Audit_UnsupportedSubjectTokenType(t *testing.T) {
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
	_, err = srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "tok", Type: badType}, Resource: "https://api.example.com"}})
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

func TestSelfIssuedExchange_Audit_SubjectTokenValidationFailure(t *testing.T) {
	srv, buf, _ := newAuditExchangeTestServer(t)

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "not-a-real-token", Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com"}})
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "subject_token_validation_failed"),
		"missing subject_token_validation_failed audit failure in: %s", out)
	require.Contains(t, out, SubjectTokenTypeIDToken,
		"audit event must carry the subject_token_type for dashboarding")
}

func TestSelfIssuedExchange_Audit_AccessTokenIssueFailure(t *testing.T) {
	srv, buf, key := newAuditExchangeTestServer(t)

	srv.accessTokenIssuer = failingAccessTokenIssuer{err: fmt.Errorf("signer down")}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: makeAuditSubjectToken(t, key), Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com", Scope: "read"}})
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "access_token_issue_failed"),
		"missing access_token_issue_failed audit failure in: %s", out)
	require.Contains(t, out, "https://api.example.com",
		"audit event must record the audience on issuance failure")
}

func TestSelfIssuedExchange_Audit_AccessTokenIssueFailure_WithActor(t *testing.T) {
	srv, _ := newActorExchangeServer(t)

	logger, buf := captureLogger()
	srv.Auditor = security.NewAuditor(logger, true)
	srv.accessTokenIssuer = failingAccessTokenIssuer{err: fmt.Errorf("signer down")}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken}, Actor: TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken}, Resource: "https://api.example.com", Scope: "read"}})
	require.Error(t, err)

	out := buf.String()
	require.True(t, containsAuthFailure(out, "access_token_issue_failed"),
		"missing access_token_issue_failed audit failure in: %s", out)
	require.Contains(t, out, actorIssuerURL,
		"failure audit must record actor_iss for delegated exchange")
	require.Contains(t, out, actorTestSub,
		"failure audit must record actor_sub for delegated exchange")
}

func TestSelfIssuedExchange_DPoP(t *testing.T) {
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

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		DPoPJKT: jkt,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &claims))

	require.NotNil(t, claims.Cnf, "cnf claim must be present for DPoP-bound token")
	require.Equal(t, jkt, claims.Cnf.JKT, "cnf.jkt must match the DPoP key thumbprint")
}

// setupExchangeOptionsTest builds a JWT-mode Server with a single OIDCValidator
// registered for SubjectTokenTypeIDToken and returns the server, its signing
// key (for verifying issued tokens), and a freshly created subject token ready
// to be exchanged.
func setupExchangeOptionsTest(t *testing.T) (*Server, *rsa.PrivateKey, string) {
	t.Helper()

	key := newTestECKey(t)
	const kid = "exchange-options-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	signingKey := generateRSAKey(t)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"read", "write"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "options-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{Issuer: testIssuer, JwksURL: jwksURL}}, jwksClient)
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

	return srv, signingKey, subjectToken
}

func TestSelfIssuedExchange_WithIdentityClaims(t *testing.T) {
	srv, signingKey, subjectToken := setupExchangeOptionsTest(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		Options: ExchangeOptions{
			Email:         "klaus-sre@machine.giantswarm.io",
			EmailVerified: true,
			Name:          "Klaus SRE Agent",
			Groups:        []string{"klaus-sre", "machine"},
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var private rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &private))

	require.Equal(t, "klaus-sre@machine.giantswarm.io", private.Email)
	require.NotNil(t, private.EmailVerified)
	require.True(t, *private.EmailVerified)
	require.Equal(t, "Klaus SRE Agent", private.Name)
	require.Equal(t, []string{"klaus-sre", "machine"}, private.Groups)
	require.Nil(t, private.Act, "act claim must be absent when no actor_token is provided")
}

func TestSelfIssuedExchange_WithExtraClaims(t *testing.T) {
	srv, signingKey, subjectToken := setupExchangeOptionsTest(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		Options: ExchangeOptions{
			Extra: map[string]any{
				"principal_kind": "machine",
				"installation":   "glean",
			},
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]any
	require.NoError(t, parsed.Claims(signingKey.Public(), &rawClaims))

	require.Equal(t, "machine", rawClaims["principal_kind"])
	require.Equal(t, "glean", rawClaims["installation"])
}

// The subject token created by setupExchangeOptionsTest carries only
// iss/sub/aud/exp/iat, so the validated subject's Claims have no
// email/name/groups to default from and the issued token carries no identity.
func TestSelfIssuedExchange_NoSubjectClaims_NoIdentity(t *testing.T) {
	srv, signingKey, subjectToken := setupExchangeOptionsTest(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]any
	require.NoError(t, parsed.Claims(signingKey.Public(), &rawClaims))

	require.NotContains(t, rawClaims, "email")
	require.NotContains(t, rawClaims, "email_verified")
	require.NotContains(t, rawClaims, "name")
	require.NotContains(t, rawClaims, "groups")
}

func TestSelfIssuedExchange_EmailVerifiedFalseWithEmail(t *testing.T) {
	srv, signingKey, subjectToken := setupExchangeOptionsTest(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		Options: ExchangeOptions{
			Email:         "unverified@machine.giantswarm.io",
			EmailVerified: false,
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]any
	require.NoError(t, parsed.Claims(signingKey.Public(), &rawClaims))

	require.Equal(t, "unverified@machine.giantswarm.io", rawClaims["email"])
	require.Contains(t, rawClaims, "email_verified", "email_verified must be emitted when Email is set")
	require.Equal(t, false, rawClaims["email_verified"])
}

func TestSelfIssuedExchange_ExtraOverridesEmailVerified(t *testing.T) {
	srv, signingKey, subjectToken := setupExchangeOptionsTest(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: subjectToken, Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		Options: ExchangeOptions{
			Email:         "x@y.example",
			EmailVerified: false,
			Extra:         map[string]any{"email_verified": true},
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]any
	require.NoError(t, parsed.Claims(signingKey.Public(), &rawClaims))

	require.Equal(t, true, rawClaims["email_verified"])
}

const (
	actorIssuerURL = "https://actor.example.com"
	actorTestSub   = "agent-sa@cluster.example.com"
)

// newActorExchangeServer builds a Server wired with a stubTokenValidator for
// actor-delegation tests. The stub maps "sub-tok" → (testIssuer, testSubject)
// and "act-tok" → (actorIssuerURL, actorTestSub) so no JWKS round-trip is
// needed. Any validated actor is accepted.
func newActorExchangeServer(t *testing.T) (srv *Server, signingKey *rsa.PrivateKey) {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	signingKey = generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"read"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "actor-test-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}
	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	// validateExchangeActorToken uses the same SubjectValidatorFor dispatch as
	// the subject path, so both tokens must live under the same type key.
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{
			byToken: map[string]*SubjectIdentity{
				"sub-tok": {Subject: testSubject, Issuer: testIssuer},
				"act-tok": {Subject: actorTestSub, Issuer: actorIssuerURL},
			},
		},
	}
	return srv, signingKey
}

// TestSelfIssuedExchange_WithActor verifies that when a valid actor_token is
// presented, the issued JWT carries act.sub = actor subject and act.iss = actor
// issuer.
func TestSelfIssuedExchange_WithActor(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var private rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &private))

	require.Equal(t, testSubject, private.Subject)
	require.NotNil(t, private.Act, "act claim must be set for delegated exchange")
	require.Equal(t, actorIssuerURL, private.Act.Iss, "act.iss must be the actor token issuer")
	require.Equal(t, actorTestSub, private.Act.Sub, "act.sub must be the agent SA subject")
}

// TestSelfIssuedExchange_ActorTokenValidationFailure verifies that a
// rejected actor token (bad signature, unknown issuer, etc.) causes
// SelfIssuedExchange to return an error without issuing a token.
func TestSelfIssuedExchange_ActorTokenValidationFailure(t *testing.T) {
	srv, _ := newActorExchangeServer(t)

	// Replace the validator so "bad-act-tok" returns a validation error.
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{
			byToken: map[string]*SubjectIdentity{
				"sub-tok": {Subject: testSubject, Issuer: testIssuer},
			},
			byErr: map[string]error{
				"bad-act-tok": fmt.Errorf("signature verification failed"),
			},
		},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "bad-act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "actor token validation")
}

// TestSelfIssuedExchange_SelfDelegationIsNoOp verifies that when the actor
// token resolves to the same identity as the subject token, the actor is
// silently stripped and the exchange succeeds with no act claim — even when
// no actor reaches the act claim.
func TestSelfIssuedExchange_SelfDelegationIsNoOp(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)

	// Both "sub-tok" and "act-tok" now resolve to the same identity.
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{
			byToken: map[string]*SubjectIdentity{
				"sub-tok": {Subject: testSubject, Issuer: testIssuer},
				"act-tok": {Subject: testSubject, Issuer: testIssuer},
			},
		},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var private rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &private))

	require.Equal(t, testSubject, private.Subject)
	require.Nil(t, private.Act, "act claim must be absent when actor==subject")
}

// TestSelfIssuedExchange_RateLimited asserts the per-session issuance limiter is
// enforced in-process, not only in HTTP middleware, so an in-process caller
// (e.g. an aggregator) cannot flood issuance from one compromised session.
func TestSelfIssuedExchange_RateLimited(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.UserRateLimiter = security.NewRateLimiter(0, 1, nil) // burst of 1, no refill
	t.Cleanup(srv.UserRateLimiter.Stop)

	req := SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}}

	_, err := srv.SelfIssuedExchange(t.Context(), req)
	require.NoError(t, err)

	_, err = srv.SelfIssuedExchange(t.Context(), req)
	require.ErrorIs(t, err, ErrExchangeRateLimited, "second issuance in the same session must be rate-limited")
}
