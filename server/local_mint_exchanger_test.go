package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// parseMintedClaims verifies the minted token's signature and decodes its claims.
func parseMintedClaims(t *testing.T, token string, signingKey *rsa.PrivateKey, out any) {
	t.Helper()
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.NoError(t, parsed.Claims(signingKey.Public(), out))
}

// localMintCfg returns a JWT-mode Config and its RSA signing key for LocalMintExchanger tests.
func localMintCfg(t *testing.T) (*Config, *rsa.PrivateKey) {
	t.Helper()
	key := generateRSAKey(t)
	return &Config{
		Issuer:                      "https://mcp.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "lme-test-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		AccessTokenTTL:              600,
	}, key
}

// serveStaticRSAJWKS starts a TLS test server serving the RSA public key as a JWKS.
// The returned URL and JWKSClient are configured to allow private IPs (localhost).
func serveStaticRSAJWKS(t *testing.T, key *rsa.PrivateKey, kid string) (jwksURL string, client *oidc.JWKSClient) {
	t.Helper()
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	c := oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
		HTTPClient:     srv.Client(),
		AllowPrivateIP: true,
	})
	return srv.URL, c
}

func TestNewLocalMintExchanger_RejectsOpaqueMode(t *testing.T) {
	cfg := &Config{
		Issuer:            "https://mcp.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	_, err := NewLocalMintExchanger(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT access token mode")
}

func TestLocalMintExchanger_Exchange_NilSubject(t *testing.T) {
	cfg, _ := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	_, err = lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Scope:    "read",
		Subject:  nil,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Subject must not be nil")
}

func TestLocalMintExchanger_Exchange_NoActor(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Scope:    "read write",
		Subject: &SubjectIdentity{
			Subject:       "user@example.com",
			Issuer:        testIssuer,
			AllowedScopes: []string{"read", "write"},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)
	require.Equal(t, SubjectTokenTypeAccessToken, result.IssuedTokenType)
	require.True(t, result.ExpiresAt.After(time.Now()))

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &claims))

	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, cfg.Issuer, claims.Issuer)
	require.Contains(t, []string(claims.Audience), "https://api.example.com")
	require.Nil(t, claims.Act, "act claim must be absent when no actor is present")
	require.Equal(t, "read write", claims.Scope)
}

func TestLocalMintExchanger_Exchange_WithActor(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	const actorSub = "agent-sa@cluster.example.com"
	const actorIss = "https://k8s.example.com"

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Scope:    "read",
		Subject: &SubjectIdentity{
			Subject:       "user@example.com",
			Issuer:        testIssuer,
			AllowedScopes: []string{"read", "write"},
		},
		Actor: &SubjectIdentity{Subject: actorSub, Issuer: actorIss},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &claims))

	require.Equal(t, "user@example.com", claims.Subject)
	require.NotNil(t, claims.Act, "act claim must be set for delegated exchange")
	require.Equal(t, actorIss, claims.Act.Iss)
	require.Equal(t, actorSub, claims.Act.Sub)
}

func TestLocalMintExchanger_Exchange_ScopeIntersection(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Scope:    "read write admin",
		Subject: &SubjectIdentity{
			Subject:       "user@example.com",
			Issuer:        testIssuer,
			AllowedScopes: []string{"read", "write"},
		},
	})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims rfc9068Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &claims))

	require.NotContains(t, claims.Scope, "admin", "scope must be intersected with AllowedScopes")
}

// TestLocalMintExchanger_RoundTrip_IsDelegated mints a token with an actor and
// validates it back through an OIDCValidator (trusted-issuer path) to verify that
// UserInfo.IsDelegated() and ActorSubject/ActorIssuer are populated on the resource-server side.
func TestLocalMintExchanger_RoundTrip_IsDelegated(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	const actorSub = "agent-sa@cluster.example.com"
	const actorIss = "https://k8s.example.com"

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: cfg.Issuer,
		Scope:    "read",
		Subject:  &SubjectIdentity{Subject: "user@example.com", Issuer: testIssuer},
		Actor:    &SubjectIdentity{Subject: actorSub, Issuer: actorIss},
	})
	require.NoError(t, err)

	jwksURL, jwksClient := serveStaticRSAJWKS(t, signingKey, "lme-test-kid")

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	srv, _, _ := setupFlowTestServer(t)
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             cfg.Issuer,
		JwksURL:            jwksURL,
		AllowedAudiences:   []string{cfg.Issuer},
		AllowPrivateIPJWKS: true,
		AcceptedTypHeaders: []string{"at+jwt"},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	userInfo, err := srv.ValidateToken(t.Context(), result.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "user@example.com", userInfo.ID)
	require.Equal(t, providers.TokenSourceTrustedIssuer, userInfo.TokenSource)
	require.True(t, userInfo.IsDelegated(), "IsDelegated must be true for OBO token")
	require.Equal(t, actorSub, userInfo.ActorSubject)
	require.Equal(t, actorIss, userInfo.ActorIssuer)
}

// TestLocalMintExchanger_Exchange_EmitsIdentityClaims asserts the validated
// subject's email/email_verified/groups are copied into the minted token so
// downstreams can authorize and attribute without an extra IdP round-trip, and
// that the issued jti is surfaced on the result for the mint audit record.
func TestLocalMintExchanger_Exchange_EmitsIdentityClaims(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Scope:    "read",
		Subject: &SubjectIdentity{
			Subject:       "user@example.com",
			Issuer:        testIssuer,
			AllowedScopes: []string{"read"},
			Claims: &oidc.IDTokenClaims{
				Email:         "user@example.com",
				EmailVerified: true,
				Groups:        []string{"customer:Panamax_User", "customer:sre"},
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.JTI)

	var claims rfc9068Claims
	parseMintedClaims(t, result.AccessToken, signingKey, &claims)

	require.Equal(t, "user@example.com", claims.Email)
	require.NotNil(t, claims.EmailVerified)
	require.True(t, *claims.EmailVerified)
	require.Equal(t, []string{"customer:Panamax_User", "customer:sre"}, claims.Groups)
	require.Equal(t, claims.ID, result.JTI, "surfaced JTI must equal the token's jti claim")
}

// TestLocalMintExchanger_Exchange_NoIdentityClaimsWithoutSubjectClaims asserts a
// subject token without decoded Claims yields no email/groups on the mint, and
// that email_verified is never emitted without an email.
func TestLocalMintExchanger_Exchange_NoIdentityClaimsWithoutSubjectClaims(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Subject:  &SubjectIdentity{Subject: "user@example.com", Issuer: testIssuer},
	})
	require.NoError(t, err)

	var claims rfc9068Claims
	parseMintedClaims(t, result.AccessToken, signingKey, &claims)

	require.Empty(t, claims.Email)
	require.Nil(t, claims.EmailVerified)
	require.Empty(t, claims.Groups)
}

// TestLocalMintExchanger_Exchange_NestsPriorActorChain asserts a second-hop mint
// nests the actor already on the subject token (RFC 8693 §4.4) instead of
// overwriting it, so a multi-hop A2A chain is preserved.
func TestLocalMintExchanger_Exchange_NestsPriorActorChain(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Subject: &SubjectIdentity{
			Subject: "user@example.com",
			Issuer:  testIssuer,
			Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			},
		},
		Actor: &SubjectIdentity{Issuer: "https://k8s.example.com", Subject: "agentB"},
	})
	require.NoError(t, err)

	var claims rfc9068Claims
	parseMintedClaims(t, result.AccessToken, signingKey, &claims)

	require.Equal(t, "user@example.com", claims.Subject)
	require.NotNil(t, claims.Act)
	require.Equal(t, "agentB", claims.Act.Sub, "outermost act is the most recent actor")
	require.NotNil(t, claims.Act.Act)
	require.Equal(t, "agentA", claims.Act.Act.Sub, "prior actor nested beneath the new one")
	require.Nil(t, claims.Act.Act.Act, "chain ends at the first hop")
}

// TestLocalMintExchanger_Exchange_PreservesChainWithoutNewActor asserts that
// when no new actor delegates, an act chain already on the subject token is
// carried forward unchanged rather than dropped.
func TestLocalMintExchanger_Exchange_PreservesChainWithoutNewActor(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Subject: &SubjectIdentity{
			Subject: "user@example.com",
			Issuer:  testIssuer,
			Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			},
		},
	})
	require.NoError(t, err)

	var claims rfc9068Claims
	parseMintedClaims(t, result.AccessToken, signingKey, &claims)

	require.NotNil(t, claims.Act)
	require.Equal(t, "agentA", claims.Act.Sub)
	require.Nil(t, claims.Act.Act)
}

// TestLocalMintExchanger_Exchange_RejectsTooDeepChain asserts an act chain that
// would exceed maxActorChainDepth is rejected fail-closed, bounding abuse.
func TestLocalMintExchanger_Exchange_RejectsTooDeepChain(t *testing.T) {
	cfg, _ := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	// A prior chain already at the maximum depth; nesting a new actor exceeds it.
	deep := &oidc.ActorClaim{Issuer: testIssuer, Subject: "a0"}
	for i := 1; i < maxActorChainDepth; i++ {
		deep = &oidc.ActorClaim{Issuer: testIssuer, Subject: fmt.Sprintf("a%d", i), Act: deep}
	}

	_, err = lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: "https://api.example.com",
		Subject: &SubjectIdentity{
			Subject: "user@example.com",
			Issuer:  testIssuer,
			Claims:  &oidc.IDTokenClaims{Act: deep},
		},
		Actor: &SubjectIdentity{Issuer: testIssuer, Subject: "newAgent"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "actor chain depth")
}

// TestLocalMintExchanger_RoundTrip_ActorChain mints a two-hop OBO token and
// validates it back through an OIDCValidator, asserting the full delegation
// chain surfaces on UserInfo.ActorChain (outermost actor first) so backends can
// authorize on any actor in the chain, not only the leaf.
func TestLocalMintExchanger_RoundTrip_ActorChain(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: cfg.Issuer,
		Subject: &SubjectIdentity{
			Subject: "user@example.com",
			Issuer:  testIssuer,
			Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			},
		},
		Actor: &SubjectIdentity{Issuer: "https://k8s.example.com", Subject: "agentB"},
	})
	require.NoError(t, err)

	jwksURL, jwksClient := serveStaticRSAJWKS(t, signingKey, "lme-test-kid")
	srv, _, _ := setupFlowTestServer(t)
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             cfg.Issuer,
		JwksURL:            jwksURL,
		AllowedAudiences:   []string{cfg.Issuer},
		AllowPrivateIPJWKS: true,
		AcceptedTypHeaders: []string{"at+jwt"},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	userInfo, err := srv.ValidateToken(t.Context(), result.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "agentB", userInfo.ActorSubject, "leaf mirrors the most recent actor")
	require.Len(t, userInfo.ActorChain, 2)
	require.Equal(t, "agentB", userInfo.ActorChain[0].Subject)
	require.Equal(t, "agentA", userInfo.ActorChain[1].Subject)
}

// TestLocalMintExchanger_RoundTrip_ForgedChainUntrustedIssuerRejected asserts a
// token carrying an act chain but signed by an issuer the validator does not
// trust is rejected at the issuer-trust boundary. Inner hops are not
// individually re-validated — the chain is only as trustworthy as the signer of
// the token that carries it — so an untrusted signer fails the whole token
// closed and a fabricated chain cannot be smuggled in.
func TestLocalMintExchanger_RoundTrip_ForgedChainUntrustedIssuerRejected(t *testing.T) {
	cfg, signingKey := localMintCfg(t)
	lme, err := NewLocalMintExchanger(cfg)
	require.NoError(t, err)

	result, err := lme.Exchange(t.Context(), &ExchangerRequest{
		Resource: cfg.Issuer,
		Subject: &SubjectIdentity{
			Subject: "user@example.com",
			Issuer:  testIssuer,
			Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://attacker.example", Subject: "agentA"},
			},
		},
		Actor: &SubjectIdentity{Issuer: "https://attacker.example", Subject: "agentB"},
	})
	require.NoError(t, err)

	jwksURL, jwksClient := serveStaticRSAJWKS(t, signingKey, "lme-test-kid")
	// Validator trusts a different issuer than the token's iss.
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             "https://other-broker.example",
		JwksURL:            jwksURL,
		AllowPrivateIPJWKS: true,
		AcceptedTypHeaders: []string{"at+jwt"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), result.AccessToken, []string{cfg.Issuer})
	require.ErrorIs(t, err, ErrIssuerNotTrusted)
}
