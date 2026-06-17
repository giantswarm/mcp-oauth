package server

import (
	"crypto/rsa"
	"encoding/json"
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
