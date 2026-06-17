package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// newSATrustedIssuerServer wires a Server with a TrustedIssuer entry that
// accepts Kubernetes ServiceAccount-style tokens (no typ header, sub glob).
func newSATrustedIssuerServer(t *testing.T) (srv *Server, signFn func(claims josejwt.Claims) string, resourceID string) {
	t.Helper()

	ecKey := newTestECKey(t)
	const kid = "sa-key"
	jwksURL, jwksClient := serveStaticJWKS(t, ecKey, kid)

	srv, _, _ = setupFlowTestServer(t)
	resourceID = srv.Config.GetResourceIdentifier()

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             "https://kubernetes.default.svc.cluster.local",
		JwksURL:            jwksURL,
		AllowedAudiences:   []string{resourceID},
		AllowPrivateIPJWKS: true,
		// Kubernetes SA tokens carry no typ header.
		AcceptedTypHeaders: []string{""},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	signFn = func(claims josejwt.Claims) string {
		t.Helper()
		// Use signSubjectToken which omits the typ header (sets "JWT") —
		// but for AcceptedTypHeaders: [""] we need NO typ header at all.
		// Use the helper that supports a custom typ, passing empty string.
		return signSubjectTokenWithType(t, ecKey, kid, "", claims)
	}
	return srv, signFn, resourceID
}

func saTokenClaims(issuer, sub, audience string) josejwt.Claims {
	now := time.Now()
	return josejwt.Claims{
		Issuer:   issuer,
		Subject:  sub,
		Audience: josejwt.Audience{audience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	}
}

func TestAcceptTrustedIssuerToken_HappyPath(t *testing.T) {
	srv, sign, resourceID := newSATrustedIssuerServer(t)

	const (
		k8sIssuer = "https://kubernetes.default.svc.cluster.local"
		sub       = "system:serviceaccount:ai-platform:my-svc"
	)
	tok := sign(saTokenClaims(k8sIssuer, sub, resourceID))

	acc, err := srv.AcceptTrustedIssuerToken(context.Background(), tok)
	require.NoError(t, err)
	require.NotNil(t, acc)

	require.Equal(t, sub, acc.Subject)
	require.Equal(t, k8sIssuer, acc.Issuer)
	require.Equal(t, resourceID, acc.Audience)
	require.True(t, strings.HasPrefix(acc.SessionID, "ext-"), "SessionID must start with ext-")
	require.Len(t, acc.SessionID, len("ext-")+16, "SessionID must be ext-<16 hex>")
	require.False(t, acc.ExpiresAt.IsZero(), "ExpiresAt must be populated from JWT exp")

	require.NotNil(t, acc.UserInfo)
	require.Equal(t, sub, acc.UserInfo.ID)
	require.Equal(t, k8sIssuer, acc.UserInfo.Issuer)
	require.Equal(t, providers.TokenSourceTrustedIssuer, acc.UserInfo.TokenSource)
	require.True(t, acc.UserInfo.IsExternalIssuer())
	require.False(t, acc.UserInfo.IsSSO())
	require.Empty(t, acc.UserInfo.Email, "SA tokens carry no email")
}

func TestAcceptTrustedIssuerToken_Determinism(t *testing.T) {
	srv, sign, resourceID := newSATrustedIssuerServer(t)
	tok := sign(saTokenClaims("https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ns:sa", resourceID))

	ctx := context.Background()
	a1, err := srv.AcceptTrustedIssuerToken(ctx, tok)
	require.NoError(t, err)
	a2, err := srv.AcceptTrustedIssuerToken(ctx, tok)
	require.NoError(t, err)

	require.Equal(t, a1.SessionID, a2.SessionID, "SessionID must be deterministic for the same token")
}

func TestAcceptTrustedIssuerToken_SessionIDMatchesForwardedPath(t *testing.T) {
	// The ext-<hex> derivation must be identical regardless of which Accept*
	// method produced the acceptance, so an aggregator that receives the same
	// bearer via different paths always correlates to the same session.
	srv, sign, resourceID := newSATrustedIssuerServer(t)
	tok := sign(saTokenClaims("https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ns:sa", resourceID))

	acc, err := srv.AcceptTrustedIssuerToken(context.Background(), tok)
	require.NoError(t, err)

	expected := srv.deriveForwardedSessionID(tok)
	require.Equal(t, expected, acc.SessionID)
}

func TestAcceptTrustedIssuerToken_NilValidator(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	// trustedIssuerValidator is nil by default — no WithTrustedIssuers configured.

	_, err := srv.AcceptTrustedIssuerToken(context.Background(), "any.token.value")
	require.ErrorIs(t, err, ErrIssuerNotTrusted)
}

func TestAcceptTrustedIssuerToken_UntrustedIssuer(t *testing.T) {
	srv, sign, resourceID := newSATrustedIssuerServer(t)
	// Token issued by an issuer not in the configured set.
	tok := sign(saTokenClaims("https://other.issuer.example", "system:serviceaccount:ns:sa", resourceID))

	_, err := srv.AcceptTrustedIssuerToken(context.Background(), tok)
	require.ErrorIs(t, err, ErrIssuerNotTrusted)
}

func TestAcceptTrustedIssuerToken_ExpiredToken(t *testing.T) {
	srv, sign, resourceID := newSATrustedIssuerServer(t)

	past := time.Now().Add(-2 * time.Hour)
	claims := josejwt.Claims{
		Issuer:   "https://kubernetes.default.svc.cluster.local",
		Subject:  "system:serviceaccount:ns:sa",
		Audience: josejwt.Audience{resourceID},
		IssuedAt: josejwt.NewNumericDate(past),
		Expiry:   josejwt.NewNumericDate(past.Add(time.Hour)), // expired an hour ago
	}
	tok := sign(claims)

	_, err := srv.AcceptTrustedIssuerToken(context.Background(), tok)
	require.Error(t, err)
	require.True(t, errors.Is(err, oidc.ErrTokenExpired), "want ErrTokenExpired, got: %v", err)
}

func TestAcceptTrustedIssuerToken_EmptyToken(t *testing.T) {
	srv, _, _ := newSATrustedIssuerServer(t)

	_, err := srv.AcceptTrustedIssuerToken(context.Background(), "")
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrIssuerNotTrusted), "empty token should not return ErrIssuerNotTrusted")
}
