package server

import (
	"testing"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

const subjectClaimTestResource = "https://mcp.test.example/mcp"

// newTrustedIssuerHarness returns a harness whose server trusts the
// harness issuer for entry's settings, and no forwarded audiences.
func newTrustedIssuerHarness(t *testing.T, entry TrustedIssuer, configure func(*Config)) *forwardedTokenHarness {
	t.Helper()
	h := newForwardedTokenHarness(t, func(c *Config) {
		c.TrustedAudiences = nil
		c.ResourceIdentifier = subjectClaimTestResource
		if configure != nil {
			configure(c)
		}
	})
	entry.Issuer = h.issuer
	entry.JwksURL = h.jwksServer.URL
	entry.AcceptedTypHeaders = []string{"JWT"}
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{entry}, h.srv.jwksClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = validator
	return h
}

func TestTrustedIssuerSubjectClaimUsername(t *testing.T) {
	h := newTrustedIssuerHarness(t, TrustedIssuer{AllowedAudiences: []string{"forwarded-audience"}, SubjectClaim: claimEmail}, nil)
	token := signTestRS256Token(t, h.privateKey, h.keyID, oidc.IDTokenClaims{
		Claims:        h.validClaims(),
		Email:         "user@test.example",
		EmailVerified: true,
	})

	userInfo, err := h.srv.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, "user@test.example", userInfo.Username)

	acceptance, err := h.srv.AcceptTrustedIssuerToken(t.Context(), token)
	require.NoError(t, err)
	require.Equal(t, "user@test.example", acceptance.Subject)
	require.Equal(t, "user-subject-123", acceptance.UserInfo.ID)
	require.Equal(t, "user@test.example", acceptance.UserInfo.Username)
}

func TestTrustedIssuerUsernameDefaultsToSub(t *testing.T) {
	h := newTrustedIssuerHarness(t, TrustedIssuer{AllowedAudiences: []string{"forwarded-audience"}}, nil)

	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, h.validClaims()))

	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.Username)
}

func TestAcceptTrustedIssuerToken_RequireResourceAccessTokens(t *testing.T) {
	h := newTrustedIssuerHarness(t, TrustedIssuer{AllowedAudiences: []string{"forwarded-audience", subjectClaimTestResource}},
		func(c *Config) { c.RequireResourceAccessTokens = true })
	resourceClaims := h.validClaims()
	resourceClaims.Audience = josejwt.Audience{subjectClaimTestResource}

	_, err := h.srv.AcceptTrustedIssuerToken(t.Context(), h.signToken(t, h.validClaims()))
	require.Error(t, err)

	_, err = h.srv.AcceptTrustedIssuerToken(t.Context(), h.signToken(t, resourceClaims))
	require.NoError(t, err)
}

func TestAcceptTrustedIssuerToken_NotCountedAsForwardedIDToken(t *testing.T) {
	h := newTrustedIssuerHarness(t, TrustedIssuer{AllowedAudiences: []string{"forwarded-audience"}}, nil)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	inst, err := instrumentation.New(instrumentation.Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	h.srv.Instrumentation = inst

	_, err = h.srv.AcceptTrustedIssuerToken(t.Context(), h.signToken(t, h.validClaims()))
	require.NoError(t, err)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names = append(names, m.Name)
		}
	}
	require.Contains(t, names, "oauth.trusted_issuer_token.accepted_total")
	require.NotContains(t, names, "oauth.forwarded_id_token.accepted_total")
}
