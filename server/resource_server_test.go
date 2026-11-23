package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const resourceServerTestIssuer = "https://dex.test.example"

func resourceServerConfig() *Config {
	return &Config{
		Issuer:                     "https://mcp.test.example",
		ResourceIdentifier:         "https://mcp.test.example/mcp",
		DisableAuthorizationServer: true,
	}
}

func dexTrustedIssuer(audiences ...string) TrustedIssuer {
	return TrustedIssuer{
		Issuer:             resourceServerTestIssuer,
		JwksURL:            resourceServerTestIssuer + "/keys",
		AllowedAudiences:   audiences,
		AcceptedTypHeaders: []string{"JWT"},
	}
}

func newResourceServer(t *testing.T, configuration *Config, logger *slog.Logger, opts ...Option) (*Server, error) {
	t.Helper()
	store := memory.New()
	srv, err := New(nil, store, store, store, configuration, logger, opts...)
	if err != nil {
		store.Stop()
		return nil, err
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.WithoutCancel(t.Context())) })
	return srv, nil
}

func TestNew_ProviderRequiredWithAuthorizationServerOn(t *testing.T) {
	configuration := resourceServerConfig()
	configuration.DisableAuthorizationServer = false

	_, err := newResourceServer(t, configuration, nil)

	require.ErrorContains(t, err, "provider is required")
}

func TestNew_AuthorizationServerOff(t *testing.T) {
	srv, err := newResourceServer(t, resourceServerConfig(), nil, WithTrustedIssuers([]TrustedIssuer{dexTrustedIssuer("platform")}))

	require.NoError(t, err)
	require.Nil(t, srv.provider)
}

func TestNew_AuthorizationServerOffRequiresTrustedIssuer(t *testing.T) {
	_, err := newResourceServer(t, resourceServerConfig(), nil)

	require.ErrorContains(t, err, "DisableAuthorizationServer requires WithTrustedIssuers")
}

func TestNew_AuthorizationServerOffRefusesInvalidTrustedIssuers(t *testing.T) {
	_, err := newResourceServer(t, resourceServerConfig(), nil, WithTrustedIssuers([]TrustedIssuer{{Issuer: resourceServerTestIssuer}}))

	require.ErrorContains(t, err, "trusted issuers")
}

func TestConfigValidate_AuthorizationServerOffRefusesAuthorizationServerSettings(t *testing.T) {
	for name, set := range map[string]func(*Config){
		"TrustedAudiences":               func(c *Config) { c.TrustedAudiences = []string{"platform"} },
		"EnableIntrospectionEndpoint":    func(c *Config) { c.EnableIntrospectionEndpoint = true },
		"EnableUserInfoEndpoint":         func(c *Config) { c.EnableUserInfoEndpoint = true },
		"EnableClientManagementEndpoint": func(c *Config) { c.EnableClientManagementEndpoint = true },
		"AccessTokenFormat jwt":          func(c *Config) { c.AccessTokenFormat = AccessTokenFormatJWT },
	} {
		t.Run(name, func(t *testing.T) {
			configuration := resourceServerConfig()
			set(configuration)

			require.ErrorContains(t, configuration.Validate(), name+" requires the authorization server")
		})
	}
}

func TestConfigValidate_ClientManagementRequiresDynamicClientRegistration(t *testing.T) {
	configuration := &Config{
		Issuer:                           "https://mcp.test.example",
		DisableDynamicClientRegistration: true,
		EnableClientManagementEndpoint:   true,
	}

	require.ErrorContains(t, configuration.Validate(), "requires Dynamic Client Registration")
}

func TestConfig_RegistrationEnabled(t *testing.T) {
	require.True(t, (&Config{}).RegistrationEnabled())
	require.False(t, (&Config{DisableDynamicClientRegistration: true}).RegistrationEnabled())
	require.False(t, (&Config{DisableAuthorizationServer: true}).RegistrationEnabled())
}

func TestNew_RequireResourceAccessTokensRefusesIssuerWithoutResourceAudience(t *testing.T) {
	configuration := resourceServerConfig()
	configuration.RequireResourceAccessTokens = true

	_, err := newResourceServer(t, configuration, nil, WithTrustedIssuers([]TrustedIssuer{dexTrustedIssuer("platform")}))

	require.ErrorContains(t, err, `trusted issuer "https://dex.test.example": RequireResourceAccessTokens needs AllowedAudiences to name the resource "https://mcp.test.example/mcp"`)
}

func TestNew_RequireResourceAccessTokensAcceptsIssuerNamingResource(t *testing.T) {
	for name, audiences := range map[string][]string{
		"resource listed": {"platform", "https://mcp.test.example/mcp"},
		"no audiences":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			configuration := resourceServerConfig()
			configuration.RequireResourceAccessTokens = true

			_, err := newResourceServer(t, configuration, nil, WithTrustedIssuers([]TrustedIssuer{dexTrustedIssuer(audiences...)}))

			require.NoError(t, err)
		})
	}
}

func TestNew_AuthorizationServerOffWarnsWithoutAdvertisedAuthorizationServer(t *testing.T) {
	for name, tc := range map[string]struct {
		resources map[string]ProtectedResourceConfig
		warns     bool
	}{
		"none advertised": {warns: true},
		"one advertised": {
			resources: map[string]ProtectedResourceConfig{"/mcp": {AuthorizationServers: []string{resourceServerTestIssuer}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			configuration := resourceServerConfig()
			configuration.ResourceMetadataByPath = tc.resources

			_, err := newResourceServer(t, configuration, slog.New(slog.NewTextHandler(&logs, nil)), WithTrustedIssuers([]TrustedIssuer{dexTrustedIssuer("platform")}))

			require.NoError(t, err)
			require.Equal(t, tc.warns, strings.Contains(logs.String(), "No authorization server is advertised"))
		})
	}
}

func TestValidateToken_AuthorizationServerOffRefusesStoredToken(t *testing.T) {
	srv, err := newResourceServer(t, resourceServerConfig(), nil, WithTrustedIssuers([]TrustedIssuer{dexTrustedIssuer("platform")}))
	require.NoError(t, err)
	require.NoError(t, srv.tokenStore.SaveToken(t.Context(), "opaque-token", &oauth2.Token{AccessToken: "provider-token", Expiry: time.Now().Add(time.Hour)}))

	userInfo, err := srv.ValidateToken(t.Context(), "opaque-token")

	require.ErrorIs(t, err, errInvalidAccessToken)
	require.Nil(t, userInfo)
}

func TestIsOpenIDProviderIssuer(t *testing.T) {
	dex := dexTrustedIssuer("platform")
	dex.OpenIDProvider = true
	other := TrustedIssuer{Issuer: "https://muster.test.example", JwksURL: "https://muster.test.example/keys", AllowedAudiences: []string{"platform"}}
	srv, err := newResourceServer(t, resourceServerConfig(), nil, WithTrustedIssuers([]TrustedIssuer{dex, other}))
	require.NoError(t, err)

	require.True(t, srv.IsOpenIDProviderIssuer(dex.Issuer))
	require.False(t, srv.IsOpenIDProviderIssuer(other.Issuer))
	require.False(t, srv.IsOpenIDProviderIssuer("https://unknown.test.example"))
}

// collectTrustedIssuerTokens replaces the server's instrumentation with one
// backed by a manual reader and returns a function collecting the
// resource_audience labels recorded on
// oauth.trusted_issuer_token.accepted_total.
func collectTrustedIssuerTokens(t *testing.T, srv *Server) func() []bool {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.WithoutCancel(t.Context())) })
	inst, err := instrumentation.New(instrumentation.Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	srv.Instrumentation = inst

	return func() []bool {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &rm))
		var labels []bool
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "oauth.trusted_issuer_token.accepted_total" {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "unexpected data type %T", m.Data)
				for _, dp := range sum.DataPoints {
					value, _ := dp.Attributes.Value(attribute.Key("resource_audience"))
					for range dp.Value {
						labels = append(labels, value.AsBool())
					}
				}
			}
		}
		return labels
	}
}

func TestValidateToken_TrustedIssuerTokenCountedWithResourceAudience(t *testing.T) {
	h := newForwardedTokenHarness(t, func(c *Config) {
		c.TrustedAudiences = nil
		c.ResourceIdentifier = "https://mcp.test.example/mcp"
	})
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             h.issuer,
		JwksURL:            h.jwksServer.URL,
		AllowedAudiences:   []string{h.audience, h.srv.Config.ResourceIdentifier},
		AcceptedTypHeaders: []string{"JWT"},
	}}, h.srv.jwksClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = validator
	accepted := collectTrustedIssuerTokens(t, h.srv)

	idToken := h.validClaims()
	resourceToken := h.validClaims()
	resourceToken.Audience = josejwt.Audience{h.srv.Config.ResourceIdentifier}
	for _, claims := range []josejwt.Claims{idToken, resourceToken} {
		_, err := h.srv.ValidateToken(t.Context(), h.signToken(t, claims))
		require.NoError(t, err)
	}

	require.ElementsMatch(t, []bool{false, true}, accepted())
}
