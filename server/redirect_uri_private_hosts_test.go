package server

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectURIPrivateHosts(t *testing.T) {
	const privateHost = "gateway.internal.example.com"
	listedHosts := []string{privateHost}
	tests := []struct {
		name         string
		hostname     string
		addresses    []string
		allowedHosts []string
		allowGlobal  bool
		category     string
	}{
		{"default blocks private IPv4", privateHost, []string{"10.0.0.1"}, nil, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"default blocks IPv6 ULA", privateHost, []string{"fd00::1"}, nil, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"listed RFC 1918 10/8", privateHost, []string{"10.0.0.1"}, listedHosts, false, ""},
		{"listed RFC 1918 172.16/12", privateHost, []string{"172.16.0.1"}, listedHosts, false, ""},
		{"listed RFC 1918 192.168/16", privateHost, []string{"192.168.0.1"}, listedHosts, false, ""},
		{"listed IPv6 ULA", privateHost, []string{"fd00::1"}, listedHosts, false, ""},
		{"listed mixed public and private", privateHost, []string{"93.184.216.34", "10.0.0.1", "fd00::1"}, listedHosts, false, ""},
		{"unlisted private IPv4", "other.internal.example.com", []string{"10.0.0.1"}, listedHosts, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"unlisted IPv6 ULA", "other.internal.example.com", []string{"fd00::1"}, listedHosts, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"unlisted public host", "public.example.com", []string{"93.184.216.34"}, listedHosts, false, ""},
		{"hostname suffix attack", privateHost + ".attacker.example", []string{"10.0.0.1"}, listedHosts, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"subdomain is not listed", "evil." + privateHost, []string{"10.0.0.1"}, listedHosts, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"wildcard does not match", privateHost, []string{"10.0.0.1"}, []string{"*.internal.example.com"}, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"port in entry does not match", privateHost, []string{"10.0.0.1"}, []string{privateHost + ":8443"}, false, RedirectURIErrorCategoryDNSPrivateIP},
		{"listed mixed IPv4 link-local", privateHost, []string{"10.0.0.1", "169.254.169.254"}, listedHosts, false, RedirectURIErrorCategoryDNSLinkLocal},
		{"listed mixed IPv6 link-local", privateHost, []string{"fd00::1", "fe80::1"}, listedHosts, false, RedirectURIErrorCategoryDNSLinkLocal},
		{"literal private IPv4 is not a hostname", "10.0.0.1", nil, []string{"10.0.0.1"}, false, RedirectURIErrorCategoryPrivateIP},
		{"literal IPv6 ULA is not a hostname", "fd00::1", nil, []string{"fd00::1"}, false, RedirectURIErrorCategoryPrivateIP},
		{"global exception overrides list", "other.internal.example.com", []string{"10.0.0.1"}, listedHosts, true, ""},
		{"global exception preserves link-local guard", privateHost, []string{"169.254.169.254"}, listedHosts, true, RedirectURIErrorCategoryDNSLinkLocal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newMockDNSResolver()
			addresses := make([]net.IP, 0, len(test.addresses))
			for _, address := range test.addresses {
				addresses = append(addresses, net.ParseIP(address))
			}
			resolver.setResult(test.hostname, addresses...)
			setup := newTestServerSetup(true)
			server, err := setup.createServer(&Config{
				Issuer:                         testAuthIssuer,
				DNSResolver:                    resolver.resolver(),
				AllowPrivateIPRedirectURIHosts: test.allowedHosts,
				AllowPrivateIPRedirectURIs:     test.allowGlobal,
			})
			require.NoError(t, err)
			t.Cleanup(server.stopMetadataCacheCleanup)
			require.True(t, server.Config.ProductionMode)
			require.True(t, server.Config.DNSValidation)
			require.True(t, server.Config.DNSValidationStrict)
			require.True(t, server.Config.ValidateRedirectURIAtAuthorization)
			require.False(t, server.Config.AllowLinkLocalRedirectURIs)
			redirectURI := "https://" + net.JoinHostPort(test.hostname, "8443") + "/callback"
			for _, stage := range []struct {
				name     string
				validate func(context.Context, string) error
			}{
				{RedirectURIStageRegistration, server.ValidateRedirectURIForRegistration},
				{RedirectURIStageAuthorization, server.ValidateRedirectURIAtAuthorizationTime},
			} {
				t.Run(stage.name, func(t *testing.T) {
					err := stage.validate(t.Context(), redirectURI)
					if test.category == "" {
						require.NoError(t, err)
						return
					}
					require.Error(t, err)
					require.Equal(t, test.category, GetRedirectURIErrorCategory(err))
				})
			}
		})
	}
}

func TestRedirectURIPrivateHostsAuthorizationFlow(t *testing.T) {
	const privateHost = "gateway.internal.example.com"
	resolver := newMockDNSResolver()
	resolver.setResult(privateHost, net.ParseIP("10.0.0.1"))
	setup := newTestServerSetup(true)
	server, err := setup.createServer(&Config{
		Issuer:                         testAuthIssuer,
		DNSResolver:                    resolver.resolver(),
		AllowPrivateIPRedirectURIHosts: []string{privateHost},
	})
	require.NoError(t, err)
	t.Cleanup(server.stopMetadataCacheCleanup)
	registeredURI := "https://" + privateHost + "/callback"
	client, _, err := server.RegisterClient(t.Context(), "private callback", ClientTypePublic, TokenEndpointAuthMethodNone,
		[]string{registeredURI}, []string{"openid"}, "192.0.2.1", 10)
	require.NoError(t, err)
	canonicalURI, err := server.ValidateRedirectURIForAuthorization(t.Context(), client.ClientID, registeredURI)
	require.NoError(t, err)
	authorizationURL, err := server.StartAuthorizationFlow(t.Context(), client.ClientID, canonicalURI, "openid", "",
		strings.Repeat("a", 43), PKCEMethodS256, strings.Repeat("b", 43), nil)
	require.NoError(t, err)
	require.NotEmpty(t, authorizationURL)
	for _, redirectURI := range []string{
		registeredURI + "?extra=1",
		registeredURI + "/other",
		"https://" + privateHost + ":8443/callback",
		"http://" + privateHost + "/callback",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			_, err := server.ValidateRedirectURIForAuthorization(t.Context(), client.ClientID, redirectURI)
			require.Error(t, err)
		})
	}
	resolver.setResult(privateHost, net.ParseIP("169.254.169.254"))
	_, err = server.StartAuthorizationFlow(t.Context(), client.ClientID, canonicalURI, "openid", "",
		strings.Repeat("a", 43), PKCEMethodS256, strings.Repeat("b", 43), nil)
	require.ErrorContains(t, err, "redirect URI failed security validation")
}
