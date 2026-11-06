package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestValidateTrustedClients(t *testing.T) {
	ok := TrustedClient{ClientID: "https://claude.ai/oauth/mcp-oauth-client-metadata", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}}

	tests := []struct {
		name    string
		clients []TrustedClient
		wantErr string
	}{
		{name: "metadata document URL", clients: []TrustedClient{ok}},
		{name: "pre-registered client ID", clients: []TrustedClient{{ClientID: "backstage", RedirectURIs: []string{"https://backstage.example.com/cb"}}}},
		{name: "empty client ID", clients: []TrustedClient{{RedirectURIs: ok.RedirectURIs}}, wantErr: "client_id is empty"},
		{name: "duplicate client ID", clients: []TrustedClient{ok, ok}, wantErr: "listed twice"},
		{name: "metadata URL without path", clients: []TrustedClient{{ClientID: "https://claude.ai", RedirectURIs: ok.RedirectURIs}}, wantErr: "with a path"},
		{name: "metadata URL with root path", clients: []TrustedClient{{ClientID: "https://claude.ai/", RedirectURIs: ok.RedirectURIs}}, wantErr: "with a path"},
		{name: "metadata URL with wildcard host", clients: []TrustedClient{{ClientID: "https://*.github.io/x.json", RedirectURIs: ok.RedirectURIs}}, wantErr: "with a path"},
		{name: "metadata URL with query", clients: []TrustedClient{{ClientID: "https://claude.ai/m?x=1", RedirectURIs: ok.RedirectURIs}}, wantErr: "with a path"},
		{name: "no redirect URIs", clients: []TrustedClient{{ClientID: ok.ClientID}}, wantErr: "redirect_uris is empty"},
		{name: "http redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"http://claude.ai/cb"}}}, wantErr: "https"},
		{name: "custom scheme redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"cursor://callback"}}}, wantErr: "https"},
		{name: "localhost redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://localhost:3000/callback"}}}, wantErr: "loopback"},
		{name: "IPv4 loopback redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://127.0.0.2/callback"}}}, wantErr: "loopback"},
		{name: "IPv6 loopback redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://[::1]/callback"}}}, wantErr: "loopback"},
		{name: "unspecified redirect URI", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://0.0.0.0/callback"}}}, wantErr: "loopback"},
		{name: "wildcard redirect host", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://*.claude.ai/cb"}}}, wantErr: "single host"},
		{name: "redirect URI with fragment", clients: []TrustedClient{{ClientID: ok.ClientID, RedirectURIs: []string{"https://claude.ai/cb#x"}}}, wantErr: "fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTrustedClients(tt.clients)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNew_RefusesInvalidConsentConfig(t *testing.T) {
	tests := map[string]*Config{
		"invalid trusted client": {Issuer: "https://auth.example.com", TrustedClients: []TrustedClient{{ClientID: "x"}}},
		"short consent key":      {Issuer: "https://auth.example.com", ConsentCookieKey: []byte("short")},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			store := memory.New()
			t.Cleanup(store.Stop)
			_, err := New(mock.NewProvider(), store, store, store, cfg, nil)
			require.Error(t, err)
		})
	}
}

func TestNew_GeneratesConsentKey(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)
	cfg := &Config{Issuer: "https://auth.example.com"}

	_, err := New(mock.NewProvider(), store, store, store, cfg, nil)

	require.NoError(t, err)
	require.Len(t, cfg.ConsentCookieKey, 32)
}

func TestRequiresConsent(t *testing.T) {
	s := &Server{Config: &Config{TrustedClients: []TrustedClient{{
		ClientID:     "https://claude.ai/oauth/mcp-oauth-client-metadata",
		RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
	}}}}

	require.False(t, s.RequiresConsent("https://claude.ai/oauth/mcp-oauth-client-metadata", "https://claude.ai/api/mcp/auth_callback"))
	require.True(t, s.RequiresConsent("https://claude.ai/oauth/mcp-oauth-client-metadata", "https://attacker.example/cb"), "trust is per redirect URI")
	require.True(t, s.RequiresConsent("https://claude.ai/oauth/other", "https://claude.ai/api/mcp/auth_callback"))
	require.True(t, s.RequiresConsent("random-dcr-id", "https://claude.ai/api/mcp/auth_callback"))
}

func TestAuthorizationRequest_ConsentKey(t *testing.T) {
	base := AuthorizationRequest{ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email", Resource: "https://mcp.example.com"}
	key := base.ConsentKey()

	same := map[string]AuthorizationRequest{
		"loopback port":   {ClientID: "c", RedirectURI: "http://127.0.0.1:50002/cb", Scope: "openid email", Resource: "https://mcp.example.com"},
		"scope order":     {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "email openid", Resource: "https://mcp.example.com"},
		"duplicate scope": {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email openid", Resource: "https://mcp.example.com"},
		"state differs":   {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email", Resource: "https://mcp.example.com", State: "x"},
	}
	for name, req := range same {
		require.Equal(t, key, req.ConsentKey(), name)
	}

	different := map[string]AuthorizationRequest{
		"client":         {ClientID: "d", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email", Resource: "https://mcp.example.com"},
		"redirect path":  {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/other", Scope: "openid email", Resource: "https://mcp.example.com"},
		"broader scopes": {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email groups", Resource: "https://mcp.example.com"},
		"resource":       {ClientID: "c", RedirectURI: "http://127.0.0.1:50001/cb", Scope: "openid email", Resource: "https://other.example.com"},
		"field boundary": {ClientID: "c\x00http://127.0.0.1/cb", RedirectURI: "", Scope: "openid email", Resource: "https://mcp.example.com"},
	}
	for name, req := range different {
		require.NotEqual(t, key, req.ConsentKey(), name)
	}

	https := AuthorizationRequest{ClientID: "c", RedirectURI: "https://example.com:8443/cb"}
	httpsOtherPort := AuthorizationRequest{ClientID: "c", RedirectURI: "https://example.com:9443/cb"}
	require.NotEqual(t, https.ConsentKey(), httpsOtherPort.ConsentKey(), "only loopback ports are ignored")
}

func TestIsPrivateIP_SpecialPurposeRanges(t *testing.T) {
	blocked := []string{
		"0.1.2.3", "100.64.0.1", "100.127.255.255", "192.0.0.8", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::1",
		"2002:7f00:1::", "2001::1", "2001:db8::1", "3fff::1", "fec0::1", "fc00::1", "fe80::1", "ff02::1", "100::1",
	}
	for _, ip := range blocked {
		require.True(t, isPrivateIP(net.ParseIP(ip)), ip)
	}

	public := []string{"8.8.8.8", "1.1.1.1", "100.128.0.1", "2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, ip := range public {
		require.False(t, isPrivateIP(net.ParseIP(ip)), ip)
	}
}

func TestRejectPrivateIPs_SharedAddressSpace(t *testing.T) {
	err := rejectPrivateIPs("cimd.example.com", []net.IPAddr{{IP: net.ParseIP("100.64.0.1")}})

	require.ErrorContains(t, err, "100.64.0.1")
}
