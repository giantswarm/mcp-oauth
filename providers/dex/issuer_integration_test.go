package dex

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

func TestConfiguredIssuerDiscovery(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		trustCA  bool
		mismatch bool
		error    string
	}{
		{name: "loopback IP with trusted CA", trustCA: true},
		{name: "untrusted CA", error: "certificate signed by unknown authority"},
		{name: "mismatched issuer", trustCA: true, mismatch: true, error: "does not match"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				assert.Equal(t, "/dex/.well-known/openid-configuration", request.URL.Path)
				issuer := "https://" + request.Host + "/dex"
				if testCase.mismatch {
					issuer += "/other"
				}
				writer.Header().Set("Content-Type", "application/json")
				assert.NoError(t, json.NewEncoder(writer).Encode(oidc.DiscoveryDocument{
					Issuer: issuer, AuthorizationEndpoint: "https://" + request.Host + "/auth",
					TokenEndpoint: "https://" + request.Host + "/token", JWKSUri: "https://" + request.Host + "/keys",
				}))
			}))
			t.Cleanup(server.Close)
			configuration := &Config{
				IssuerURL: server.URL + "/dex", ClientID: "client", ClientSecret: "fixture",
				DiscoveryTimeout: time.Second,
			}
			if testCase.trustCA {
				configuration.RootCAs = x509.NewCertPool()
				configuration.RootCAs.AddCert(server.Certificate())
			}
			provider, err := NewProvider(configuration)
			if testCase.error != "" {
				require.ErrorContains(t, err, testCase.error)
				return
			}
			require.NoError(t, err)
			require.EqualValues(t, 1, requests.Load())
			require.Equal(t, server.URL+"/auth", provider.Endpoint.AuthURL)
		})
	}
}

func TestConfiguredIssuerSyntaxBeforeDiscovery(t *testing.T) {
	for suffix, refusal := range map[string]string{
		"?tenant=one": "query component", "?": "query component",
		"#fragment": "fragment component", "#": "fragment component",
	} {
		t.Run(suffix, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			t.Cleanup(server.Close)
			_, err := NewProvider(&Config{
				IssuerURL: server.URL + "/dex" + suffix, ClientID: "client", ClientSecret: "fixture",
				HTTPClient: server.Client(), DiscoveryTimeout: time.Second,
			})
			require.ErrorContains(t, err, refusal)
			require.Zero(t, requests.Load())
		})
	}
}
