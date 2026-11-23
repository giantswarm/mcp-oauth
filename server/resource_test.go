package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseResourceURI(t *testing.T) {
	for _, test := range []struct {
		name, resource string
		valid          bool
	}{
		{name: "HTTPS", resource: "https://api.example.com", valid: true},
		{name: "URN", resource: "urn:example:resource", valid: true},
		{name: "query", resource: "https://api.example.com/?value=%23fragment", valid: true},
		{name: "IPv6", resource: "https://[2001:db8::1]:443/path", valid: true},
		{name: "encoded brackets", resource: "https://api.example.com/%5Bvalue%5D", valid: true},
		{name: "opaque escaping", resource: "urn:example:some%20value", valid: true},
		{name: "relative", resource: "/relative"},
		{name: "fragment", resource: "https://api.example.com/#fragment"},
		{name: "empty fragment", resource: "https://api.example.com/#"},
		{name: "invalid escaping", resource: "https://api.example.com/%zz"},
		{name: "space in path", resource: "https://api.example.com/a b"},
		{name: "space in opaque URI", resource: "urn:example:bad value"},
		{name: "invalid query escaping", resource: "https://api.example.com/?q=%zz"},
		{name: "short query escaping", resource: "https://api.example.com/?q=%2"},
		{name: "invalid opaque escaping", resource: "urn:example:%zz"},
		{name: "raw path brackets", resource: "https://api.example.com/[value]"},
		{name: "raw query brackets", resource: "https://api.example.com/?q=[value]"},
		{name: "non-ASCII path", resource: "https://api.example.com/café"},
		{name: "too long", resource: "urn:" + strings.Repeat("a", MaxResourceLength)},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parseResourceURI(test.resource)
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, test.resource, parsed.String())
			} else {
				require.Error(t, err)
				require.Nil(t, parsed)
			}
		})
	}
}

func TestResourcesMatch(t *testing.T) {
	for _, test := range []struct {
		name, left, right string
		match             bool
	}{
		{name: "HTTP normalization", left: "HTTPS://API.example.com:443/path/", right: "https://api.example.com/path", match: true},
		{name: "IPv6 normalization", left: "http://[2001:DB8::1]:80/", right: "http://[2001:db8::1]", match: true},
		{name: "same opaque URI", left: "urn:example:allowed", right: "urn:example:allowed", match: true},
		{name: "different opaque URIs", left: "urn:example:allowed", right: "urn:example:forbidden"},
		{name: "escaped separator", left: "https://api.example.com/a%2Fb", right: "https://api.example.com/a/b"},
		{name: "escaped trailing separator", left: "https://api.example.com/path%2F", right: "https://api.example.com/path"},
		{name: "userinfo", left: "https://user@api.example.com", right: "https://api.example.com"},
		{name: "empty query", left: "https://api.example.com?", right: "https://api.example.com"},
		{name: "malformed left", left: "urn:bad value", right: "urn:example:value"},
		{name: "malformed right", left: "urn:example:value", right: "urn:bad value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.match, resourcesMatch(test.left, test.right))
		})
	}
}

func TestExchangeResourceSyntax(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			exchanger := &stubExchanger{result: &ExchangerResult{AccessToken: "downstream-token"}}
			var exchange func(string) (*TokenExchangeResult, error)
			if flow == "brokered" {
				service, _ := newBrokerTestServer(t, exchanger,
					map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())
				exchange = func(resource string) (*TokenExchangeResult, error) {
					return service.BrokeredExchange(t.Context(), BrokeredExchangeRequest{
						SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "subject-jwt", Type: SubjectTokenTypeIDToken}, Resource: resource},
						ClientID:        "backstage", Audience: "gaggle",
					})
				}
			} else {
				service, _ := newActorExchangeServer(t)
				clientID := registerExchangeClient(t, service)
				exchange = func(resource string) (*TokenExchangeResult, error) {
					return service.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
						SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken}, Resource: resource},
						ClientID:        clientID,
					})
				}
			}
			for _, resource := range []string{"relative", "https://api.example.com/#fragment", "https://api.example.com/#"} {
				result, err := exchange(resource)
				require.ErrorIs(t, err, ErrInvalidTarget)
				require.Nil(t, result)
				require.Nil(t, exchanger.gotReq)
			}
			result, err := exchange("urn:example:resource")
			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}
