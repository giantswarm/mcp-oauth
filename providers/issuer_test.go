package providers_test

import (
	"context"
	"testing"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

// jwksProviderStub satisfies both Provider and JWKSProvider, with a fixed
// issuer URL used to assert IssuerOf's happy path.
type jwksProviderStub struct {
	issuer string
}

func (p *jwksProviderStub) Name() string            { return "stub-jwks" }
func (p *jwksProviderStub) DefaultScopes() []string { return nil }
func (p *jwksProviderStub) AuthorizationURL(string, string, string, []string, *providers.AuthorizationURLOptions) string {
	return ""
}
func (p *jwksProviderStub) ExchangeCode(context.Context, string, string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *jwksProviderStub) ValidateToken(context.Context, string) (*providers.UserInfo, error) {
	return nil, nil
}
func (p *jwksProviderStub) RefreshToken(context.Context, string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *jwksProviderStub) RevokeToken(context.Context, string) error { return nil }
func (p *jwksProviderStub) HealthCheck(context.Context) error         { return nil }
func (p *jwksProviderStub) JWKSURI(context.Context) (string, error)   { return "https://jwks.example/keys", nil }
func (p *jwksProviderStub) IssuerURL() string                         { return p.issuer }

// oauthOnlyStub is a Provider that deliberately does NOT implement
// JWKSProvider — the case IssuerOf must return "" for (e.g. the in-tree
// GitHub provider, which is OAuth 2.0 only).
type oauthOnlyStub struct{}

func (p *oauthOnlyStub) Name() string            { return "stub-oauth-only" }
func (p *oauthOnlyStub) DefaultScopes() []string { return nil }
func (p *oauthOnlyStub) AuthorizationURL(string, string, string, []string, *providers.AuthorizationURLOptions) string {
	return ""
}
func (p *oauthOnlyStub) ExchangeCode(context.Context, string, string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *oauthOnlyStub) ValidateToken(context.Context, string) (*providers.UserInfo, error) {
	return nil, nil
}
func (p *oauthOnlyStub) RefreshToken(context.Context, string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *oauthOnlyStub) RevokeToken(context.Context, string) error { return nil }
func (p *oauthOnlyStub) HealthCheck(context.Context) error         { return nil }

func TestIssuerOf(t *testing.T) {
	cases := []struct {
		name string
		p    providers.Provider
		want string
	}{
		{"nil provider", nil, ""},
		{"jwks-capable", &jwksProviderStub{issuer: "https://auth.example"}, "https://auth.example"},
		{"jwks-capable-empty-issuer", &jwksProviderStub{issuer: ""}, ""},
		{"oauth-only", &oauthOnlyStub{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := providers.IssuerOf(tc.p); got != tc.want {
				t.Errorf("IssuerOf = %q, want %q", got, tc.want)
			}
		})
	}
}
