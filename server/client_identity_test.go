package server

import (
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

func TestValidatedClientIdentityFromIDToken(t *testing.T) {
	for _, test := range []struct {
		name   string
		claims oidc.IDTokenClaims
		want   string
	}{
		{"single audience", oidc.IDTokenClaims{Claims: jwt.Claims{Audience: jwt.Audience{"portal"}}}, "portal"},
		{"authorized party", oidc.IDTokenClaims{Claims: jwt.Claims{Audience: jwt.Audience{"kubernetes", "portal"}}, AuthorizedParty: "portal"}, "portal"},
		{"ambiguous", oidc.IDTokenClaims{Claims: jwt.Claims{Audience: jwt.Audience{"portal", "other"}}}, ""},
		{"absent", oidc.IDTokenClaims{}, ""},
		{"unrelated access claim", oidc.IDTokenClaims{ClientID: "untrusted-as-id-client"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, (&Server{}).idTokenClaimsToUserInfo(&test.claims).ClientID)
		})
	}
}

func TestValidatedJWTClientIdentity(t *testing.T) {
	for _, test := range []struct {
		name  string
		claim any
		valid bool
	}{
		{"valid", "client", true}, {"empty", "", false}, {"numeric", 12, false}, {"array", []string{"client"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info, err := userInfoFromJWTClaims(map[string]any{"iss": "https://issuer.example.test", "sub": "subject", "client_id": test.claim})
			if !test.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "client", info.ClientID)
		})
	}
	info, err := userInfoFromJWTClaims(map[string]any{"iss": "https://issuer.example.test", "sub": "subject"})
	require.NoError(t, err)
	require.Empty(t, info.ClientID)
}
