package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
)

func TestBrokeredExchangeTokenUsage(t *testing.T) {
	for _, test := range []struct {
		name, issued, usage, expected string
	}{
		{name: "implicit access token", expected: "Bearer"},
		{name: "explicit access token", issued: SubjectTokenTypeAccessToken, usage: "bEaReR", expected: "Bearer"},
		{name: "access token requires usage", issued: SubjectTokenTypeAccessToken, usage: "N_A"},
		{name: "ID token default", issued: SubjectTokenTypeIDToken, expected: "N_A"},
		{name: "ID token explicit", issued: SubjectTokenTypeIDToken, usage: "n_a", expected: "N_A"},
		{name: "ID token bearer rejected", issued: SubjectTokenTypeIDToken, usage: "Bearer"},
		{name: "JWT access token", issued: SubjectTokenTypeJWT, usage: "Bearer", expected: "Bearer"},
		{name: "JWT assertion", issued: SubjectTokenTypeJWT, usage: "N_A", expected: "N_A"},
		{name: "JWT requires explicit usage", issued: SubjectTokenTypeJWT},
		{name: "unsupported binding", usage: "DPoP"},
		{name: "unknown usage", usage: "unknown"},
		{name: "custom assertion", issued: "urn:example:assertion", usage: "N_A", expected: "N_A"},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchanger := &stubExchanger{result: &ExchangerResult{
				AccessToken: "downstream-token", IssuedTokenType: test.issued, TokenType: test.usage,
				ExpiresAt: time.Now().Add(time.Minute),
			}}
			service, logs := newBrokerTestServer(t, exchanger,
				map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())
			result, err := service.BrokeredExchange(t.Context(), BrokeredExchangeRequest{
				SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "subject-jwt", Type: SubjectTokenTypeIDToken}},
				ClientID:        "backstage", Audience: "gaggle",
			})
			if test.expected == "" {
				require.ErrorIs(t, err, ErrInvalidExchangerResult)
				require.Nil(t, result)
				require.NotContains(t, logs.String(), security.EventTokenIssued)
				details := auditDetails(t, logs, security.EventAuthFailure)
				require.Equal(t, "token_exchange_invalid_result", details["reason"])
				require.Equal(t, "warning", details["severity"])
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result.TokenType)
		})
	}
}
