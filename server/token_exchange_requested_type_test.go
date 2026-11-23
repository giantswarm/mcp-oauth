package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
)

func TestBrokeredExchangeRequestedTokenType(t *testing.T) {
	for _, test := range []struct {
		name, requested, issued string
		mismatch                bool
	}{
		{name: "host chooses ID token", issued: SubjectTokenTypeIDToken},
		{name: "explicit access token", requested: SubjectTokenTypeAccessToken, issued: SubjectTokenTypeAccessToken},
		{name: "default access token", requested: SubjectTokenTypeAccessToken},
		{name: "explicit ID token", requested: SubjectTokenTypeIDToken, issued: SubjectTokenTypeIDToken},
		{name: "wrong type", requested: SubjectTokenTypeAccessToken, issued: SubjectTokenTypeIDToken, mismatch: true},
		{name: "default does not match", requested: SubjectTokenTypeIDToken, mismatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchanger := &stubExchanger{result: &ExchangerResult{
				AccessToken: "downstream-token", IssuedTokenType: test.issued, ExpiresAt: time.Now().Add(time.Minute),
			}}
			service, logs := newBrokerTestServer(t, exchanger,
				map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())
			result, err := service.BrokeredExchange(t.Context(), BrokeredExchangeRequest{
				SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "subject-jwt", Type: SubjectTokenTypeIDToken}},
				ClientID:        "backstage", Audience: "gaggle", RequestedTokenType: test.requested,
			})
			require.NotNil(t, exchanger.gotReq)
			require.Equal(t, test.requested, exchanger.gotReq.RequestedTokenType)
			if test.mismatch {
				require.ErrorIs(t, err, ErrIssuedTokenTypeMismatch)
				require.Nil(t, result)
				require.NotContains(t, logs.String(), security.EventTokenIssued)
				details := auditDetails(t, logs, security.EventAuthFailure)
				require.Equal(t, "token_exchange_issued_type_mismatch", details["reason"])
				require.Equal(t, "warning", details["severity"])
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, result.AccessToken)
			}
		})
	}
}
