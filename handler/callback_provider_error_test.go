package handler

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
)

func TestCallback_ProviderErrorRedirectsToClient(t *testing.T) {
	tests := []struct {
		upstream string
		want     string
	}{
		{upstream: constants.ErrorCodeAccessDenied, want: constants.ErrorCodeAccessDenied},
		{upstream: constants.ErrorCodeTemporarilyUnavailable, want: constants.ErrorCodeTemporarilyUnavailable},
		{upstream: constants.ErrorCodeLoginRequired, want: constants.ErrorCodeLoginRequired},
		{upstream: constants.ErrorCodeInvalidScope, want: constants.ErrorCodeServerError},
		{upstream: "<script>", want: constants.ErrorCodeServerError},
	}
	for _, tt := range tests {
		t.Run(tt.upstream, func(t *testing.T) {
			provider := mock.NewProvider()
			flow := newConsentFlowWithProvider(t, provider, nil)
			clientState := testutil.GenerateRandomString(43)
			page := flow.get(flow.authorizeTarget(consentTestRedirect, clientState, nil))
			approved := flow.post(consentID(t, page), consentDecisionApprove, nil)
			requireProviderRedirect(t, approved)
			upstream, err := url.Parse(approved.Header().Get("Location"))
			require.NoError(t, err)

			callback := url.Values{
				"state":             {upstream.Query().Get("state")},
				"error":             {tt.upstream},
				"error_description": {"upstream text that must not reach the client"},
			}
			response := flow.get("/oauth/callback?" + callback.Encode())

			require.Equal(t, http.StatusFound, response.Code)
			location, err := url.Parse(response.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, consentTestRedirect, location.Scheme+"://"+location.Host+location.Path)
			query := location.Query()
			require.Equal(t, tt.want, query.Get("error"))
			require.Equal(t, clientState, query.Get("state"))
			require.Equal(t, flow.h.server.Config.Issuer, query.Get("iss"))
			require.NotContains(t, query.Get("error_description"), "upstream text")
			require.Zero(t, provider.CallCounts["ExchangeCode"])
		})
	}
}
