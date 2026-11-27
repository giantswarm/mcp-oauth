package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNew_IDTokenBearerDeprecations(t *testing.T) {
	tests := []struct {
		name                        string
		trustedAudiences            []string
		requireResourceAccessTokens bool
		options                     []Option
		warnings                    []string
	}{
		{
			name:             "configured trusted audiences",
			trustedAudiences: []string{"legacy-client"},
			warnings:         []string{"DEPRECATED: TrustedAudiences"},
		},
		{
			name:     "trusted audiences supplied as an option",
			options:  []Option{WithTrustedAudiences([]string{"legacy-client"})},
			warnings: []string{"DEPRECATED: TrustedAudiences"},
		},
		{
			name:                        "resource access tokens disable forwarded bearer acceptance",
			trustedAudiences:            []string{"legacy-client"},
			requireResourceAccessTokens: true,
		},
		{
			name:             "invalid trusted audiences are removed",
			trustedAudiences: []string{"", " "},
		},
		{
			name: "no forwarded bearer configuration",
		},
		{
			name: "OpenID provider issuer",
			options: []Option{WithTrustedIssuers([]TrustedIssuer{{
				Issuer:             "https://idp.example.com",
				JwksURL:            "https://idp.example.com/keys",
				AllowedAudiences:   []string{"legacy-client"},
				AcceptedTypHeaders: []string{"JWT"},
				OpenIDProvider:     true,
			}})},
			warnings: []string{"DEPRECATED: TrustedIssuer.OpenIDProvider"},
		},
		{
			name: "issuer accepts a missing typ",
			options: []Option{WithTrustedIssuers([]TrustedIssuer{{
				Issuer:             "https://idp.example.com",
				JwksURL:            "https://idp.example.com/keys",
				AllowedAudiences:   []string{"legacy-client"},
				AcceptedTypHeaders: []string{"at+jwt", ""},
			}})},
			warnings: []string{"DEPRECATED: TrustedIssuer.AcceptedTypHeaders"},
		},
		{
			name: "issuer accepts access tokens by default",
			options: []Option{WithTrustedIssuers([]TrustedIssuer{{
				Issuer:           "https://idp.example.com",
				JwksURL:          "https://idp.example.com/keys",
				AllowedAudiences: []string{"https://auth.example.com/mcp"},
			}})},
		},
		{
			name: "issuer explicitly accepts access tokens",
			options: []Option{WithTrustedIssuers([]TrustedIssuer{{
				Issuer:             "https://idp.example.com",
				JwksURL:            "https://idp.example.com/keys",
				AllowedAudiences:   []string{"https://auth.example.com/mcp"},
				AcceptedTypHeaders: []string{"at+jwt"},
			}})},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger, logs := captureLogger()
			store := memory.New()
			configuration := &Config{
				Issuer:                      "https://auth.example.com",
				ResourceIdentifier:          "https://auth.example.com/mcp",
				TrustedAudiences:            test.trustedAudiences,
				RequireResourceAccessTokens: test.requireResourceAccessTokens,
			}
			server, err := NewWithCombined(mock.NewProvider(), store, configuration, logger, test.options...)
			if err != nil {
				store.Stop()
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, server.Shutdown(context.WithoutCancel(t.Context()))) })
			for _, warning := range test.warnings {
				require.Contains(t, logs.String(), warning)
			}
			if len(test.warnings) == 0 {
				require.NotContains(t, logs.String(), "DEPRECATED:")
			}
			require.Equal(t, test.requireResourceAccessTokens, server.Config.RequireResourceAccessTokens)
		})
	}
}
