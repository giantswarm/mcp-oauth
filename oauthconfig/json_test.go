package oauthconfig_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
)

func TestFromEnvJSONRequiresSingleValue(t *testing.T) {
	for _, variable := range []string{"OAUTH_TRUSTED_ISSUERS", "OAUTH_ADDITIONAL_RESOURCES", "OAUTH_TRUSTED_CLIENTS"} {
		for _, suffix := range []string{" []", " trailing", " {"} {
			t.Run(variable+suffix, func(t *testing.T) {
				resourceEnv(t)
				t.Setenv("OAUTH_TRUSTED_CLIENTS", "")
				t.Setenv(variable, "[]"+suffix)
				if variable == "OAUTH_TRUSTED_ISSUERS" {
					_, err := oauthconfig.TrustedIssuersFromEnv()
					require.Error(t, err)
					return
				}
				_, err := oauthconfig.FromEnv()
				require.Error(t, err)
			})
		}
	}
}

func TestTrustedIssuersFromEnvEmptyList(t *testing.T) {
	for _, value := range []string{"[]", "[] \n\t", "null"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("OAUTH_TRUSTED_ISSUERS", value)
			issuers, err := oauthconfig.TrustedIssuersFromEnv()
			require.NoError(t, err)
			require.Nil(t, issuers)
		})
	}
}
