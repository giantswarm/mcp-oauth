package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestNewRejectsInvalidTrustedIssuers(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		issuer TrustedIssuer
	}{
		{"missing issuer", TrustedIssuer{JwksURL: "https://issuer.example.com/keys"}},
		{"missing JWKS", TrustedIssuer{Issuer: "https://issuer.example.com"}},
		{"invalid actor policy", TrustedIssuer{
			Issuer: "https://issuer.example.com", JwksURL: "https://issuer.example.com/keys",
			Actors: &ActorPolicy{Subjects: map[string]string{"https://actor.example.com": "*"}},
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := memory.New()
			t.Cleanup(store.Stop)
			configuration := &Config{Issuer: "https://mcp.example.com", EnableClientIDMetadataDocuments: true}
			instance, err := NewWithCombined(mock.NewProvider(), store, configuration, nil, WithTrustedIssuers([]TrustedIssuer{testCase.issuer}))
			require.ErrorContains(t, err, "trusted issuers")
			require.Nil(t, instance)
		})
	}
}

func TestNewAcceptsOptionalTrustedIssuers(t *testing.T) {
	for _, issuers := range [][]TrustedIssuer{
		nil,
		{},
		{{Issuer: "https://issuer.example.com", JwksURL: "https://issuer.example.com/keys"}},
	} {
		store := memory.New()
		t.Cleanup(store.Stop)
		configuration := &Config{Issuer: "https://mcp.example.com"}
		instance, err := NewWithCombined(mock.NewProvider(), store, configuration, nil, WithTrustedIssuers(issuers))
		require.NoError(t, err)
		require.Equal(t, len(issuers) > 0, instance.trustedIssuerValidator != nil)
		if len(issuers) > 0 {
			for _, tokenType := range []string{SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT} {
				require.Same(t, instance.trustedIssuerValidator, instance.SubjectValidatorFor(tokenType))
			}
		}
	}
}
