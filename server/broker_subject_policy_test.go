package server

import (
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

func TestBrokeredExchangeClientSubjectPolicy(t *testing.T) {
	const identityIssuer = "https://identity.example.com"
	for _, test := range []struct {
		name      string
		issuer    string
		audiences []string
		client    string
		claims    bool
		invalid   bool
		allowed   bool
	}{
		{name: "intended recipient", issuer: identityIssuer, audiences: []string{"agent-manager"}, claims: true, allowed: true},
		{name: "multiple audiences", issuer: identityIssuer, audiences: []string{"other", "agent-manager"}, claims: true, allowed: true},
		{name: "another recipient", issuer: identityIssuer, audiences: []string{"model-manager"}, claims: true},
		{name: "another issuer same subject", issuer: "https://other.example.com", audiences: []string{"agent-manager"}, claims: true},
		{name: "missing audiences", issuer: identityIssuer, claims: true},
		{name: "missing verified claims", issuer: identityIssuer},
		{name: "issuer audience pairs", issuer: "https://second.example.com", audiences: []string{"agent-manager"}, claims: true},
		{name: "second issuer intended recipient", issuer: "https://second.example.com", audiences: []string{"second-manager"}, claims: true, allowed: true},
		{name: "unconfigured client", issuer: identityIssuer, audiences: []string{"model-manager"}, client: "legacy", claims: true, allowed: true},
		{name: "invalid token", issuer: identityIssuer, audiences: []string{"agent-manager"}, claims: true, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := SubjectIdentity{Subject: "same-person", Issuer: test.issuer}
			if test.claims {
				identity.Claims = &oidc.IDTokenClaims{Claims: jwt.Claims{Issuer: test.issuer, Subject: "raw-subject", Audience: jwt.Audience(test.audiences)}}
			}
			validator := &stubSubjectValidator{identity: identity}
			if test.invalid {
				validator.err = errors.New("invalid signature")
			}
			exchanger := &stubExchanger{result: &ExchangerResult{AccessToken: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour)}}
			server, logs := newBrokerTestServer(t, exchanger, map[string][]string{"manager": {"github"}, "legacy": {"github"}}, validator)
			server.Config.TokenExchangeClientSubjectPolicies = map[string][]BrokerSubjectPolicy{"manager": {
				{Issuer: identityIssuer, Audiences: []string{"agent-manager"}},
				{Issuer: "https://second.example.com", Audiences: []string{"second-manager"}},
			}}
			client := test.client
			if client == "" {
				client = "manager"
			}
			result, err := server.BrokeredExchange(t.Context(), BrokeredExchangeRequest{
				SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "synthetic-subject-token", Type: SubjectTokenTypeIDToken}},
				ClientID:        client, Audience: "github",
			})
			if test.allowed {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.NotNil(t, exchanger.gotReq)
				return
			}
			require.Error(t, err)
			require.Nil(t, result)
			require.Nil(t, exchanger.gotReq)
			if !test.invalid {
				require.Contains(t, logs.String(), "token_exchange_subject_not_allowed")
			}
			require.NotContains(t, logs.String(), "synthetic-subject-token")
		})
	}
}

func TestConfigBrokerSubjectPolicies(t *testing.T) {
	for _, test := range []struct {
		name     string
		policies map[string][]BrokerSubjectPolicy
		valid    bool
	}{
		{name: "unset", valid: true},
		{name: "valid", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}, valid: true},
		{name: "no output allowlist", policies: map[string][]BrokerSubjectPolicy{"other": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}},
		{name: "empty policies", policies: map[string][]BrokerSubjectPolicy{"manager": {}}},
		{name: "missing issuer", policies: map[string][]BrokerSubjectPolicy{"manager": {{Audiences: []string{"agent-manager"}}}}},
		{name: "missing audiences", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com"}}}},
		{name: "blank audience", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com", Audiences: []string{" "}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := &Config{Issuer: "https://broker.example.com", TokenExchangeClientAudiences: map[string][]string{"manager": {"github"}}, TokenExchangeClientSubjectPolicies: test.policies}
			err := configuration.Validate()
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
