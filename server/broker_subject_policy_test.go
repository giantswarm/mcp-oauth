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
		name       string
		issuer     string
		audiences  []string
		client     string
		claims     bool
		invalid    bool
		allowed    bool
		noPolicies bool
	}{
		{name: "intended recipient", issuer: identityIssuer, audiences: []string{"agent-manager"}, claims: true, allowed: true},
		{name: "multiple audiences", issuer: identityIssuer, audiences: []string{"other", "agent-manager"}, claims: true, allowed: true},
		{name: "another recipient", issuer: identityIssuer, audiences: []string{"model-manager"}, claims: true},
		{name: "another issuer same subject", issuer: "https://other.example.com", audiences: []string{"agent-manager"}, claims: true},
		{name: "missing audiences", issuer: identityIssuer, claims: true},
		{name: "missing verified claims", issuer: identityIssuer},
		{name: "issuer audience pairs", issuer: "https://second.example.com", audiences: []string{"agent-manager"}, claims: true},
		{name: "second issuer intended recipient", issuer: "https://second.example.com", audiences: []string{"second-manager"}, claims: true, allowed: true},
		{name: "unconfigured client", issuer: identityIssuer, audiences: []string{"agent-manager"}, client: "legacy", claims: true},
		{name: "missing policy map", issuer: identityIssuer, audiences: []string{"agent-manager"}, claims: true, noPolicies: true},
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
			if test.noPolicies {
				server.Config.TokenExchangeClientSubjectPolicies = nil
			}
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
				require.ErrorIs(t, err, ErrBrokerSubjectNotAllowed)
				require.Contains(t, logs.String(), "token_exchange_subject_not_allowed")
			}
			require.NotContains(t, logs.String(), "synthetic-subject-token")
		})
	}
}

func TestConfigBrokerSubjectPolicies(t *testing.T) {
	for _, test := range []struct {
		name      string
		audiences map[string][]string
		policies  map[string][]BrokerSubjectPolicy
		valid     bool
	}{
		{name: "broker unconfigured", valid: true},
		{name: "missing policies", audiences: map[string][]string{"manager": {"github"}}},
		{name: "disabled client", audiences: map[string][]string{"manager": {}}, valid: true},
		{name: "partial policies", audiences: map[string][]string{"manager": {"github"}, "other": {"github"}}, policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}},
		{name: "valid", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}, valid: true},
		{name: "no output allowlist", policies: map[string][]BrokerSubjectPolicy{"other": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}},
		{name: "empty policies", policies: map[string][]BrokerSubjectPolicy{"manager": {}}},
		{name: "missing issuer", policies: map[string][]BrokerSubjectPolicy{"manager": {{Audiences: []string{"agent-manager"}}}}},
		{name: "missing audiences", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com"}}}},
		{name: "blank audience", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: "https://identity.example.com", Audiences: []string{" "}}}}},
		{name: "blank issuer", policies: map[string][]BrokerSubjectPolicy{"manager": {{Issuer: " ", Audiences: []string{"agent-manager"}}}}},
		{name: "blank client", audiences: map[string][]string{" ": {"github"}}, policies: map[string][]BrokerSubjectPolicy{" ": {{Issuer: "https://identity.example.com", Audiences: []string{"agent-manager"}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			audiences := test.audiences
			if audiences == nil && test.policies != nil {
				audiences = map[string][]string{"manager": {"github"}}
			}
			configuration := &Config{Issuer: "https://broker.example.com", TokenExchangeClientAudiences: audiences, TokenExchangeClientSubjectPolicies: test.policies}
			err := configuration.Validate()
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestBrokeredExchangeClientSubjectPolicyVerifiedJWT(t *testing.T) {
	const issuer = "https://dex.example.com"
	const keyID = "broker-subject-key"
	key := newTestECKey(t)
	jwksURL, jwksClient := serveStaticJWKS(t, key, keyID)
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer: issuer, JwksURL: jwksURL,
		AllowedAudiences: []string{"broker-client", "another-client"},
	}}, jwksClient)
	require.NoError(t, err)

	for _, audience := range []string{"broker-client", "another-client"} {
		t.Run(audience, func(t *testing.T) {
			subject := signSubjectToken(t, key, keyID, jwt.Claims{
				Issuer: issuer, Subject: brokerTestUserSub, Audience: jwt.Audience{audience},
				Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})
			exchanger := &stubExchanger{result: &ExchangerResult{
				AccessToken: "downstream-token", ExpiresAt: time.Now().Add(time.Hour),
			}}
			broker, logs := newBrokerTestServer(t, exchanger, map[string][]string{"manager": {"github"}}, validator)
			result, err := broker.BrokeredExchange(t.Context(), BrokeredExchangeRequest{
				SubjectExchange: SubjectExchange{Subject: TypedToken{Token: subject, Type: SubjectTokenTypeIDToken}},
				ClientID:        "manager", Audience: "github",
			})
			if audience == "broker-client" {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.Equal(t, issuer, exchanger.gotReq.Subject.Issuer)
			} else {
				require.ErrorIs(t, err, ErrBrokerSubjectNotAllowed)
				require.Nil(t, result)
				require.Nil(t, exchanger.gotReq)
			}
			require.NotContains(t, logs.String(), subject)
		})
	}
}
