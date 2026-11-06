package server

import (
	"fmt"
	"slices"
	"strings"
)

// BrokerSubjectPolicy binds an identity issuer and its accepted subject-token
// audiences to a confidential broker client. Global token validation still applies.
type BrokerSubjectPolicy struct {
	Issuer    string
	Audiences []string
}

func (p BrokerSubjectPolicy) valid() bool {
	return strings.TrimSpace(p.Issuer) != "" && len(p.Audiences) > 0 && !slices.ContainsFunc(p.Audiences, func(audience string) bool {
		return strings.TrimSpace(audience) == ""
	})
}

func (c *Config) validateBrokerSubjectPolicies() error {
	for clientID, policies := range c.TokenExchangeClientSubjectPolicies {
		if strings.TrimSpace(clientID) == "" || len(c.TokenExchangeClientAudiences[clientID]) == 0 {
			return fmt.Errorf("TokenExchangeClientSubjectPolicies: client %q needs an output audience allowlist", clientID)
		}
		if len(policies) == 0 {
			return fmt.Errorf("TokenExchangeClientSubjectPolicies: client %q needs a subject policy", clientID)
		}
		for _, policy := range policies {
			if !policy.valid() {
				return fmt.Errorf("TokenExchangeClientSubjectPolicies: client %q needs an issuer and subject audiences", clientID)
			}
		}
	}
	return nil
}

func (s *Server) brokerSubjectAllowed(clientID string, identity *SubjectIdentity) bool {
	policies, restricted := s.Config.TokenExchangeClientSubjectPolicies[clientID]
	if !restricted {
		return true
	}
	if identity == nil || identity.Claims == nil {
		return false
	}
	for _, policy := range policies {
		if policy.Issuer != identity.Issuer {
			continue
		}
		for _, audience := range identity.Claims.Audience {
			if audience != "" && slices.Contains(policy.Audiences, audience) {
				return true
			}
		}
	}
	return false
}
