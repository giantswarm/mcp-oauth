package server

import (
	"fmt"
	"maps"
	"slices"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// validateOptions returns the first error an option recorded, then checks
// the trusted issuers against the configuration.
func (s *Server) validateOptions() error {
	if s.initializationError != nil {
		return s.initializationError
	}
	return s.validateTrustedIssuerSettings()
}

// validateTrustedIssuerSettings refuses, once the options are applied, a
// resource server that could accept no token, and under
// RequireResourceAccessTokens an issuer whose tokens could never name this
// server's resource. It warns when the authorization server is off and the
// metadata advertises no authorization server.
func (s *Server) validateTrustedIssuerSettings() error {
	if s.Config.DisableAuthorizationServer && s.trustedIssuerValidator == nil {
		return fmt.Errorf("DisableAuthorizationServer requires WithTrustedIssuers: no token could be accepted")
	}
	if s.Config.RequireResourceAccessTokens && s.trustedIssuerValidator != nil {
		resource := []string{s.Config.GetResourceIdentifier()}
		for _, issuer := range slices.Sorted(maps.Keys(s.trustedIssuerValidator.issuers)) {
			audiences := s.trustedIssuerValidator.issuers[issuer].AllowedAudiences
			if len(audiences) > 0 && helpers.FindMatchingAudience(audiences, resource) == "" {
				return fmt.Errorf("trusted issuer %q: RequireResourceAccessTokens needs AllowedAudiences to name the resource %q", issuer, resource[0])
			}
		}
	}
	if s.Config.DisableAuthorizationServer && !s.advertisesAuthorizationServer() {
		s.Logger.Warn("No authorization server is advertised in the protected resource metadata; MCP requires at least one",
			"recommendation", "list the issuer clients sign in with in ResourceMetadataByPath AuthorizationServers")
	}
	return nil
}

func (s *Server) advertisesAuthorizationServer() bool {
	for _, resource := range s.Config.ResourceMetadataByPath {
		if len(resource.AuthorizationServers) > 0 {
			return true
		}
	}
	return false
}

// IsOpenIDProviderIssuer reports whether issuer is a trusted issuer marked
// as the OpenID Provider people sign in with ([TrustedIssuer.OpenIDProvider]).
func (s *Server) IsOpenIDProviderIssuer(issuer string) bool {
	if s.trustedIssuerValidator == nil {
		return false
	}
	entry, ok := s.trustedIssuerValidator.entry(issuer)
	return ok && entry.OpenIDProvider
}
