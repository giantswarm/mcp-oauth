package server

import (
	"maps"
	"slices"
)

func (s *Server) logIDTokenBearerDeprecations() {
	if len(s.Config.TrustedAudiences) > 0 && !s.Config.RequireResourceAccessTokens {
		s.Logger.Warn("DEPRECATED: TrustedAudiences accepts upstream ID tokens as bearers; migrate callers to per-resource access tokens and set RequireResourceAccessTokens before mcp-oauth 2.0.0")
	}
	if s.trustedIssuerValidator == nil {
		return
	}
	for _, issuer := range slices.Sorted(maps.Keys(s.trustedIssuerValidator.issuers)) {
		configuration := s.trustedIssuerValidator.issuers[issuer]
		if configuration.OpenIDProvider {
			s.Logger.Warn("DEPRECATED: TrustedIssuer.OpenIDProvider accepts ID tokens as bearers; migrate callers to per-resource access tokens before disabling OpenIDProvider in mcp-oauth 2.0.0", "issuer", issuer)
		}
		if slices.Contains(configuration.AcceptedTypHeaders, "") {
			s.Logger.Warn("DEPRECATED: TrustedIssuer.AcceptedTypHeaders accepts a missing typ; migrate callers to access tokens with typ at+jwt before mcp-oauth 2.0.0", "issuer", issuer)
		}
	}
}
