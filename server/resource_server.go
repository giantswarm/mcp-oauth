package server

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"slices"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// ErrAuthorizationServerDisabled is returned by the authorization server
// flows (authorization, provider callback, code exchange, refresh,
// revocation, identity flow, forwarded ID tokens) when
// Config.DisableAuthorizationServer is true.
var ErrAuthorizationServerDisabled = errors.New("the authorization server is turned off (Config.DisableAuthorizationServer)")

// requireAuthorizationServer refuses an authorization server flow on a
// resource server, which has no provider to call and no grant to issue.
func (s *Server) requireAuthorizationServer() error {
	if s.Config.DisableAuthorizationServer {
		return ErrAuthorizationServerDisabled
	}
	return nil
}

// validateOptions returns the first error an option recorded, then checks
// the trusted issuers against the configuration.
func (s *Server) validateOptions() error {
	if s.initializationError != nil {
		return s.initializationError
	}
	return s.validateTrustedIssuerSettings()
}

// validateTrustedIssuerSettings refuses, once the options are applied, a
// resource server that could accept no token. With the authorization server
// off and RequireResourceAccessTokens set, it also refuses an issuer whose
// tokens could never name this server's resource: the issuer list then only
// admits bearers. With the authorization server on the same list also
// validates RFC 8693 subject tokens, whose audience is not this resource.
func (s *Server) validateTrustedIssuerSettings() error {
	if !s.Config.DisableAuthorizationServer {
		return nil
	}
	if s.trustedIssuerValidator == nil {
		return fmt.Errorf("DisableAuthorizationServer requires WithTrustedIssuers: no token could be accepted")
	}
	if s.Config.RequireResourceAccessTokens {
		resource := []string{s.Config.GetResourceIdentifier()}
		for _, issuer := range slices.Sorted(maps.Keys(s.trustedIssuerValidator.issuers)) {
			audiences := s.trustedIssuerValidator.issuers[issuer].AllowedAudiences
			if len(audiences) > 0 && helpers.FindMatchingAudience(audiences, resource) == "" {
				return fmt.Errorf("trusted issuer %q: RequireResourceAccessTokens needs AllowedAudiences to name the resource %q", issuer, resource[0])
			}
		}
	}
	if missing := s.resourcesWithoutAuthorizationServer(); len(missing) > 0 {
		s.Logger.Warn("No authorization server is advertised in the protected resource metadata; MCP requires at least one",
			"resources", missing,
			"recommendation", "list the issuer clients sign in with in ResourceMetadataByPath AuthorizationServers")
	}
	return nil
}

// resourcesWithoutAuthorizationServer lists the resource identifiers whose
// protected resource metadata names no authorization server: the main
// resource unless a ResourceMetadataByPath entry for it, by identifier or by
// its URL path, lists one, and every entry that lists none.
func (s *Server) resourcesWithoutAuthorizationServer() []string {
	main := s.Config.GetResourceIdentifier()
	mainPath := ""
	if mainURL, err := url.Parse(main); err == nil {
		mainPath = path.Clean("/" + mainURL.Path)
	}
	mainAdvertised := false
	var missing []string
	for _, resourcePath := range slices.Sorted(maps.Keys(s.Config.ResourceMetadataByPath)) {
		resource := s.Config.ResourceMetadataByPath[resourcePath]
		identifier := s.Config.PathResourceIdentifier(resourcePath, resource)
		if len(resource.AuthorizationServers) == 0 {
			missing = append(missing, identifier)
			continue
		}
		if resourcesMatch(identifier, main) || path.Clean("/"+resourcePath) == mainPath {
			mainAdvertised = true
		}
	}
	if !mainAdvertised && !slices.Contains(missing, main) {
		missing = append([]string{main}, missing...)
	}
	return missing
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
