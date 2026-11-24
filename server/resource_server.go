package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"slices"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
)

// ErrAuthorizationServerDisabled is returned by the authorization server
// flows (authorization, provider callback, code exchange, refresh, session
// refresh, revocation, identity flow, forwarded ID tokens) when
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
	return s.validateResourceServer()
}

// validateResourceServer refuses, once the options are applied, a
// resource server that could accept no token, and warns about a resource
// that advertises no authorization server. With the authorization server
// off and RequireResourceAccessTokens set, it also refuses an issuer whose
// tokens could name none of this server's resources, the main one or a
// ResourceMetadataByPath entry: the issuer list then only admits bearers.
// With the authorization server on the same list also validates RFC 8693
// subject tokens, whose audience is not this resource.
func (s *Server) validateResourceServer() error {
	if !s.Config.DisableAuthorizationServer {
		return nil
	}
	if s.trustedIssuerValidator == nil {
		return fmt.Errorf("DisableAuthorizationServer requires WithTrustedIssuers: no token could be accepted")
	}
	if s.Config.RequireResourceAccessTokens {
		resources := s.Config.resourceIdentifiers()
		for _, issuer := range slices.Sorted(maps.Keys(s.trustedIssuerValidator.issuers)) {
			audiences := s.trustedIssuerValidator.issuers[issuer].AllowedAudiences
			if len(audiences) > 0 && helpers.FindMatchingAudience(audiences, resources) == "" {
				return fmt.Errorf("trusted issuer %q: RequireResourceAccessTokens needs AllowedAudiences to name a resource of this server %q", issuer, resources)
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

// requestedResourceKey carries, through one ValidateTokenForResource call,
// the protected resource the request targets.
type requestedResourceKey struct{}

// ValidateTokenForResource validates accessToken as [Server.ValidateToken]
// does, for a request to resource: the main resource identifier or the
// identifier of a ResourceMetadataByPath entry. Empty resource is the main
// resource. A token this server issued, and a trusted issuer token under
// Config.RequireResourceAccessTokens, must name resource or the main
// resource in its audience. Without that switch a trusted issuer token is
// also accepted when its audience names only an entry's AllowedAudiences.
func (s *Server) ValidateTokenForResource(ctx context.Context, accessToken, resource string) (*providers.UserInfo, error) {
	if resource == "" || resourcesMatch(resource, s.Config.GetResourceIdentifier()) {
		return s.ValidateToken(ctx, accessToken)
	}
	if !s.Config.servesResource(resource) {
		return nil, fmt.Errorf("resource %q is not a protected resource of this server", resource)
	}
	return s.ValidateToken(context.WithValue(ctx, requestedResourceKey{}, resource), accessToken)
}

// acceptedAudiences returns the resource identifiers a bearer's audience may
// name: the main resource, and the resource the request targets when
// ValidateTokenForResource named another one.
func (s *Server) acceptedAudiences(ctx context.Context) []string {
	accepted := []string{s.Config.GetResourceIdentifier()}
	if resource, ok := ctx.Value(requestedResourceKey{}).(string); ok {
		accepted = append(accepted, resource)
	}
	return accepted
}

// namesAcceptedResource reports whether a token audience names a resource
// identifier from acceptedAudiences.
func (s *Server) namesAcceptedResource(ctx context.Context, audience []string) bool {
	return helpers.FindMatchingAudience(audience, s.acceptedAudiences(ctx)) != ""
}

// checkTrustedIssuerAudience reports whether a trusted issuer token's audience
// names an accepted resource, and refuses one that does not under
// RequireResourceAccessTokens.
func (s *Server) checkTrustedIssuerAudience(ctx context.Context, identity *SubjectIdentity) (bool, error) {
	if identity.Claims == nil {
		s.Auditor.LogAuthFailure(ctx, identity.Subject, "", "", "trusted_issuer_audience_invalid")
		return false, errors.New("trusted issuer JWT is not intended for this resource server")
	}
	resourceAudience := s.namesAcceptedResource(ctx, identity.Claims.Audience)
	if s.Config.RequireResourceAccessTokens && !resourceAudience {
		s.Auditor.LogAuthFailure(ctx, identity.Subject, "", "", "trusted_issuer_audience_invalid")
		return false, errors.New("trusted issuer JWT is not intended for this resource server")
	}
	return resourceAudience, nil
}
