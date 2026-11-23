package oauthconfig

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/server"
)

// additionalResource is one OAUTH_ADDITIONAL_RESOURCES entry, named after the
// RFC 9728 protected resource metadata fields.
type additionalResource struct {
	Resource             string   `json:"resource"`
	ScopesSupported      []string `json:"scopesSupported,omitempty"`
	AuthorizationServers []string `json:"authorizationServers,omitempty"`
}

// loadProtectedResourcesFromEnv reads RESOURCE, AUTHORIZATION_SERVERS and
// ADDITIONAL_RESOURCES. Each protected resource is set once: the main one by
// the two plain variables, each extra one by its full URL in the list. Every
// metadata entry carries its identifier explicitly, so the document's
// resource is the URL its well-known path was derived from (RFC 9728 §3.3).
func loadProtectedResourcesFromEnv(prefix string, cfg *server.Config) error {
	if raw := os.Getenv(prefix + "RESOURCE"); raw != "" {
		if err := validateResourceIdentifier(prefix+"RESOURCE", raw, cfg.AllowInsecureHTTP); err != nil {
			return err
		}
		cfg.ResourceIdentifier = raw
	}
	authorizationServers := splitAndTrim(os.Getenv(prefix+"AUTHORIZATION_SERVERS"), ",")
	if err := validateIssuerIdentifiers(prefix+"AUTHORIZATION_SERVERS", authorizationServers, cfg.AllowInsecureHTTP); err != nil {
		return err
	}
	extras, err := additionalResourcesFromEnv(prefix)
	if err != nil {
		return err
	}
	if len(authorizationServers) == 0 && len(extras) == 0 {
		return nil
	}

	main := cfg.GetResourceIdentifier()
	mainURL, err := url.Parse(main)
	if err != nil {
		return fmt.Errorf("%sRESOURCE: %w", prefix, err)
	}
	byPath := make(map[string]server.ProtectedResourceConfig, len(extras)+1)
	if len(authorizationServers) > 0 {
		byPath[metadataPath(mainURL)] = server.ProtectedResourceConfig{
			ResourceIdentifier:   main,
			AuthorizationServers: authorizationServers,
		}
	}
	for i, extra := range extras {
		name := fmt.Sprintf("%sADDITIONAL_RESOURCES[%d]", prefix, i)
		extraPath, err := extra.validate(name, mainURL, cfg.AllowInsecureHTTP)
		if err != nil {
			return err
		}
		if _, ok := byPath[extraPath]; ok {
			return fmt.Errorf("%s.resource: %q is listed twice", name, extra.Resource)
		}
		servers := extra.AuthorizationServers
		if len(servers) == 0 {
			servers = authorizationServers
		}
		byPath[extraPath] = server.ProtectedResourceConfig{
			ResourceIdentifier:   extra.Resource,
			ScopesSupported:      extra.ScopesSupported,
			AuthorizationServers: servers,
		}
	}
	cfg.ResourceMetadataByPath = byPath
	return nil
}

func additionalResourcesFromEnv(prefix string) ([]additionalResource, error) {
	raw := os.Getenv(prefix + "ADDITIONAL_RESOURCES")
	if raw == "" {
		return nil, nil
	}
	var extras []additionalResource
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&extras); err != nil {
		return nil, fmt.Errorf("%sADDITIONAL_RESOURCES: %w", prefix, err)
	}
	return extras, nil
}

// validate checks an extra resource against the main one and returns the
// path its metadata is served under.
func (extra additionalResource) validate(name string, main *url.URL, allowInsecure bool) (string, error) {
	if err := validateResourceIdentifier(name+".resource", extra.Resource, allowInsecure); err != nil {
		return "", err
	}
	extraURL, err := url.Parse(extra.Resource)
	if err != nil {
		return "", fmt.Errorf("%s.resource: %w", name, err)
	}
	if !strings.EqualFold(extraURL.Scheme, main.Scheme) || !strings.EqualFold(extraURL.Host, main.Host) {
		return "", fmt.Errorf("%s.resource: %q is not on the origin of the main resource %q", name, extra.Resource, main)
	}
	if err := helpers.ValidateMetadataPath(extraURL.Path); err != nil {
		return "", fmt.Errorf("%s.resource: %w", name, err)
	}
	extraPath := metadataPath(extraURL)
	if helpers.NormalizeURL(extra.Resource) == helpers.NormalizeURL(main.String()) || extraPath == metadataPath(main) {
		return "", fmt.Errorf("%s.resource: %q is the main resource; set it with the RESOURCE variable", name, extra.Resource)
	}
	if err := validateIssuerIdentifiers(name+".authorizationServers", extra.AuthorizationServers, allowInsecure); err != nil {
		return "", err
	}
	return extraPath, nil
}

func validateIssuerIdentifiers(name string, issuers []string, allowInsecure bool) error {
	for _, issuer := range issuers {
		if err := validateIssuerIdentifier(issuer, allowInsecure); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// metadataPath is the path a resource's metadata document is served under,
// after the well-known prefix (RFC 9728 §3.1).
func metadataPath(resource *url.URL) string {
	return path.Clean("/" + strings.TrimPrefix(resource.Path, "/"))
}

// validateResourceIdentifier applies RFC 8707 §2 and RFC 9728 §1.2: an
// absolute https URI without a fragment. A query or a trailing slash only
// warns, following the MCP canonical server URI.
func validateResourceIdentifier(name, raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%s: %q is not an absolute URI", name, raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%s: %q has a fragment (RFC 8707 §2)", name, raw)
	}
	if err := requireHTTPS(u, allowInsecure); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if u.RawQuery != "" {
		slog.Default().Warn("Resource identifier has a query component; RFC 8707 §2 recommends none", "env_var", name, "resource", raw)
	}
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		slog.Default().Warn("Resource identifier ends with a slash; MCP clients send the form without it", "env_var", name, "resource", raw)
	}
	return nil
}

// validateIssuerIdentifier applies RFC 8414 §2: an https URL with no query or
// fragment.
func validateIssuerIdentifier(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("issuer %q is not an absolute URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("issuer %q has a query or fragment (RFC 8414 §2)", raw)
	}
	return requireHTTPS(u, allowInsecure)
}

// requireHTTPS accepts https, and http only for a loopback host or under
// ALLOW_INSECURE_HTTP, as the issuer check does.
func requireHTTPS(u *url.URL, allowInsecure bool) error {
	switch {
	case strings.EqualFold(u.Scheme, "https"):
		return nil
	case strings.EqualFold(u.Scheme, "http") && (allowInsecure || helpers.IsLoopbackHostname(u.Hostname())):
		return nil
	default:
		return fmt.Errorf("%q must use https", u.String())
	}
}

// loadEndpointSwitchesFromEnv reads the optional endpoint switches, named
// after the specifications that define the endpoints.
func loadEndpointSwitchesFromEnv(prefix string, cfg *server.Config) error {
	var err error
	if cfg.EnableIntrospectionEndpoint, err = optionalBool(prefix+"ENABLE_INTROSPECTION_ENDPOINT", false); err != nil {
		return err
	}
	if cfg.EnableUserInfoEndpoint, err = optionalBool(prefix+"ENABLE_USERINFO_ENDPOINT", false); err != nil {
		return err
	}
	if cfg.EnableClientManagementEndpoint, err = optionalBool(prefix+"ENABLE_CLIENT_CONFIGURATION_ENDPOINT", false); err != nil {
		return err
	}
	cfg.RequireResourceAccessTokens, err = optionalBool(prefix+"REQUIRE_RESOURCE_ACCESS_TOKENS", false)
	return err
}
