package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// validateTrustedPublicRegistrationRedirectURIs validates and normalizes
// TrustedPublicRegistrationRedirectURIs and populates the lookup set.
func validateTrustedPublicRegistrationRedirectURIs(config *Config, logger *slog.Logger) {
	if len(config.TrustedPublicRegistrationRedirectURIs) == 0 {
		return
	}

	set := make(map[string]bool, len(config.TrustedPublicRegistrationRedirectURIs))
	normalized := make([]string, 0, len(config.TrustedPublicRegistrationRedirectURIs))

	for i, raw := range config.TrustedPublicRegistrationRedirectURIs {
		canonical, err := normalizeTrustedRedirectURI(raw)
		if err != nil {
			logger.Error("Removing invalid TrustedPublicRegistrationRedirectURIs entry",
				"index", i, "uri", raw, logKeyReason, err.Error())
			continue
		}
		if set[canonical] {
			logger.Warn("Removing duplicate TrustedPublicRegistrationRedirectURIs entry",
				"index", i, "uri", raw, "normalized", canonical)
			continue
		}
		set[canonical] = true
		normalized = append(normalized, canonical)
	}

	if len(normalized) == 0 {
		config.TrustedPublicRegistrationRedirectURIs = nil
		config.trustedRedirectURIsSet = nil
		logger.Warn("All TrustedPublicRegistrationRedirectURIs entries dropped after validation",
			"result", "feature disabled")
		return
	}
	config.TrustedPublicRegistrationRedirectURIs = normalized
	config.trustedRedirectURIsSet = set
	logger.Debug("TrustedPublicRegistrationRedirectURIs configured", "count", len(normalized))

	if config.AllowPublicClientRegistration {
		logger.Warn("TrustedPublicRegistrationRedirectURIs is redundant when AllowPublicClientRegistration=true",
			"recommendation", "set AllowPublicClientRegistration=false")
	}
}

// normalizeTrustedRedirectURI returns the canonical form of a redirect URI suitable
// for exact-match comparison via helpers.NormalizeURL. Returns an error for any
// URI that is not safe to allowlist (non-HTTPS, fragment, userinfo, missing host,
// loopback, private, link-local, or unspecified IP literal).
func normalizeTrustedRedirectURI(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty URI")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}

	if strings.ToLower(parsed.Scheme) != SchemeHTTPS {
		return "", fmt.Errorf("scheme %q: only https is allowed", parsed.Scheme)
	}
	if parsed.Fragment != "" {
		return "", errors.New("fragment is not allowed")
	}
	if parsed.User != nil {
		return "", errors.New("userinfo is not allowed")
	}

	host := parsed.Hostname()
	if host == "" {
		return "", errors.New("missing host")
	}
	if helpers.IsLoopbackHostname(host) {
		return "", errors.New("loopback host is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		switch {
		case ip.IsUnspecified():
			return "", errors.New("unspecified IP is not allowed")
		case ip.IsPrivate():
			return "", errors.New("private IP is not allowed")
		case helpers.IsLinkLocal(ip):
			return "", errors.New("link-local IP is not allowed")
		}
	}

	return helpers.NormalizeURL(raw), nil
}
