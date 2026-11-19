package server

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/privateaddr"
)

// ErrClientMetadataNotAllowed is returned for a URL client_id that
// RestrictClientMetadata refuses: it is neither pinned in PreRegisteredClientMetadata
// nor on a host in ClientMetadataHosts. No DNS lookup or request is made for it.
var ErrClientMetadataNotAllowed = errors.New("client_id metadata URL is not pre-registered and its host is not in ClientMetadataHosts")

func validateRestrictClientMetadata(cfg *Config) error {
	if !cfg.RestrictClientMetadata {
		if len(cfg.ClientMetadataHosts) > 0 {
			return fmt.Errorf("ClientMetadataHosts requires RestrictClientMetadata")
		}
		return nil
	}
	if !cfg.EnableClientIDMetadataDocuments {
		return fmt.Errorf("RestrictClientMetadata requires EnableClientIDMetadataDocuments")
	}
	if len(cfg.PreRegisteredClientMetadata) == 0 && len(cfg.ClientMetadataHosts) == 0 {
		return fmt.Errorf("RestrictClientMetadata needs PreRegisteredClientMetadata or ClientMetadataHosts: it would refuse every URL client_id")
	}
	for i, host := range cfg.ClientMetadataHosts {
		if err := validateClientMetadataHost(host); err != nil {
			return fmt.Errorf("ClientMetadataHosts[%d]: %w", i, err)
		}
	}
	return nil
}

// validateClientMetadataHost accepts an exact DNS hostname only: no wildcard,
// port, scheme, path or IP literal.
func validateClientMetadataHost(host string) error {
	key := privateaddr.HostKey(host)
	switch {
	case key == "":
		return fmt.Errorf("empty host")
	case strings.ContainsAny(key, "*:/@?# \t"):
		return fmt.Errorf("%q is not an exact hostname (no wildcard, port, scheme or path)", host)
	case net.ParseIP(key) != nil:
		return fmt.Errorf("%q is an IP literal; list a hostname", host)
	}
	return nil
}

// checkClientMetadataAllowed applies RestrictClientMetadata to a URL client_id
// that is not pinned: its host must be in ClientMetadataHosts, matched on the
// host key.
func (s *Server) checkClientMetadataAllowed(clientID string) error {
	if !s.Config.RestrictClientMetadata {
		return nil
	}
	u, err := url.Parse(clientID)
	if err == nil && s.clientMetadataHosts.Contains(u.Hostname()) {
		return nil
	}
	return ErrClientMetadataNotAllowed
}
