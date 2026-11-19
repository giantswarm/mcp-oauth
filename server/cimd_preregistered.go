package server

import (
	"fmt"
	"slices"

	"github.com/giantswarm/mcp-oauth/storage"
)

func validatePreRegisteredClientMetadata(cfg *Config) error {
	if len(cfg.PreRegisteredClientMetadata) > 0 && !cfg.EnableClientIDMetadataDocuments {
		return fmt.Errorf("PreRegisteredClientMetadata requires EnableClientIDMetadataDocuments")
	}
	seen := make(map[string]bool, len(cfg.PreRegisteredClientMetadata))
	for i, metadata := range cfg.PreRegisteredClientMetadata {
		if !isClientIDMetadataDocumentURL(metadata.ClientID) {
			return fmt.Errorf("PreRegisteredClientMetadata[%d]: invalid CIMD client_id", i)
		}
		if seen[metadata.ClientID] {
			return fmt.Errorf("PreRegisteredClientMetadata[%d]: duplicate client_id", i)
		}
		seen[metadata.ClientID] = true
		if err := validateClientMetadata(&metadata); err != nil {
			return fmt.Errorf("PreRegisteredClientMetadata[%d]: %w", i, err)
		}
	}
	return nil
}

// buildPreRegisteredClients snapshots the validated configuration. Neither mutation of
// the caller's configuration nor a returned Client may change the pinned policy.
func buildPreRegisteredClients(documents []ClientMetadata) map[string]*storage.Client {
	clients := make(map[string]*storage.Client, len(documents))
	for _, metadata := range documents {
		setClientMetadataDefaults(&metadata)
		clients[metadata.ClientID] = clonePreRegisteredClient(metadataToClient(&metadata))
	}
	return clients
}

func clonePreRegisteredClient(client *storage.Client) *storage.Client {
	copy := *client
	copy.RedirectURIs = slices.Clone(client.RedirectURIs)
	copy.GrantTypes = slices.Clone(client.GrantTypes)
	copy.ResponseTypes = slices.Clone(client.ResponseTypes)
	copy.Scopes = slices.Clone(client.Scopes)
	return &copy
}
