package server

import (
	"context"
	"errors"

	"github.com/giantswarm/mcp-oauth/storage"
)

// GetRevocationClient resolves registered clients and public CIMD identifiers without fetching metadata.
func (s *Server) GetRevocationClient(ctx context.Context, clientID string) (*storage.Client, error) {
	client, err := s.GetRegisteredClient(ctx, clientID)
	if !errors.Is(err, storage.ErrClientNotFound) || !s.Config.EnableClientIDMetadataDocuments || !isClientIDMetadataDocumentURL(clientID) {
		return client, err
	}
	// CIMD clients use "none"; revocation authorization comes from the issued token's client binding.
	return &storage.Client{ClientID: clientID, ClientType: ClientTypePublic, TokenEndpointAuthMethod: TokenEndpointAuthMethodNone}, nil
}

func (s *Server) revocationTokenOwner(ctx context.Context, token string) (string, *storage.RefreshTokenFamilyMetadata, error) {
	family, err := s.lookupRefreshTokenFamily(ctx, token)
	if err != nil {
		return "", nil, err
	}
	if family != nil {
		return family.ClientID, family, nil
	}
	getter, ok := s.tokenStore.(storage.TokenMetadataGetter)
	if !ok {
		return "", nil, nil
	}
	metadata, err := getter.GetTokenMetadata(token)
	if storage.IsNotFoundError(err) || storage.IsExpiredError(err) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if metadata == nil {
		return "", nil, nil
	}
	return metadata.ClientID, nil, nil
}
