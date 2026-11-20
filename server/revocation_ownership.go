package server

import (
	"context"

	"github.com/giantswarm/mcp-oauth/storage"
)

func (s *Server) revocationClientMatches(ctx context.Context, token, clientID string) (bool, error) {
	if clientID == "" {
		return false, nil
	}
	family, err := s.lookupRefreshTokenFamily(ctx, token)
	if err != nil {
		return false, s.storageUnavailable(ctx, "read revocation token family", clientID, "", err)
	}
	if family != nil {
		return family.ClientID == clientID, nil
	}
	getter, ok := s.tokenStore.(storage.TokenMetadataGetter)
	if !ok {
		return false, nil
	}
	metadata, err := getter.GetTokenMetadata(token)
	if storage.IsNotFoundError(err) || storage.IsExpiredError(err) {
		return false, nil
	}
	if err != nil {
		return false, s.storageUnavailable(ctx, "read revocation token owner", clientID, "", err)
	}
	return metadata != nil && metadata.ClientID == clientID, nil
}
