package server

import (
	"context"

	"github.com/giantswarm/mcp-oauth/storage"
)

func (s *Server) checkClientRevocation(ctx context.Context, clientID string) error {
	store, ok := s.clientStore.(storage.ClientRevocationStore)
	if !ok {
		return nil
	}
	revoked, err := store.IsClientRevoked(ctx, clientID)
	if err != nil {
		return s.storageUnavailable(ctx, "read client revocation", clientID, "", err)
	}
	if revoked {
		return errInvalidAccessToken
	}
	return nil
}
