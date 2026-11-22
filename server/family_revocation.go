package server

import (
	"context"
	"errors"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func (s *Server) checkFamilyRevocation(ctx context.Context, familyID, clientID string) error {
	if familyID == "" {
		return nil
	}
	revoked, err := s.familyRevoked(ctx, familyID)
	if errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
		return nil
	}
	if err != nil {
		return s.storageUnavailable(ctx, "check token family revocation", clientID, "", err)
	}
	if revoked {
		s.Auditor.LogEvent(ctx, security.Event{
			Type: security.EventAuthFailure, ClientID: clientID,
			Details: map[string]any{logKeyReason: "family_revoked", logKeySeverity: severityWarning},
		})
		return errInvalidAccessToken
	}
	return nil
}

func (s *Server) familyRevoked(ctx context.Context, familyID string) (bool, error) {
	if indexed, ok := s.tokenStore.(storage.RefreshTokenFamilyRevocationChecker); ok {
		return indexed.IsRefreshTokenFamilyRevoked(ctx, familyID)
	}
	if indexed, ok := s.tokenStore.(storage.RefreshTokenFamilyByIDStore); ok {
		family, err := indexed.GetRefreshTokenFamilyByID(ctx, familyID)
		return family != nil && family.Revoked, err
	}
	return false, nil
}

func (s *Server) checkRefreshFamilyRevocation(ctx context.Context, familyID, clientID string) error {
	return refreshGrantError(s.checkFamilyRevocation(ctx, familyID, clientID))
}

func refreshGrantError(err error) error {
	if err == nil || errors.Is(err, ErrStorageUnavailable) {
		return err
	}
	return errInvalidGrant
}
