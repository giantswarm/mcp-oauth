package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/giantswarm/mcp-oauth/storage"
)

var _ storage.RefreshTokenFamilyRevocationChecker = (*Store)(nil)

// IsRefreshTokenFamilyRevoked checks the retained family fence even after member deletion.
func (s *Store) IsRefreshTokenFamilyRevoked(_ context.Context, familyID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokedFamilies[familyID].After(time.Now()), nil
}

func maxFamilyRetention(first, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}

func (s *Store) markFamilyRevokedLocked(familyID string, now time.Time) error {
	if _, exists := s.revokedFamilies[familyID]; !exists && len(s.revokedFamilies) >= hardMaxFamilyMetadataEntries {
		return fmt.Errorf("revoked family limit exceeded (%d entries)", len(s.revokedFamilies))
	}
	retentionDays := s.revokedFamilyRetentionDays
	if retentionDays <= 0 {
		retentionDays = 90
	}
	s.revokedFamilies[familyID] = maxFamilyRetention(s.revokedFamilies[familyID],
		maxFamilyRetention(s.familyRetainUntil[familyID], now.Add(time.Duration(retentionDays)*24*time.Hour)))
	return nil
}
