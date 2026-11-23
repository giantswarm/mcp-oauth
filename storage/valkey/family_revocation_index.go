package valkey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

var _ storage.RefreshTokenFamilyRevocationChecker = (*Store)(nil)

const familyRevocationIndexWithLegacyMarkers = "1-legacy"

var errFamilyRecordsExist = errors.New("family records require migration")

func (s *Store) familyRevocationIndexKey() string {
	return s.keyOf("schema", "family-revocations", "1")
}

func (s *Store) initializeFamilyRevocationIndex(ctx context.Context) error {
	version, err := s.client.Do(ctx, s.client.B().Get().Key(s.familyRevocationIndexKey()).Build()).ToString()
	if err == nil {
		if version != "1" && version != familyRevocationIndexWithLegacyMarkers {
			return fmt.Errorf("unsupported family revocation index version")
		}
		s.legacyFamilyMarkers.Store(version == familyRevocationIndexWithLegacyMarkers)
		s.familyRevocationsIndexed.Store(true)
		return nil
	}
	if !isNilError(err) {
		return err
	}
	err = s.walkFamilyKeys(ctx, func(string) error { return errFamilyRecordsExist })
	if errors.Is(err, errFamilyRecordsExist) {
		s.logger.Warn("Family revocation index requires migration; compatibility reads remain enabled")
		return nil
	}
	if err != nil {
		return err
	}
	return s.completeFamilyRevocationIndex(ctx)
}

// IsRefreshTokenFamilyRevoked checks the shared revocation marker.
// Unmigrated storage retains per-member validation until old writers are fenced and migration completes.
func (s *Store) IsRefreshTokenFamilyRevoked(ctx context.Context, familyID string) (revoked bool, err error) {
	operation := s.startTracedOp(ctx, "is_refresh_token_family_revoked")
	defer operation.end(&err)
	if familyID == "" {
		return false, nil
	}
	if !s.familyRevocationsIndexed.Load() {
		family, err := s.GetRefreshTokenFamilyByID(operation.ctx, familyID)
		if errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
			return false, nil
		}
		return family != nil && family.Revoked, err
	}
	revoked, err = s.client.Do(operation.ctx, s.client.B().Sismember().Key(s.familyKey(familyID)).
		Member(familyRevocationMarker).Build()).AsBool()
	if err != nil || revoked || !s.legacyFamilyMarkers.Load() {
		return revoked, err
	}
	return s.client.Do(operation.ctx, s.client.B().Sismember().Key(s.legacyFamilyKey(familyID)).
		Member(familyRevocationMarker).Build()).AsBool()
}

// MigrateFamilyRevocations preserves revoked members from both key layouts in the shared marker index.
// All OAuth traffic and old writers must be stopped until this operation succeeds.
// Other Store instances must be reopened after migration to enable indexed reads.
func (s *Store) MigrateFamilyRevocations(ctx context.Context) error {
	s.familyRevocationsIndexed.Store(false)
	if err := s.client.Do(ctx, s.client.B().Del().Key(s.familyRevocationIndexKey()).Build()).Error(); err != nil {
		return fmt.Errorf("disable family revocation index: %w", err)
	}
	if err := s.walkFamilyKeys(ctx, func(key string) error { return s.migrateFamilyRevocation(ctx, key) }); err != nil {
		return err
	}
	return s.completeFamilyRevocationIndex(ctx)
}

func (s *Store) walkFamilyKeys(ctx context.Context, visit func(string) error) error {
	nodes := s.client.Nodes()
	if len(nodes) == 0 {
		return fmt.Errorf("no Valkey nodes available for family migration")
	}
	for _, node := range nodes {
		if err := s.walkNodeFamilyKeys(ctx, node, visit); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) walkNodeFamilyKeys(ctx context.Context, node valkeygo.Client, visit func(string) error) error {
	pattern := strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]").
		Replace(s.keyOf("family", "")) + "*"
	var cursor uint64
	for {
		page, err := node.Do(ctx, node.B().Scan().Cursor(cursor).
			Match(pattern).Count(scanBatchSize).Build()).AsScanEntry()
		if err != nil {
			return fmt.Errorf("scan family revocations: %w", err)
		}
		for _, key := range page.Elements {
			if err := visit(key); err != nil {
				return err
			}
		}
		cursor = page.Cursor
		if cursor == 0 {
			return nil
		}
	}
}

func (s *Store) migrateFamilyRevocation(ctx context.Context, key string) error {
	marked, err := s.indexFamilyRevocation(ctx, key)
	if marked {
		s.legacyFamilyMarkers.Store(true)
	}
	return err
}

func (s *Store) migrateRevokedMember(ctx context.Context, member string, remaining int64) error {
	family, err := s.readMemberFamilyMetadata(ctx, member)
	if errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read family revocation metadata: %w", err)
	}
	if family == nil || !family.Revoked {
		return nil
	}
	if family.FamilyID == "" {
		return fmt.Errorf("revoked family metadata has no family identifier")
	}
	familyKey := s.familyKey(family.FamilyID)
	if remaining == -1 {
		if err := s.client.Do(ctx, s.client.B().Eval().Script(`
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('PERSIST', KEYS[1])
return 1
`).Numkeys(1).Key(familyKey).Arg(familyRevocationMarker).Build()).Error(); err != nil {
			return fmt.Errorf("preserve permanent family revocation: %w", err)
		}
		return nil
	}
	retention := max(s.revokedFamilyRetention(), time.Duration(remaining)*time.Millisecond)
	if err := s.saddExtendOnlyTTL(ctx, familyKey, familyRevocationMarker, retention); err != nil {
		return fmt.Errorf("index revoked family: %w", err)
	}
	return nil
}

func (s *Store) completeFamilyRevocationIndex(ctx context.Context) error {
	version := "1"
	if s.legacyFamilyMarkers.Load() {
		version = familyRevocationIndexWithLegacyMarkers
	}
	if err := s.client.Do(ctx, s.client.B().Set().Key(s.familyRevocationIndexKey()).Value(version).Build()).Error(); err != nil {
		return fmt.Errorf("complete family revocation index: %w", err)
	}
	s.familyRevocationsIndexed.Store(true)
	return nil
}
