package valkey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

var errOnlineFamilyMigrationRequiresStandalone = errors.New("online family revocation index migration requires standalone Valkey; use the stopped-traffic migration command for clusters")

const (
	defaultFamilyIndexPollInterval = 30 * time.Second
	defaultFamilyMigrationLease    = 10 * time.Minute
)

func (s *Store) familyMigrationLeaseKey() string {
	return s.keyOf("schema", "family-revocations", "migration-lease")
}

// startFamilyRevocationIndexing keeps an unindexed store on compatibility
// lookups until the index is complete, then switches it to indexed lookups.
// With migrate set, it also backfills the index while traffic is served.
func (s *Store) startFamilyRevocationIndexing(migrate bool) {
	if s.familyRevocationsIndexed.Load() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stopBackground = cancel
	s.backgroundDone = make(chan struct{})
	if migrate {
		s.logger.Info("Family revocation index requires migration; migrating while serving")
	}
	go func() {
		defer close(s.backgroundDone)
		s.indexFamilyRevocations(ctx, migrate)
	}()
}

func (s *Store) stopFamilyRevocationIndexing() {
	if s.stopBackground == nil {
		return
	}
	s.stopBackground()
	<-s.backgroundDone
}

func (s *Store) indexFamilyRevocations(ctx context.Context, migrate bool) {
	ticker := time.NewTicker(s.familyIndexPollInterval)
	defer ticker.Stop()
	for {
		indexed, err := s.loadFamilyRevocationIndexState(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			s.logger.Warn("Family revocation index check failed", "error", err)
		case indexed:
			s.logger.Info("Family revocation index complete; indexed lookups enabled")
			return
		case migrate:
			published, err := s.migrateFamilyRevocationsUnderLease(ctx)
			if err != nil && ctx.Err() == nil {
				s.logger.Warn("Online family revocation migration failed; compatibility lookups remain enabled", "error", err)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				migrate = false
				s.logger.Error("Online family revocation migration exceeded its lease; automatic migration disabled; run the stopped-traffic migration command with a larger -timeout", "lease", s.familyMigrationLease)
			}
			if published {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loadFamilyRevocationIndexState enables indexed lookups only after a supported
// completion state is present.
func (s *Store) loadFamilyRevocationIndexState(ctx context.Context) (bool, error) {
	readCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	version, err := s.client.Do(readCtx, s.client.B().Get().Key(s.familyRevocationIndexKey()).Build()).ToString()
	if isNilError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if version != "1" && version != familyRevocationIndexWithLegacyChecks {
		return false, fmt.Errorf("unsupported family revocation index version")
	}
	s.checkLegacyFamilyMarkers.Store(version == familyRevocationIndexWithLegacyChecks)
	s.familyRevocationsIndexed.Store(true)
	return true, nil
}

// migrateFamilyRevocationsUnderLease requires standalone Valkey because a
// per-node SCAN cannot cover keys moved between cluster nodes during the walk.
func (s *Store) migrateFamilyRevocationsUnderLease(ctx context.Context) (bool, error) {
	if s.client.Mode() != valkeygo.ClientModeStandalone {
		return false, errOnlineFamilyMigrationRequiresStandalone
	}
	ctx, cancel := context.WithTimeout(ctx, s.familyMigrationLease)
	defer cancel()
	holder, acquired, err := s.acquireFamilyMigrationLease(ctx)
	if err != nil || !acquired {
		return false, err
	}
	defer s.releaseFamilyMigrationLease(holder)

	checkLegacy := false
	if err := s.walkFamilyKeys(ctx, func(key string) error {
		needsLegacyChecks, err := s.indexFamilyRevocation(ctx, key)
		checkLegacy = checkLegacy || needsLegacyChecks
		return err
	}); err != nil {
		return false, err
	}
	if err := s.publishFamilyRevocationIndexState(ctx, checkLegacy); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) acquireFamilyMigrationLease(ctx context.Context) (string, bool, error) {
	holder := rand.Text()
	err := s.client.Do(ctx, s.client.B().Set().Key(s.familyMigrationLeaseKey()).Value(holder).
		Nx().Px(s.familyMigrationLease).Build()).Error()
	if isNilError(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("acquire family revocation migration lease: %w", err)
	}
	return holder, true, nil
}

func (s *Store) releaseFamilyMigrationLease(holder string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
	defer cancel()
	err := s.client.Do(ctx, s.client.B().Eval().Script(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`).Numkeys(1).Key(s.familyMigrationLeaseKey()).Arg(holder).Build()).Error()
	if err != nil {
		s.logger.Warn("Failed to release family revocation migration lease", "error", err)
	}
}

// indexFamilyRevocation preserves revoked members. A marker enables legacy
// checks because hashed and legacy family keys share an ambiguous namespace.
func (s *Store) indexFamilyRevocation(ctx context.Context, key string) (bool, error) {
	members, err := s.client.Do(ctx, s.client.B().Smembers().Key(key).Build()).AsStrSlice()
	if err != nil {
		return false, fmt.Errorf("read family revocation members: %w", err)
	}
	remaining, err := s.client.Do(ctx, s.client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		return false, fmt.Errorf("read family revocation retention: %w", err)
	}
	checkLegacy := slices.Contains(members, familyRevocationMarker)
	for _, member := range s.readFamilyMembersMetadata(ctx, members) {
		if errors.Is(member.err, storage.ErrRefreshTokenFamilyNotFound) {
			continue
		}
		if member.err != nil {
			return checkLegacy, fmt.Errorf("read family revocation metadata: %w", member.err)
		}
		if err := s.indexRevokedFamily(ctx, member.meta, remaining); err != nil {
			return checkLegacy, err
		}
	}
	return checkLegacy, nil
}

// publishFamilyRevocationIndexState preserves the legacy-check requirement
// across concurrent completions.
func (s *Store) publishFamilyRevocationIndexState(ctx context.Context, checkLegacy bool) error {
	version := "1"
	if checkLegacy {
		version = familyRevocationIndexWithLegacyChecks
	}
	err := s.client.Do(ctx, s.client.B().Eval().Script(`
if redis.call('GET', KEYS[1]) == ARGV[2] then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1])
return 1
`).Numkeys(1).Key(s.familyRevocationIndexKey()).Arg(version, familyRevocationIndexWithLegacyChecks).Build()).Error()
	if err != nil {
		return fmt.Errorf("complete family revocation index: %w", err)
	}
	return nil
}
