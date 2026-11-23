package valkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"
)

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
		indexed, retry := s.familyRevocationIndexStep(ctx, migrate)
		if indexed {
			s.logger.Info("Family revocation index complete; indexed lookups enabled")
			return
		}
		if retry {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// familyRevocationIndexStep reports whether the store switched to the index,
// and whether it published the index itself and should load it at once.
func (s *Store) familyRevocationIndexStep(ctx context.Context, migrate bool) (indexed, retry bool) {
	indexed, err := s.loadFamilyRevocationIndex(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Warn("Family revocation index check failed", "error", err)
		}
		return false, false
	}
	if indexed || !migrate {
		return indexed, false
	}
	published, err := s.migrateFamilyRevocationsUnderLease(ctx)
	if err != nil && ctx.Err() == nil {
		s.logger.Warn("Online family revocation migration failed; compatibility lookups remain enabled", "error", err)
	}
	return false, published
}

// loadFamilyRevocationIndex reports whether another store completed the index
// and, if so, switches this store to it.
func (s *Store) loadFamilyRevocationIndex(ctx context.Context) (bool, error) {
	readCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	version, err := s.client.Do(readCtx, s.client.B().Get().Key(s.familyRevocationIndexKey()).Build()).ToString()
	if isNilError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if version != "1" && version != familyRevocationIndexWithLegacyMarkers {
		return false, fmt.Errorf("unsupported family revocation index version")
	}
	s.legacyFamilyMarkers.Store(version == familyRevocationIndexWithLegacyMarkers)
	s.familyRevocationsIndexed.Store(true)
	return true, nil
}

// migrateFamilyRevocationsUnderLease backfills the index while other stores
// serve traffic. Writers from v1.17.2 on add the shared marker before touching
// members, so revocations made during the walk are indexed by their writer and
// compatibility lookups stay correct until the index is complete. A walk that
// overlaps a topology change may miss keys and is repeated.
func (s *Store) migrateFamilyRevocationsUnderLease(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.familyMigrationLease)
	defer cancel()
	holder, acquired, err := s.acquireFamilyMigrationLease(ctx)
	if err != nil || !acquired {
		return false, err
	}
	defer s.releaseFamilyMigrationLease(holder)

	before := slices.Sorted(maps.Keys(s.client.Nodes()))
	legacyMarkers := false
	if err := s.walkFamilyKeys(ctx, func(key string) error {
		marked, err := s.indexFamilyRevocation(ctx, key)
		legacyMarkers = legacyMarkers || marked
		return err
	}); err != nil {
		return false, err
	}
	if after := slices.Sorted(maps.Keys(s.client.Nodes())); !slices.Equal(before, after) {
		return false, fmt.Errorf("valkey topology changed during family revocation migration")
	}
	if err := s.publishFamilyRevocationIndex(ctx, legacyMarkers); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) acquireFamilyMigrationLease(ctx context.Context) (string, bool, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", false, err
	}
	holder := hex.EncodeToString(nonce)
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

// indexFamilyRevocation marks the families of revoked members of one family
// key and reports whether the key holds the shared marker itself.
func (s *Store) indexFamilyRevocation(ctx context.Context, key string) (bool, error) {
	members, err := s.client.Do(ctx, s.client.B().Smembers().Key(key).Build()).AsStrSlice()
	if err != nil {
		return false, fmt.Errorf("read family revocation members: %w", err)
	}
	remaining, err := s.client.Do(ctx, s.client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		return false, fmt.Errorf("read family revocation retention: %w", err)
	}
	marked := false
	for _, member := range members {
		if member == familyRevocationMarker {
			marked = true
			continue
		}
		if err := s.migrateRevokedMember(ctx, member, remaining); err != nil {
			return marked, err
		}
	}
	return marked, nil
}

// publishFamilyRevocationIndex never downgrades an index that records legacy
// markers, so a concurrent walk that saw fewer markers cannot drop them.
func (s *Store) publishFamilyRevocationIndex(ctx context.Context, legacyMarkers bool) error {
	version := "1"
	if legacyMarkers {
		version = familyRevocationIndexWithLegacyMarkers
	}
	err := s.client.Do(ctx, s.client.B().Eval().Script(`
if redis.call('GET', KEYS[1]) == ARGV[2] then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1])
return 1
`).Numkeys(1).Key(s.familyRevocationIndexKey()).Arg(version, familyRevocationIndexWithLegacyMarkers).Build()).Error()
	if err != nil {
		return fmt.Errorf("complete family revocation index: %w", err)
	}
	return nil
}
