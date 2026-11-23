package valkey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

var (
	errOnlineFamilyMigrationRequiresStandalone = errors.New("online family revocation index migration requires standalone Valkey; use the stopped-traffic migration command for clusters")
	errFamilyWalkInterrupted                   = errors.New("valkey server restarted or failed over during the family revocation walk")
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
// With migrateFamilyIndex set on standalone Valkey, it also backfills the index
// while traffic is served.
func (s *Store) startFamilyRevocationIndexing() {
	s.familyIndexingMu.Lock()
	defer s.familyIndexingMu.Unlock()
	if s.familyIndexingClosed || s.familyRevocationsIndexed.Load() {
		return
	}
	migrate := s.migrateFamilyIndex
	switch {
	case migrate && s.client.Mode() != valkeygo.ClientModeStandalone:
		migrate = false
		s.logger.Error("Family revocation index requires migration, which only runs online on standalone Valkey; compatibility lookups remain enabled; run the stopped-traffic migration command")
	case migrate:
		s.logger.Info("Family revocation index requires migration; migrating while serving")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.stopFamilyIndexing = cancel
	s.familyIndexingDone = done
	go func() {
		defer close(done)
		s.awaitFamilyRevocationIndex(ctx, migrate)
	}()
}

// stopFamilyRevocationIndexing stops the worker and waits for it to exit.
// With closing set, the worker is never started again.
func (s *Store) stopFamilyRevocationIndexing(closing bool) {
	s.familyIndexingMu.Lock()
	defer s.familyIndexingMu.Unlock()
	s.familyIndexingClosed = s.familyIndexingClosed || closing
	if s.stopFamilyIndexing == nil {
		return
	}
	s.stopFamilyIndexing()
	<-s.familyIndexingDone
	s.stopFamilyIndexing = nil
}

// awaitFamilyRevocationIndex polls for a completed index. Failed walks are
// retried with a delay that doubles up to the lease, so a namespace that fails
// on every walk is not rescanned at the poll interval.
func (s *Store) awaitFamilyRevocationIndex(ctx context.Context, migrate bool) {
	ticker := time.NewTicker(s.familyIndexPollInterval)
	defer ticker.Stop()
	retryDelay := s.familyIndexPollInterval
	var retryAt time.Time
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
		case migrate && !time.Now().Before(retryAt):
			published, err := s.migrateFamilyRevocationsUnderLease(ctx)
			switch {
			case published:
				continue
			case ctx.Err() != nil:
				return
			case errors.Is(err, context.DeadlineExceeded):
				migrate = false
				s.logger.Error("Online family revocation migration exceeded its lease; automatic migration disabled; run the stopped-traffic migration command with a larger -timeout", "lease", s.familyMigrationLease)
			case err != nil:
				s.logger.Warn("Online family revocation migration failed; compatibility lookups remain enabled", "error", err, "retry_in", retryDelay)
				retryAt = time.Now().Add(retryDelay)
				retryDelay = min(2*retryDelay, s.familyMigrationLease)
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

	runID, err := s.serverRunID(ctx)
	if err != nil {
		return false, err
	}
	checkLegacy, err := s.indexFamilyRevocations(ctx)
	if err != nil {
		return false, err
	}
	walkedRunID, err := s.serverRunID(ctx)
	if err != nil {
		return false, err
	}
	if walkedRunID != runID {
		return false, errFamilyWalkInterrupted
	}
	if err := s.publishFamilyRevocationIndexState(ctx, checkLegacy); err != nil {
		return false, err
	}
	return true, nil
}

// serverRunID identifies the server process. SCAN covers every key present for
// a whole iteration only within one run, so a restart or failover during the
// walk changes the run ID and voids the walk.
func (s *Store) serverRunID(ctx context.Context) (string, error) {
	info, err := s.client.Do(ctx, s.client.B().Info().Section("server").Build()).ToString()
	if err != nil {
		return "", fmt.Errorf("read Valkey server run ID: %w", err)
	}
	for line := range strings.Lines(info) {
		if runID, found := strings.CutPrefix(strings.TrimSpace(line), "run_id:"); found && runID != "" {
			return runID, nil
		}
	}
	return "", errors.New("valkey INFO server reply has no run_id")
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
