package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/storage"
)

// ============================================================
// RefreshTokenFamilyStore Implementation
// ============================================================

// SaveRefreshTokenWithFamily saves a refresh token with family tracking for reuse detection
// This is the OAuth 2.1 compliant version that enables token theft detection
func (s *Store) SaveRefreshTokenWithFamily(ctx context.Context, refreshToken, userID, clientID, familyID string, generation int, expiresAt time.Time) (err error) {
	op := s.startTracedOp(ctx, "save_refresh_token_with_family")
	defer op.end(&err)

	if err = s.validateRefreshTokenParams(refreshToken, userID, clientID, familyID); err != nil {
		return err
	}

	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	if err = s.saveRefreshTokenBasic(op.ctx, refreshToken, userID, ttl); err != nil {
		return err
	}

	if err = s.saveFamilyMetadata(op.ctx, refreshToken, userID, clientID, familyID, generation, ttl); err != nil {
		return err
	}

	if err = s.saveRefreshTokenMetadata(op.ctx, refreshToken, userID, clientID, familyID, ttl); err != nil {
		return err
	}
	if err = s.addTokenToFamilySet(op.ctx, refreshToken, familyID, ttl); err != nil {
		cleanupError := s.client.Do(op.ctx, s.client.B().Del().Key(
			s.refreshTokenKey(refreshToken), s.refreshTokenMetaKey(refreshToken), s.tokenMetaKey(refreshToken),
		).Build()).Error()
		return errors.Join(err, cleanupError)
	}

	s.addTokenToUserClientSet(op.ctx, refreshToken, userID, clientID, ttl)

	s.logger.Debug("Saved refresh token with family tracking",
		"user_id", userID,
		"family_id", safeTruncate(familyID, tokenIDLogLength),
		"generation", generation,
		"expires_at", expiresAt)

	return nil
}

// validateRefreshTokenParams validates the refresh token parameters.
func (s *Store) validateRefreshTokenParams(refreshToken, userID, clientID, familyID string) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if refreshToken == familyRevocationMarker {
		return fmt.Errorf("refresh token uses a reserved family marker")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if clientID == "" {
		return fmt.Errorf("clientID cannot be empty")
	}
	if familyID == "" {
		return fmt.Errorf("family ID cannot be empty")
	}
	if err := validateInputLength(refreshToken); err != nil {
		return err
	}
	if err := validateInputLength(userID); err != nil {
		return err
	}
	if err := validateInputLength(clientID); err != nil {
		return err
	}
	return validateInputLength(familyID)
}

// saveRefreshTokenBasic saves the basic refresh token info.
func (s *Store) saveRefreshTokenBasic(ctx context.Context, refreshToken, userID string, ttl time.Duration) error {
	refreshKey := s.refreshTokenKey(refreshToken)
	if err := s.client.Do(
		ctx,
		s.client.B().Set().Key(refreshKey).Value(userID).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	return nil
}

// saveFamilyMetadata saves the family metadata for reuse detection.
func (s *Store) saveFamilyMetadata(ctx context.Context, refreshToken, userID, clientID, familyID string, generation int, ttl time.Duration) error {
	familyMeta := &storage.RefreshTokenFamilyMetadata{
		FamilyID:   familyID,
		UserID:     userID,
		ClientID:   clientID,
		Generation: generation,
		IssuedAt:   time.Now(),
		Revoked:    false,
	}

	metaData, err := json.Marshal(toRefreshTokenFamilyJSON(familyMeta))
	if err != nil {
		return fmt.Errorf("failed to marshal family metadata: %w", err)
	}

	metaKey := s.refreshTokenMetaKey(refreshToken)
	if err := s.client.Do(
		ctx,
		s.client.B().Set().Key(metaKey).Value(string(metaData)).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save family metadata: %w", err)
	}
	return nil
}

// The marker shares the family set so revocation and member admission are atomic.
const familyRevocationMarker = "!revoked"

const luaAddActiveFamilyToken = `
if redis.call('SISMEMBER', KEYS[1], ARGV[4]) == 1 then
    return 'FAMILY_REVOKED'
end
` + luaAtomicSaddExtendOnlyTTL

// addTokenToFamilySet admits a token only while its family is not revoked.
func (s *Store) addTokenToFamilySet(ctx context.Context, refreshToken, familyID string, ttl time.Duration) error {
	horizon, fallback := s.extendOnlyTTLArgs(ttl)
	result, err := s.client.Do(ctx, s.client.B().Eval().Script(luaAddActiveFamilyToken).
		Numkeys(1).Key(s.familyKey(familyID)).Arg(refreshToken).
		Arg(fmt.Sprintf("%d", horizon)).Arg(fmt.Sprintf("%d", fallback)).Arg(familyRevocationMarker).Build()).ToString()
	if err != nil {
		return fmt.Errorf("add refresh token to family: %w", err)
	}
	if result == "FAMILY_REVOKED" {
		return storage.ErrRefreshTokenFamilyRevoked
	}
	return nil
}

// saveRefreshTokenMetadata saves token metadata for revocation tracking.
// If metadata already exists for this token (e.g., set earlier by saveTokenMetadata),
// the existing entry is preserved via SET NX. Otherwise a minimal entry is created.
func (s *Store) saveRefreshTokenMetadata(ctx context.Context, refreshToken, userID, clientID, familyID string, ttl time.Duration) error {
	tokenMeta := &storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: nsRefresh,
		FamilyID:  familyID,
	}

	tokenMetaData, err := json.Marshal(toTokenMetadataJSON(tokenMeta))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	tokenMetaKey := s.tokenMetaKey(refreshToken)
	if err := s.client.Do(
		ctx,
		s.client.B().Set().Key(tokenMetaKey).Value(string(tokenMetaData)).Nx().Ex(ttl).Build(),
	).Error(); err != nil {
		if isNilError(err) {
			s.logger.Debug("Token metadata already exists (NX not set), preserving richer entry",
				"token", safeTruncate(refreshToken, tokenIDLogLength))
		} else {
			return fmt.Errorf("failed to save refresh token metadata: %w", err)
		}
	}
	return nil
}

// addTokenToUserClientSet adds the token to the user+client set for bulk
// revocation, keeping the set bounded with an extend-only TTL.
func (s *Store) addTokenToUserClientSet(ctx context.Context, refreshToken, userID, clientID string, ttl time.Duration) {
	s.addToUserClientSet(ctx, userID, clientID, refreshToken, ttl)
}

// digestMemberPrefix marks a user+client member that is the digest of a token
// rather than the token itself (see userClientMember).
const digestMemberPrefix = "sha256:"

// userClientMember is the user+client member for a token. An id_token is an
// upstream JWT forwarded as a bearer: bulk revocation only needs to delete its
// metadata, which is keyed by the token's digest, so the set holds the digest
// and never the credential. Every other token is its own member: revocation
// resolves it at the provider and in the server's token-pair registry.
func userClientMember(tokenID, tokenType string) string {
	if tokenType == "id" {
		return digestMemberPrefix + hashKeyComponent(tokenID)
	}
	return tokenID
}

// addToUserClientSet adds member to the user+client sorted set that backs bulk
// revocation, scored by its expiry, and prunes the members that have expired.
// See saddExtendOnlyTTL for the TTL rule, which the set keeps.
func (s *Store) addToUserClientSet(ctx context.Context, userID, clientID, member string, ttl time.Duration) {
	horizon, fallback := s.extendOnlyTTLArgs(ttl)
	now := time.Now().Unix()
	score := "+inf"
	if horizon > 0 {
		score = fmt.Sprintf("%d", now+horizon)
	}
	if err := s.client.Do(
		ctx,
		s.client.B().Eval().Script(luaAtomicZaddPruneExtendOnlyTTL).
			Numkeys(1).
			Key(s.userClientKey(userID, clientID)).
			Arg(member).
			Arg(fmt.Sprintf("%d", horizon)).
			Arg(fmt.Sprintf("%d", fallback)).
			Arg(fmt.Sprintf("%d", now)).
			Arg(score).
			Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to user+client set",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
	}
}

// saddExtendOnlyTTL atomically adds member to a revocation set and keeps the set
// bounded with an extend-only TTL (see luaAtomicSaddExtendOnlyTTL for the full
// rationale). ttl is the member's own horizon. A set that already expires keeps
// max(existing, ttl), so it is never shortened below a still-live member; a set
// with no expiry is bounded at ttl, or at the store's refresh-token TTL when
// ttl is non-positive because the member has no or an expired horizon.
func (s *Store) saddExtendOnlyTTL(ctx context.Context, key, member string, ttl time.Duration) error {
	horizon, fallback := s.extendOnlyTTLArgs(ttl)
	return s.client.Do(
		ctx,
		s.client.B().Eval().Script(luaAtomicSaddExtendOnlyTTL).
			Numkeys(1).
			Key(key).
			Arg(member).
			Arg(fmt.Sprintf("%d", horizon)).
			Arg(fmt.Sprintf("%d", fallback)).
			Build(),
	).Error()
}

// extendOnlyTTLArgs converts a member's ttl into the extend-only scripts'
// horizon (whole seconds, 0 when unknown or expired) and fallback bound (the
// store's refresh-token TTL, at least 1).
func (s *Store) extendOnlyTTLArgs(ttl time.Duration) (horizon, fallback int64) {
	if ttl > 0 {
		// valkey EXPIRE with 0 seconds deletes the key, so never let a positive
		// sub-second horizon truncate to 0 and wipe the set.
		horizon = ceilSeconds(ttl)
	}
	if fallback = int64(s.refreshTokenTTL.Seconds()); fallback < 1 {
		fallback = 1
	}
	return horizon, fallback
}

// GetRefreshTokenFamily retrieves family metadata for a refresh token.
//
// Deliberately NO legacyRefreshTokenMetaKey fallback: this lookup is the
// ACCUSING half of reuse detection (server.handleRefreshTokenReuseDetection
// escalates "refresh-token record gone but family alive" to a full
// user+client revocation). The unified layout is a hard cutover in which
// GetRefreshTokenInfo and the atomic consume never read legacy-format keys,
// so a leftover pre-key-hashing refresh token always resolves as not-found
// there; if THIS lookup still saw the live legacy family metadata, that
// benign leftover would be misclassified as token theft. Without the
// fallback the leftover classifies as family-less → plain invalid_grant →
// re-login.
func (s *Store) GetRefreshTokenFamily(ctx context.Context, refreshToken string) (result *storage.RefreshTokenFamilyMetadata, err error) {
	op := s.startTracedOp(ctx, "get_refresh_token_family")
	defer op.end(&err)

	result, err = getAndUnmarshal(op.ctx, s, s.refreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
	if err != nil || result.Revoked {
		return result, err
	}
	revoked, err := s.client.Do(op.ctx, s.client.B().Sismember().Key(s.familyKey(result.FamilyID)).Member(familyRevocationMarker).Build()).AsBool()
	if err != nil {
		return nil, fmt.Errorf("read refresh token family revocation: %w", err)
	}
	result.Revoked = revoked
	return result, nil
}

// GetRefreshTokenFamilyByID returns family metadata indexed by family ID.
// The family marker and any revoked member take precedence over live members.
// The marker remains authoritative when individual member metadata has expired.
// Returns ErrRefreshTokenFamilyNotFound when no family state remains.
func (s *Store) GetRefreshTokenFamilyByID(ctx context.Context, familyID string) (result *storage.RefreshTokenFamilyMetadata, err error) {
	op := s.startTracedOp(ctx, "get_refresh_token_family_by_id")
	defer op.end(&err)

	if familyID == "" {
		return nil, storage.ErrRefreshTokenFamilyNotFound
	}

	tokens, err := s.getFamilyTokens(op.ctx, familyID)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, storage.ErrRefreshTokenFamilyNotFound
	}
	markedRevoked := slices.Contains(tokens, familyRevocationMarker)
	family, err := s.readIndexedFamilyMetadata(op.ctx, tokens, markedRevoked)
	if err != nil {
		return nil, err
	}
	if family != nil {
		return family, nil
	}
	if markedRevoked {
		return &storage.RefreshTokenFamilyMetadata{FamilyID: familyID, Revoked: true}, nil
	}
	return nil, storage.ErrRefreshTokenFamilyNotFound
}

func (s *Store) readIndexedFamilyMetadata(ctx context.Context, tokens []string, markedRevoked bool) (*storage.RefreshTokenFamilyMetadata, error) {
	// Non-not-found errors (transport failures, unmarshal errors) are returned
	// immediately rather than silently falling through to ErrRefreshTokenFamilyNotFound.
	// Fail-closed is correct here: swallowing a storage error and returning
	// "family not found" would allow a compromised token family to appear legitimate.
	var live *storage.RefreshTokenFamilyMetadata
	for _, member := range s.readFamilyMembersMetadata(ctx, tokens) {
		if member.err != nil {
			if !errors.Is(member.err, storage.ErrRefreshTokenFamilyNotFound) {
				return nil, member.err
			}
			continue
		}
		meta := member.meta
		if meta == nil {
			continue
		}
		if meta.Revoked || markedRevoked {
			meta.Revoked = true
			return meta, nil
		}
		if live == nil {
			live = meta
		}
	}
	return live, nil
}

// familyMemberMetadata is the metadata read for one family member: meta is
// set when err is nil; err is ErrRefreshTokenFamilyNotFound when the member
// has metadata under neither key layout.
type familyMemberMetadata struct {
	token string
	meta  *storage.RefreshTokenFamilyMetadata
	err   error
}

// readFamilyMembersMetadata reads the metadata of every family member (the
// revocation marker excluded) in at most two pipelined batches, so the cost in
// round trips does not grow with the family: one batch reads the current-layout
// keys, and a second one reads the legacy keys of the members whose current key
// is missing. It is the batched form of readMemberFamilyMetadata. The result
// keeps the order of tokens.
func (s *Store) readFamilyMembersMetadata(ctx context.Context, tokens []string) []familyMemberMetadata {
	members := make([]familyMemberMetadata, 0, len(tokens))
	for _, token := range tokens {
		if token != familyRevocationMarker {
			members = append(members, familyMemberMetadata{token: token})
		}
	}
	missing := s.readMembersMetadataBatch(ctx, members, allMemberIndexes(len(members)), s.refreshTokenMetaKey)
	s.readMembersMetadataBatch(ctx, members, missing, s.legacyRefreshTokenMetaKey)
	return members
}

func allMemberIndexes(n int) []int {
	indexes := make([]int, n)
	for i := range indexes {
		indexes[i] = i
	}
	return indexes
}

// readMembersMetadataBatch reads the metadata key that keyOf names for each
// member at indexes, in one pipelined batch, and stores the outcome on the
// member. It returns the indexes of the members whose key is missing.
func (s *Store) readMembersMetadataBatch(ctx context.Context, members []familyMemberMetadata, indexes []int, keyOf func(string) string) []int {
	if len(indexes) == 0 {
		return nil
	}
	commands := make(valkeygo.Commands, len(indexes))
	for i, index := range indexes {
		commands[i] = s.client.B().Get().Key(keyOf(members[index].token)).Build()
	}
	var missing []int
	for i, result := range s.client.DoMulti(ctx, commands...) {
		member := &members[indexes[i]]
		member.meta, member.err = decodeResult(result, storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
		if errors.Is(member.err, storage.ErrRefreshTokenFamilyNotFound) {
			missing = append(missing, indexes[i])
		}
	}
	return missing
}

// readMemberFamilyMetadata reads one family member's metadata, falling back to
// the key layout written by pre-migration pods. It returns
// ErrRefreshTokenFamilyNotFound when the member has metadata under neither.
func (s *Store) readMemberFamilyMetadata(ctx context.Context, refreshToken string) (*storage.RefreshTokenFamilyMetadata, error) {
	meta, err := getAndUnmarshal(ctx, s, s.refreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
	if err == nil {
		return meta, nil
	}
	if !errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
		return nil, err
	}
	return getAndUnmarshal(ctx, s, s.legacyRefreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
}

// GetActiveRefreshTokenByFamily returns the most recent (highest generation)
// non-revoked refresh token for the family along with the owning client ID
// (storage.ActiveRefreshTokenByFamilyStore). Iterates the same Set used
// by GetRefreshTokenFamilyByID, fetches per-token metadata, and picks
// the highest-Generation entry whose Revoked flag is unset.
//
// Returns ErrRefreshTokenFamilyRevoked when the family is marked revoked or
// any reachable member is revoked. Returns ErrRefreshTokenFamilyNotFound when
// no family state remains.
func (s *Store) GetActiveRefreshTokenByFamily(ctx context.Context, familyID string) (refreshToken, clientID string, err error) {
	op := s.startTracedOp(ctx, "get_active_refresh_token_by_family")
	defer op.end(&err)

	if familyID == "" {
		return "", "", storage.ErrRefreshTokenFamilyNotFound
	}

	tokens, err := s.getFamilyTokens(op.ctx, familyID)
	if err != nil {
		return "", "", err
	}
	if len(tokens) == 0 {
		return "", "", storage.ErrRefreshTokenFamilyNotFound
	}
	if slices.Contains(tokens, familyRevocationMarker) {
		return "", "", storage.ErrRefreshTokenFamilyRevoked
	}

	bestToken, bestClientID, anyRevoked := s.pickActiveMember(op.ctx, tokens)
	switch {
	case anyRevoked:
		return "", "", storage.ErrRefreshTokenFamilyRevoked
	case bestToken != "":
		return bestToken, bestClientID, nil
	default:
		return "", "", storage.ErrRefreshTokenFamilyNotFound
	}
}

// pickActiveMember walks the family member set and returns the
// highest-generation non-revoked token + its client ID. The third
// return value reports whether any reachable member is revoked, which the
// caller answers with ErrRefreshTokenFamilyRevoked ahead of any active
// member: the flag is family-wide, so one revoked member means the family
// was revoked and a non-revoked member beside it is a member the revocation
// walk did not reach.
func (s *Store) pickActiveMember(ctx context.Context, tokens []string) (token, clientID string, anyRevoked bool) {
	var bestGen int
	for _, member := range s.readFamilyMembersMetadata(ctx, tokens) {
		candidate, meta := member.token, member.meta
		if member.err != nil {
			if !errors.Is(member.err, storage.ErrRefreshTokenFamilyNotFound) {
				s.logger.Warn("pickActiveMember: storage error reading candidate metadata",
					"token_prefix", safeTruncate(candidate, tokenIDLogLength), "error", member.err)
			}
			continue
		}
		if meta == nil {
			continue
		}
		if meta.Revoked {
			anyRevoked = true
			continue
		}
		if token == "" || meta.Generation > bestGen {
			token = candidate
			clientID = meta.ClientID
			bestGen = meta.Generation
		}
	}
	return token, clientID, anyRevoked
}

// RevokeRefreshTokenFamily revokes all tokens in a family (for reuse detection)
// This is called when token reuse is detected (OAuth 2.1 security requirement)
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) (err error) {
	op := s.startTracedOp(ctx, "revoke_refresh_token_family")
	defer op.end(&err)
	if familyID == "" {
		return fmt.Errorf("family ID cannot be empty")
	}
	if err := s.saddExtendOnlyTTL(op.ctx, s.familyKey(familyID), familyRevocationMarker, s.revokedFamilyRetention()); err != nil {
		return fmt.Errorf("mark refresh token family revoked: %w", err)
	}

	tokens, err := s.getFamilyTokens(op.ctx, familyID)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}

	now := time.Now()
	revokedCount := 0
	unknownCount := 0
	var revocationError error

	for _, token := range tokens {
		if token == familyRevocationMarker {
			continue
		}
		outcome, memberError := s.revokeTokenInFamily(op.ctx, token, now)
		revocationError = errors.Join(revocationError, memberError)
		switch outcome {
		case familyMemberRevoked:
			revokedCount++
		case familyMemberUnknown:
			unknownCount++
		}
	}

	// The marker fences staged writes even when no member metadata remains.
	if revokedCount == 0 && unknownCount == 0 && revocationError == nil {
		s.logger.Info("Refresh token family walked but no member metadata was found",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"members", len(tokens))
		return nil
	}

	if unknownCount > 0 {
		revocationError = errors.Join(revocationError, fmt.Errorf("refresh token family revocation incomplete: %d members could not be updated", unknownCount))
	}
	if err := errors.Join(revocationError, s.retainRevokedFamilySet(op.ctx, familyID)); err != nil {
		return err
	}

	s.logger.Warn("Revoked refresh token family due to reuse detection",
		"family_id", safeTruncate(familyID, tokenIDLogLength),
		"tokens_revoked", revokedCount,
		"tokens_unknown", unknownCount)

	return nil
}

// revokedFamilyRetention is how long a revoked family's state is kept: both a
// member's revoked metadata and the family set that indexes it. One accessor for
// the two, because a set shorter than the metadata it indexes turns the
// revoked-family signal into not-found. New clamps the day count to the default
// when it is not positive, so the window is always at least a day.
func (s *Store) revokedFamilyRetention() time.Duration {
	return time.Duration(s.revokedFamilyRetentionDays) * 24 * time.Hour
}

// retainRevokedFamilySet holds the family set for the retention window that
// markFamilyMetadataRevoked applies to each member's metadata. The set is the
// by-family-ID index over that metadata, so it must live at least as long: an
// index that expires first turns the revoked-family signal into not-found,
// which GetActiveRefreshTokenByFamily and the self-issued JWT family check both
// read as legitimate absence.
//
// The set may outlive the metadata, when a member horizon longer than the
// window already bounds it. Both by-family-ID reads then walk it, find no
// metadata and return not-found, which is the correct answer.
//
// Both the hashed and the legacy key are extended, because getFamilyTokens
// unions the two.
func (s *Store) retainRevokedFamilySet(ctx context.Context, familyID string) error {
	retention := int64(s.revokedFamilyRetention().Seconds())
	var retentionError error
	// One call per key: the hashed and the legacy key differ in their last
	// component, so they can land in different cluster slots and a single
	// multi-key EVAL would be cross-slot.
	for _, key := range []string{s.familyKey(familyID), s.legacyFamilyKey(familyID)} {
		// luaExtendOnlyTTL only extends, and it is a no-op on a missing key, so
		// a family that has no legacy twin is untouched.
		if err := s.client.Do(
			ctx,
			s.client.B().Eval().Script(luaExtendOnlyTTL).
				Numkeys(1).
				Key(key).
				Arg(fmt.Sprintf("%d", retention)).
				Build(),
		).Error(); err != nil {
			retentionError = errors.Join(retentionError, err)
		}
	}
	return retentionError
}

// getFamilyTokens retrieves all tokens in a family.
func (s *Store) getFamilyTokens(ctx context.Context, familyID string) ([]string, error) {
	tokens, err := s.client.Do(ctx, s.client.B().Smembers().Key(s.familyKey(familyID)).Build()).AsStrSlice()
	if err != nil && !isNilError(err) {
		return nil, fmt.Errorf("failed to get family members: %w", err)
	}
	// Always union with the legacy set: during a rolling deploy both sets may have
	// members (old pods write to legacyFamilyKey, new pods to familyKey), and
	// revocation must cover all of them. Short-circuiting on len(tokens)>0 would
	// miss tokens issued by pre-migration pods. Same reasoning as getTokensForUserClient.
	legacyTokens, legacyErr := s.client.Do(ctx, s.client.B().Smembers().Key(s.legacyFamilyKey(familyID)).Build()).AsStrSlice()
	if legacyErr != nil && !isNilError(legacyErr) {
		return nil, fmt.Errorf("failed to get legacy family members: %w", legacyErr)
	}
	seen := make(map[string]struct{}, len(tokens)+len(legacyTokens))
	result := make([]string, 0, len(tokens)+len(legacyTokens))
	for _, t := range append(tokens, legacyTokens...) {
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			result = append(result, t)
		}
	}
	return result, nil
}

// familyMemberOutcome reports what a revocation walk established about one
// family member, which is what decides whether the family set still indexes
// anything.
type familyMemberOutcome int

const (
	// familyMemberAbsent: no metadata under either key layout.
	familyMemberAbsent familyMemberOutcome = iota
	// familyMemberRevoked: the revoked record was written and is retained.
	familyMemberRevoked
	// familyMemberUnknown: the metadata could not be read, parsed or written,
	// so the member is neither revoked nor known to be absent.
	familyMemberUnknown
)

// revokeTokenInFamily revokes a single token within a family. It reports what
// the member's metadata now holds, which is the state the family set indexes.
func (s *Store) revokeTokenInFamily(ctx context.Context, token string, now time.Time) (familyMemberOutcome, error) {
	tokenPrefix := safeTruncate(token, tokenIDLogLength)

	outcome := s.markFamilyMetadataRevoked(ctx, token, now, tokenPrefix)
	return outcome, s.deleteTokenKeys(ctx, token, tokenPrefix)
}

// markFamilyMetadataRevoked updates family metadata to mark as revoked. It
// reports whether the revoked record was written and is therefore retained for
// the revoked-family window, the member has no metadata at all, or the member's
// state could not be established.
func (s *Store) markFamilyMetadataRevoked(ctx context.Context, token string, now time.Time, tokenPrefix string) familyMemberOutcome {
	metaKey := s.refreshTokenMetaKey(token)
	data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
	if err != nil {
		if !isNilError(err) {
			s.logger.Warn("Failed to read family metadata for revocation, key may be unrevoked",
				"token_prefix", tokenPrefix, "error", err)
			return familyMemberUnknown
		}
		// Key not found under hashed format: try legacy key written by pre-migration pods.
		metaKey = s.legacyRefreshTokenMetaKey(token)
		data, err = s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
		if err != nil {
			if !isNilError(err) {
				s.logger.Warn("Failed to read legacy family metadata for revocation, key may be unrevoked",
					"token_prefix", tokenPrefix, "error", err)
				return familyMemberUnknown
			}
			return familyMemberAbsent
		}
	}

	var j refreshTokenFamilyJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		// No error field: a json.SyntaxError quotes the byte it stopped on, and
		// this value is token metadata. token_prefix names the key, which is
		// what an operator needs to find it.
		s.logger.Warn("Failed to parse family metadata for revocation, key may be unrevoked",
			"token_prefix", tokenPrefix)
		return familyMemberUnknown
	}

	j.Revoked = true
	j.RevokedAt = now.Unix()

	updatedData, _ := json.Marshal(&j)
	if err := s.client.Do(
		ctx,
		s.client.B().Set().Key(metaKey).Value(string(updatedData)).Ex(s.revokedFamilyRetention()).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to write revoked family metadata, key may be unrevoked",
			"token_prefix", tokenPrefix,
			"error", err)
		return familyMemberUnknown
	}
	return familyMemberRevoked
}

// deleteTokenKeys deletes all keys associated with a token.
// Both hashed (current) and legacy (pre-migration) key formats are deleted so
// that revocation works for tokens written by older pods during a rolling deploy.
func (s *Store) deleteTokenKeys(ctx context.Context, token, tokenPrefix string) error {
	if err := s.client.Do(ctx, s.client.B().Del().Key(
		s.refreshTokenKey(token), s.legacyRefreshTokenKey(token),
		s.tokenKey(token), s.legacyTokenKey(token),
		s.tokenMetaKey(token), s.legacyTokenMetaKey(token),
		s.tokenRefKey(token),
	).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete token keys during family revocation",
			"token_prefix", tokenPrefix, "error", err)
		return err
	}
	return nil
}

// deleteKey deletes a single key and logs any errors.
func (s *Store) deleteKey(ctx context.Context, key, description, tokenPrefix string) {
	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete "+description+" during family revocation",
			"token_prefix", tokenPrefix,
			"error", err)
	}
}

// ============================================================
// TokenRevocationStore Implementation
// ============================================================

// SaveTokenMetadata saves metadata for a token. Implements
// storage.TokenMetadataStore. IssuedAt and ExpiresAt are set by the caller
// and persisted as-is. When ExpiresAt is non-zero the key TTL is set
// accordingly so stale metadata is evicted automatically.
func (s *Store) SaveTokenMetadata(ctx context.Context, tokenID string, metadata storage.TokenMetadata) error {
	if err := validateTokenMetadataParams(tokenID, metadata); err != nil {
		return err
	}
	if metadata.FamilyID != "" {
		if metadata.TokenType == "access" || metadata.TokenType == "refresh" {
			horizon := metadata.ExpiresAt
			if metadata.RetainUntil.After(horizon) {
				horizon = metadata.RetainUntil
			}
			if err := s.addTokenToFamilySet(ctx, tokenID, metadata.FamilyID, calculateTTL(horizon)); err != nil {
				return err
			}
		}
	}

	data, err := json.Marshal(toTokenMetadataJSON(&metadata))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	if err := s.setTokenMetaKey(ctx, s.tokenMetaKey(tokenID), string(data), metadata.ExpiresAt); err != nil {
		return fmt.Errorf("failed to save token metadata: %w", err)
	}

	s.addToUserClientSet(ctx, metadata.UserID, metadata.ClientID,
		userClientMember(tokenID, metadata.TokenType), calculateTTL(metadata.ExpiresAt))

	s.logger.Debug("Saved token metadata",
		"token_type", metadata.TokenType,
		"user_id", metadata.UserID,
		"client_id", metadata.ClientID,
		"audience", metadata.Audience,
		"scopes", metadata.Scopes,
		"family_id", metadata.FamilyID)

	return nil
}

func validateTokenMetadataParams(tokenID string, metadata storage.TokenMetadata) error {
	if tokenID == "" || metadata.UserID == "" || metadata.ClientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
	}
	for _, identifier := range []string{tokenID, metadata.UserID, metadata.ClientID, metadata.FamilyID} {
		if err := validateInputLength(identifier); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) setTokenMetaKey(ctx context.Context, key, value string, expiresAt time.Time) error {
	if !expiresAt.IsZero() {
		if ttl := calculateTTL(expiresAt); ttl > 0 {
			return s.client.Do(ctx, s.client.B().Set().Key(key).Value(value).ExSeconds(int64(ttl.Seconds())).Build()).Error()
		}
	}
	return s.client.Do(ctx, s.client.B().Set().Key(key).Value(value).Build()).Error()
}

// GetTokenMetadata retrieves metadata for a token (including RFC 8707 audience).
//
// Absence is signaled with storage.ErrTokenNotFound so callers can
// distinguish "no such token" from transient storage failures without
// string-matching.
//
// Deliberately NO legacyTokenMetaKey fallback (same hard-cutover reasoning as
// GetRefreshTokenFamily): tokens whose records only exist under legacy-format
// keys are never accepted by the unified refresh grant or validation paths,
// so their metadata must classify as absent — invalid_grant / inactive —
// rather than lend a leftover credential the appearance of a live one.
func (s *Store) GetTokenMetadata(tokenID string) (result *storage.TokenMetadata, err error) {
	// The interface carries no context, so the operation's deadline is the only
	// bound on this read; without it an unresponsive Valkey would hold the
	// caller for as long as the outage lasts.
	op := s.startTracedOp(context.Background(), "get_token_metadata")
	defer op.end(&err)

	data, err := s.client.Do(op.ctx, s.client.B().Get().Key(s.tokenMetaKey(tokenID)).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("token metadata: %w", storage.ErrTokenNotFound)
		}
		return nil, fmt.Errorf("failed to get token metadata: %w", err)
	}

	var j tokenMetadataJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token metadata: %w", err)
	}

	return fromTokenMetadataJSON(&j), nil
}

// RevokeAllTokensForUserClient revokes all tokens (access + refresh) for a specific user+client combination.
// This implements the OAuth 2.1 requirement for authorization code reuse detection.
// Returns the number of tokens revoked and any error encountered.
func (s *Store) RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) (count int, err error) {
	op := s.startTracedOp(ctx, "revoke_all_tokens_for_user_client")
	defer op.end(&err)

	if err = s.validateRevocationParams(userID, clientID); err != nil {
		return 0, err
	}

	tokenIDs, err := s.getTokensForUserClient(op.ctx, userID, clientID)
	if err != nil {
		return 0, err
	}
	if len(tokenIDs) == 0 {
		return 0, nil
	}

	familyError := s.revokeFamiliesForTokens(op.ctx, tokenIDs)
	revokedCount, tokenError := s.revokeIndividualTokens(op.ctx, tokenIDs)
	if err := errors.Join(familyError, tokenError); err != nil {
		return revokedCount, err
	}
	if err := s.deleteUserClientSet(op.ctx, userID, clientID); err != nil {
		return revokedCount, err
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked all tokens for user+client",
			"user_id", userID,
			"client_id", clientID,
			"tokens_revoked", revokedCount,
			"reason", "authorization_code_reuse_detected")
	}

	return revokedCount, nil
}

// RevokeTokensForFamily revokes one refresh-token family and deletes every
// token issued to userID+clientID under it, leaving the user's other families
// intact. Implements storage.TokenFamilyRevocationStore.
//
// The family's members are picked from the user+client index by their token
// metadata BEFORE the family is revoked, because revoking deletes the refresh
// tokens' metadata the match reads.
func (s *Store) RevokeTokensForFamily(ctx context.Context, userID, clientID, familyID string) (count int, err error) {
	op := s.startTracedOp(ctx, "revoke_tokens_for_family")
	defer op.end(&err)

	if err = s.validateRevocationParams(userID, clientID); err != nil {
		return 0, err
	}
	if familyID == "" {
		return 0, fmt.Errorf("familyID cannot be empty")
	}

	members, err := s.getTokensForUserClient(op.ctx, userID, clientID)
	if err != nil {
		return 0, err
	}
	familyMembers := make([]string, 0, len(members))
	var memberError error
	for _, member := range members {
		memberFamily, err := s.memberFamilyID(op.ctx, member)
		memberError = errors.Join(memberError, err)
		if memberFamily == familyID {
			familyMembers = append(familyMembers, member)
		}
	}

	if err = errors.Join(memberError, s.RevokeRefreshTokenFamily(op.ctx, familyID)); err != nil {
		return 0, err
	}
	revokedMembers := make([]string, 0, len(familyMembers))
	for _, member := range familyMembers {
		if err := s.deleteTokenAndMetadata(op.ctx, member); err != nil {
			memberError = errors.Join(memberError, err)
			continue
		}
		revokedMembers = append(revokedMembers, member)
	}
	if err = errors.Join(memberError, s.removeUserClientMembers(op.ctx, userID, clientID, revokedMembers)); err != nil {
		return len(revokedMembers), err
	}

	if len(familyMembers) > 0 {
		s.logger.Warn("Revoked refresh token family and its tokens",
			"user_id", userID,
			"client_id", clientID,
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"tokens_revoked", len(familyMembers))
	}

	return len(familyMembers), nil
}

// memberFamilyID reads the family binding without treating unavailable metadata as absence.
func (s *Store) memberFamilyID(ctx context.Context, member string) (string, error) {
	key := s.tokenMetaKey(member)
	if digest, ok := strings.CutPrefix(member, digestMemberPrefix); ok {
		key = s.keyOf("meta", digest)
	}
	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return "", nil
		}
		return "", err
	}
	var j tokenMetadataJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return "", fmt.Errorf("invalid token family metadata")
	}
	return j.FamilyID, nil
}

// removeUserClientMembers removes members from the user+client index in every
// layout.
func (s *Store) removeUserClientMembers(ctx context.Context, userID, clientID string, members []string) error {
	if len(members) == 0 {
		return nil
	}
	errs := []error{s.client.Do(ctx, s.client.B().Zrem().Key(s.userClientKey(userID, clientID)).Member(members...).Build()).Error()}
	for _, key := range []string{s.setUserClientKey(userID, clientID), s.legacyUserClientKey(userID, clientID)} {
		errs = append(errs, s.client.Do(ctx, s.client.B().Srem().Key(key).Member(members...).Build()).Error())
	}
	return errors.Join(errs...)
}

// validateRevocationParams validates the user and client IDs for revocation.
func (s *Store) validateRevocationParams(userID, clientID string) error {
	if userID == "" || clientID == "" {
		return fmt.Errorf("userID and clientID cannot be empty")
	}
	if err := validateInputLength(userID); err != nil {
		return err
	}
	return validateInputLength(clientID)
}

// getTokensForUserClient retrieves every member of a user+client combination:
// the sorted set, the plain SET it replaced and the legacy (pre-key-hashing)
// SET, unioned and deduplicated. All three are always read: during a rolling
// deploy more than one may have members, and RevokeAllTokensForUserClient must
// revoke every token regardless of which pod issued it. The older reads are a
// no-op (empty result) once those keys have expired. Members include id_token
// digests (digestMemberPrefix).
func (s *Store) getTokensForUserClient(ctx context.Context, userID, clientID string) ([]string, error) {
	members, err := s.client.Do(ctx, s.client.B().Zrange().Key(s.userClientKey(userID, clientID)).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil && !isNilError(err) {
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}
	seen := make(map[string]struct{}, len(members))
	result := make([]string, 0, len(members))
	add := func(ids []string) {
		for _, id := range ids {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}
	add(members)
	for _, key := range []string{s.setUserClientKey(userID, clientID), s.legacyUserClientKey(userID, clientID)} {
		ids, err := s.client.Do(ctx, s.client.B().Smembers().Key(key).Build()).AsStrSlice()
		if err != nil && !isNilError(err) {
			return nil, fmt.Errorf("failed to get tokens for user+client (previous layout): %w", err)
		}
		add(ids)
	}
	return result, nil
}

// revokeFamiliesForTokens identifies and revokes all token families for the given tokens.
func (s *Store) revokeFamiliesForTokens(ctx context.Context, tokenIDs []string) error {
	familiesToRevoke, revocationError := s.identifyFamilies(ctx, tokenIDs)
	for familyID := range familiesToRevoke {
		if err := s.RevokeRefreshTokenFamily(ctx, familyID); err != nil {
			revocationError = errors.Join(revocationError, err)
		}
	}
	return revocationError
}

// identifyFamilies finds all family IDs for the given tokens.
func (s *Store) identifyFamilies(ctx context.Context, tokenIDs []string) (map[string]bool, error) {
	families := make(map[string]bool)
	var metadataError error
	for _, tokenID := range tokenIDs {
		if strings.HasPrefix(tokenID, digestMemberPrefix) {
			continue // an id_token belongs to no refresh-token family
		}
		data, err := s.client.Do(ctx, s.client.B().Get().Key(s.refreshTokenMetaKey(tokenID)).Build()).ToString()
		if err != nil && isNilError(err) {
			// Key not found under hashed format: try legacy key written by pre-migration pods.
			data, err = s.client.Do(ctx, s.client.B().Get().Key(s.legacyRefreshTokenMetaKey(tokenID)).Build()).ToString()
		}
		if err != nil {
			if !isNilError(err) {
				metadataError = errors.Join(metadataError, err)
			}
			continue
		}
		var j refreshTokenFamilyJSON
		if err := json.Unmarshal([]byte(data), &j); err != nil {
			metadataError = errors.Join(metadataError, fmt.Errorf("invalid refresh token family metadata"))
		} else if j.FamilyID != "" {
			families[j.FamilyID] = true
		}
	}
	return families, metadataError
}

// revokeIndividualTokens revokes individual tokens and returns the count.
func (s *Store) revokeIndividualTokens(ctx context.Context, tokenIDs []string) (int, error) {
	revokedCount := 0
	var revocationError error
	for _, tokenID := range tokenIDs {
		if err := s.deleteTokenAndMetadata(ctx, tokenID); err != nil {
			revocationError = errors.Join(revocationError, err)
			continue
		}
		revokedCount++
	}
	return revokedCount, revocationError
}

// deleteTokenAndMetadata deletes a token and all its associated metadata.
// Both hashed (current) and legacy (pre-migration) key formats are deleted. An
// id_token digest member deletes the metadata keyed by that digest.
func (s *Store) deleteTokenAndMetadata(ctx context.Context, tokenID string) error {
	if digest, ok := strings.CutPrefix(tokenID, digestMemberPrefix); ok {
		if err := s.client.Do(ctx, s.client.B().Del().Key(s.keyOf("meta", digest)).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete id_token metadata during user+client revocation", "error", err)
			return err
		}
		return nil
	}
	return s.deleteTokenKeys(ctx, tokenID, safeTruncate(tokenID, tokenIDLogLength))
}

// deleteUserClientSet deletes the user+client index in every layout.
func (s *Store) deleteUserClientSet(ctx context.Context, userID, clientID string) error {
	if err := s.client.Do(ctx, s.client.B().Del().Key(
		s.userClientKey(userID, clientID), s.setUserClientKey(userID, clientID), s.legacyUserClientKey(userID, clientID),
	).Build()).Error(); err != nil {
		return err
	}
	return nil
}

// GetTokensByUserClient retrieves all token IDs for a user+client combination,
// in every index layout, deduplicated (see getTokensForUserClient). This is
// used by Server.RevokeAllTokensForUserClient for provider-side revocation and
// in-process unregistration: a missing legacy token would stay unrevoked at the
// provider, and a token listed twice would be revoked twice, which some
// providers reject. id_token digests are left out: an id_token has no provider
// mapping and no registry entry, and the store's own
// RevokeAllTokensForUserClient deletes its metadata.
func (s *Store) GetTokensByUserClient(ctx context.Context, userID, clientID string) (tokens []string, err error) {
	op := s.startTracedOp(ctx, "get_tokens_by_user_client")
	defer op.end(&err)

	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("userID and clientID cannot be empty")
	}

	members, err := s.getTokensForUserClient(op.ctx, userID, clientID)
	if err != nil {
		return nil, err
	}
	tokens = make([]string, 0, len(members))
	for _, m := range members {
		if !strings.HasPrefix(m, digestMemberPrefix) {
			tokens = append(tokens, m)
		}
	}
	return tokens, nil
}
