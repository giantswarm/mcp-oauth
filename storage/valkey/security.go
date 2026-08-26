package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

	s.addTokenToFamilySet(op.ctx, refreshToken, familyID, ttl)

	if err = s.saveRefreshTokenMetadata(op.ctx, refreshToken, userID, clientID, familyID, ttl); err != nil {
		return err
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

// addTokenToFamilySet adds the token to the family set for family-wide
// revocation, keeping the set bounded with an extend-only TTL.
//
// The set is the index RevokeRefreshTokenFamily walks, and each member's family
// metadata carries its own issuance horizon, so the set must outlive its
// longest-lived member. A member missing from the set is a member reuse
// detection still sees but revocation cannot reach.
func (s *Store) addTokenToFamilySet(ctx context.Context, refreshToken, familyID string, ttl time.Duration) {
	if err := s.saddExtendOnlyTTL(ctx, s.familyKey(familyID), refreshToken, ttl); err != nil {
		s.logger.Warn("Failed to add token to family set",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"error", err)
	}
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
	s.addToUserClientSet(ctx, s.userClientKey(userID, clientID), refreshToken, userID, clientID, ttl)
}

// addToUserClientSet adds member to the user+client set that backs bulk
// revocation. See saddExtendOnlyTTL for the TTL rule.
func (s *Store) addToUserClientSet(ctx context.Context, key, member, userID, clientID string, ttl time.Duration) {
	if err := s.saddExtendOnlyTTL(ctx, key, member, ttl); err != nil {
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
	horizon := int64(0)
	if ttl > 0 {
		// valkey EXPIRE with 0 seconds deletes the key, so never let a positive
		// sub-second horizon truncate to 0 and wipe the set.
		if horizon = int64(ttl.Seconds()); horizon < 1 {
			horizon = 1
		}
	}
	fallback := int64(s.refreshTokenTTL.Seconds())
	if fallback < 1 {
		fallback = 1
	}
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

	return getAndUnmarshal(op.ctx, s, s.refreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
}

// GetRefreshTokenFamilyByID returns family metadata indexed by family ID
// (storage.RefreshTokenFamilyByIDStore). Lookups walk the members of the
// {prefix}family:{familyID} Set and follow each to its per-token metadata.
//
// A revoked member wins: the Revoked flag is per member, so a family whose
// members disagree is a family whose revocation did not reach every member,
// and reporting it as live would re-admit the tokens RevokeRefreshTokenFamily
// was called to kill. Two states produce that disagreement: a member whose
// revoked write failed, and a rotation that raced the revocation and added a
// member after it. Both are answered revoked. The remaining fields (FamilyID,
// UserID, ClientID, IssuedAt) are identical across members, so any member
// carries them.
//
// The walk therefore runs to the first revoked member, or to the end of the
// Set for a live family. Set size is bounded by the rotations within one
// refresh-token horizon, the same bound GetActiveRefreshTokenByFamily walks.
//
// Returns ErrRefreshTokenFamilyNotFound when the Set is empty (also when
// the family was wiped by retention cleanup).
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

	// Non-not-found errors (transport failures, unmarshal errors) are returned
	// immediately rather than silently falling through to ErrRefreshTokenFamilyNotFound.
	// Fail-closed is correct here: swallowing a storage error and returning
	// "family not found" would allow a compromised token family to appear legitimate.
	var live *storage.RefreshTokenFamilyMetadata
	for _, refreshToken := range tokens {
		meta, err := s.readMemberFamilyMetadata(op.ctx, refreshToken)
		if err != nil {
			if !errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
				return nil, err
			}
			continue
		}
		if meta == nil {
			continue
		}
		if meta.Revoked {
			return meta, nil
		}
		if live == nil {
			live = meta
		}
	}
	if live != nil {
		return live, nil
	}
	return nil, storage.ErrRefreshTokenFamilyNotFound
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
// Returns ErrRefreshTokenFamilyRevoked when any reachable member is revoked,
// which is the whole family (only RevokeRefreshTokenFamily sets the flag, and
// it sets it on every member it reaches). A member added by a rotation that
// raced the revocation is therefore not handed back as active. Returns
// ErrRefreshTokenFamilyNotFound when no member's metadata is reachable at all.
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
	for _, candidate := range tokens {
		meta, err := s.readMemberFamilyMetadata(ctx, candidate)
		if err != nil {
			if !errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
				s.logger.Warn("pickActiveMember: storage error reading candidate metadata",
					"token_prefix", safeTruncate(candidate, tokenIDLogLength), "error", err)
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

	for _, token := range tokens {
		switch s.revokeTokenInFamily(op.ctx, token, now) {
		case familyMemberRevoked:
			revokedCount++
		case familyMemberUnknown:
			unknownCount++
		}
	}

	// The set indexes the members' revoked metadata, so drop the retention only
	// when every member is provably absent: both by-family-ID reads then fall
	// through to not-found off a walk that finds no metadata. A member whose
	// state we could not read or write is not absent, and retention is
	// fail-closed, so it holds the set too.
	if revokedCount == 0 && unknownCount == 0 {
		s.logger.Warn("Refresh token family walked but no member metadata was found",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"members", len(tokens))
		return nil
	}

	s.retainRevokedFamilySet(op.ctx, familyID)

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
func (s *Store) retainRevokedFamilySet(ctx context.Context, familyID string) {
	retention := int64(s.revokedFamilyRetention().Seconds())
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
			s.logger.Warn("Failed to extend family set TTL for revocation retention",
				"family_id", safeTruncate(familyID, tokenIDLogLength),
				"error", err)
		}
	}
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
func (s *Store) revokeTokenInFamily(ctx context.Context, token string, now time.Time) familyMemberOutcome {
	tokenPrefix := safeTruncate(token, tokenIDLogLength)

	outcome := s.markFamilyMetadataRevoked(ctx, token, now, tokenPrefix)
	s.deleteTokenKeys(ctx, token, tokenPrefix)
	return outcome
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
		s.logger.Warn("Failed to parse family metadata for revocation, key may be unrevoked",
			"token_prefix", tokenPrefix, "error", err)
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
func (s *Store) deleteTokenKeys(ctx context.Context, token, tokenPrefix string) {
	if err := s.client.Do(ctx, s.client.B().Del().Key(
		s.refreshTokenKey(token), s.legacyRefreshTokenKey(token),
		s.tokenKey(token), s.legacyTokenKey(token),
		s.tokenMetaKey(token), s.legacyTokenMetaKey(token),
		s.tokenRefKey(token),
	).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete token keys during family revocation",
			"token_prefix", tokenPrefix, "error", err)
	}
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
	if tokenID == "" || metadata.UserID == "" || metadata.ClientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
	}
	if err := validateInputLength(tokenID); err != nil {
		return err
	}
	if err := validateInputLength(metadata.UserID); err != nil {
		return err
	}
	if err := validateInputLength(metadata.ClientID); err != nil {
		return err
	}
	if metadata.FamilyID != "" {
		if err := validateInputLength(metadata.FamilyID); err != nil {
			return err
		}
	}

	data, err := json.Marshal(toTokenMetadataJSON(&metadata))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	if err := s.setTokenMetaKey(ctx, s.tokenMetaKey(tokenID), string(data), metadata.ExpiresAt); err != nil {
		return fmt.Errorf("failed to save token metadata: %w", err)
	}

	s.addToUserClientSet(ctx, s.userClientKey(metadata.UserID, metadata.ClientID), tokenID,
		metadata.UserID, metadata.ClientID, calculateTTL(metadata.ExpiresAt))

	s.logger.Debug("Saved token metadata",
		"token_type", metadata.TokenType,
		"user_id", metadata.UserID,
		"client_id", metadata.ClientID,
		"audience", metadata.Audience,
		"scopes", metadata.Scopes,
		"family_id", metadata.FamilyID)

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
func (s *Store) GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error) {
	ctx := context.Background()

	data, err := s.client.Do(ctx, s.client.B().Get().Key(s.tokenMetaKey(tokenID)).Build()).ToString()
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

	s.revokeFamiliesForTokens(op.ctx, tokenIDs)
	revokedCount := s.revokeIndividualTokens(op.ctx, tokenIDs)
	s.deleteUserClientSet(op.ctx, userID, clientID)

	if revokedCount > 0 {
		s.logger.Warn("Revoked all tokens for user+client",
			"user_id", userID,
			"client_id", clientID,
			"tokens_revoked", revokedCount,
			"reason", "authorization_code_reuse_detected")
	}

	return revokedCount, nil
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

// getTokensForUserClient retrieves all token IDs for a user+client combination.
// Both hashed (current) and legacy (pre-migration) sets are always read and
// unioned. Short-circuiting on the first non-empty result is intentionally
// avoided: during a rolling deploy both sets may have members, and
// RevokeAllTokensForUserClient must revoke every token regardless of which pod
// issued it. The second SMEMBERS is a no-op (empty result) once all legacy keys
// have expired after migration.
func (s *Store) getTokensForUserClient(ctx context.Context, userID, clientID string) ([]string, error) {
	tokenIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(s.userClientKey(userID, clientID)).Build()).AsStrSlice()
	if err != nil && !isNilError(err) {
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}
	legacyIDs, legacyErr := s.client.Do(ctx, s.client.B().Smembers().Key(s.legacyUserClientKey(userID, clientID)).Build()).AsStrSlice()
	if legacyErr != nil && !isNilError(legacyErr) {
		return nil, fmt.Errorf("failed to get tokens for user+client (legacy): %w", legacyErr)
	}
	seen := make(map[string]struct{}, len(tokenIDs)+len(legacyIDs))
	result := make([]string, 0, len(tokenIDs)+len(legacyIDs))
	for _, id := range append(tokenIDs, legacyIDs...) {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			result = append(result, id)
		}
	}
	return result, nil
}

// revokeFamiliesForTokens identifies and revokes all token families for the given tokens.
func (s *Store) revokeFamiliesForTokens(ctx context.Context, tokenIDs []string) {
	familiesToRevoke := s.identifyFamilies(ctx, tokenIDs)
	for familyID := range familiesToRevoke {
		if err := s.RevokeRefreshTokenFamily(ctx, familyID); err != nil {
			s.logger.Warn("Failed to revoke token family",
				"family_id", safeTruncate(familyID, tokenIDLogLength),
				"error", err)
		}
	}
}

// identifyFamilies finds all family IDs for the given tokens.
func (s *Store) identifyFamilies(ctx context.Context, tokenIDs []string) map[string]bool {
	families := make(map[string]bool)
	for _, tokenID := range tokenIDs {
		data, err := s.client.Do(ctx, s.client.B().Get().Key(s.refreshTokenMetaKey(tokenID)).Build()).ToString()
		if err != nil && isNilError(err) {
			// Key not found under hashed format: try legacy key written by pre-migration pods.
			data, err = s.client.Do(ctx, s.client.B().Get().Key(s.legacyRefreshTokenMetaKey(tokenID)).Build()).ToString()
		}
		if err != nil {
			if !isNilError(err) {
				s.logger.Warn("identifyFamilies: storage error, family may be missed during revocation",
					"token_prefix", safeTruncate(tokenID, tokenIDLogLength), "error", err)
			}
			continue
		}
		var j refreshTokenFamilyJSON
		if err := json.Unmarshal([]byte(data), &j); err == nil && j.FamilyID != "" {
			families[j.FamilyID] = true
		}
	}
	return families
}

// revokeIndividualTokens revokes individual tokens and returns the count.
func (s *Store) revokeIndividualTokens(ctx context.Context, tokenIDs []string) int {
	revokedCount := 0
	for _, tokenID := range tokenIDs {
		s.deleteTokenAndMetadata(ctx, tokenID)
		revokedCount++
	}
	return revokedCount
}

// deleteTokenAndMetadata deletes a token and all its associated metadata.
// Both hashed (current) and legacy (pre-migration) key formats are deleted.
func (s *Store) deleteTokenAndMetadata(ctx context.Context, tokenID string) {
	if err := s.client.Do(ctx, s.client.B().Del().Key(
		s.tokenKey(tokenID), s.legacyTokenKey(tokenID),
		s.refreshTokenKey(tokenID), s.legacyRefreshTokenKey(tokenID),
		s.tokenMetaKey(tokenID), s.legacyTokenMetaKey(tokenID),
		s.tokenRefKey(tokenID),
	).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete token keys during user+client revocation",
			"token_prefix", safeTruncate(tokenID, tokenIDLogLength),
			"error", err)
	}
}

// deleteUserClientSet deletes the user+client token set (both key formats).
func (s *Store) deleteUserClientSet(ctx context.Context, userID, clientID string) {
	if err := s.client.Do(ctx, s.client.B().Del().Key(
		s.userClientKey(userID, clientID), s.legacyUserClientKey(userID, clientID),
	).Build()).Error(); err != nil {
		s.logger.Warn("Failed to delete user+client set", "user_id", userID, "client_id", clientID, "error", err)
	}
}

// GetTokensByUserClient retrieves all token IDs for a user+client combination.
// Both hashed (current) and legacy (pre-migration) sets are unioned and deduplicated.
// This is used by Server.RevokeAllTokensForUserClient for provider-side revocation;
// missing legacy tokens would leave pre-migration tokens unrevoked at the provider.
func (s *Store) GetTokensByUserClient(ctx context.Context, userID, clientID string) (tokens []string, err error) {
	op := s.startTracedOp(ctx, "get_tokens_by_user_client")
	defer op.end(&err)

	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("userID and clientID cannot be empty")
	}

	// Union hashed (current) and legacy (pre-migration) sets. During a rolling
	// deploy both sets may have members; callers such as Server.RevokeAllTokensForUserClient
	// use this result for provider-side revocation and in-process unregistration,
	// so missing legacy tokens would leave pre-migration tokens unrevoked at the provider.
	// Deduplicate: a token written across both sets (edge case during rolling deploy) would
	// otherwise be double-revoked at the provider, which some providers reject, causing
	// checkProviderRevocationFailure to abort the local revocation step.
	tokens, err = s.client.Do(op.ctx, s.client.B().Smembers().Key(s.userClientKey(userID, clientID)).Build()).AsStrSlice()
	if err != nil && !isNilError(err) {
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}
	legacyTokens, legacyErr := s.client.Do(op.ctx, s.client.B().Smembers().Key(s.legacyUserClientKey(userID, clientID)).Build()).AsStrSlice()
	if legacyErr != nil && !isNilError(legacyErr) {
		return nil, fmt.Errorf("failed to get tokens for user+client (legacy): %w", legacyErr)
	}
	seen := make(map[string]struct{}, len(tokens)+len(legacyTokens))
	combined := make([]string, 0, len(tokens)+len(legacyTokens))
	for _, t := range append(tokens, legacyTokens...) {
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			combined = append(combined, t)
		}
	}
	if len(combined) == 0 {
		return []string{}, nil
	}
	return combined, nil
}
