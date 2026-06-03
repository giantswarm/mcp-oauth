package valkey

import (
	"context"
	"encoding/json"
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

	s.addTokenToUserClientSet(op.ctx, refreshToken, userID, clientID)

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
	return nil
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

// addTokenToFamilySet adds the token to the family set for family-wide revocation.
func (s *Store) addTokenToFamilySet(ctx context.Context, refreshToken, familyID string, ttl time.Duration) {
	familySetKey := s.familyKey(familyID)
	if err := s.client.Do(
		ctx,
		s.client.B().Sadd().Key(familySetKey).Member(refreshToken).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to family set",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"error", err)
	}

	if err := s.client.Do(
		ctx,
		s.client.B().Expire().Key(familySetKey).Seconds(int64(ttl.Seconds())).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to set TTL on family set",
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
		TokenType: "refresh",
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

// addTokenToUserClientSet adds the token to the user+client set for bulk revocation.
func (s *Store) addTokenToUserClientSet(ctx context.Context, refreshToken, userID, clientID string) {
	userClientKey := s.userClientKey(userID, clientID)
	if err := s.client.Do(
		ctx,
		s.client.B().Sadd().Key(userClientKey).Member(refreshToken).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to user+client set",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
	}
}

// GetRefreshTokenFamily retrieves family metadata for a refresh token
func (s *Store) GetRefreshTokenFamily(ctx context.Context, refreshToken string) (result *storage.RefreshTokenFamilyMetadata, err error) {
	op := s.startTracedOp(ctx, "get_refresh_token_family")
	defer op.end(&err)

	return getAndUnmarshal(op.ctx, s, s.refreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
}

// GetRefreshTokenFamilyByID returns family metadata indexed by family ID
// (storage.RefreshTokenFamilyByIDStore). Lookups read one member of the
// {prefix}family:{familyID} Set and follow it to the per-token metadata
// hash; the family fields (FamilyID, UserID, ClientID, Revoked,
// RevokedAt, IssuedAt) are identical across the Set's members so any
// member is representative.
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

	for _, refreshToken := range tokens {
		meta, err := getAndUnmarshal(op.ctx, s, s.refreshTokenMetaKey(refreshToken), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
		if err == nil && meta != nil {
			return meta, nil
		}
	}
	return nil, storage.ErrRefreshTokenFamilyNotFound
}

// GetActiveRefreshTokenByFamily returns the most recent (highest generation)
// non-revoked refresh token for the family along with the owning client ID
// (storage.ActiveRefreshTokenByFamilyStore). Iterates the same Set used
// by GetRefreshTokenFamilyByID, fetches per-token metadata, and picks
// the highest-Generation entry whose Revoked flag is unset.
//
// Returns ErrRefreshTokenFamilyNotFound when the Set is empty, or
// ErrRefreshTokenFamilyRevoked when entries exist but every reachable
// member's metadata is revoked.
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

	bestToken, bestClientID, anyMetaSeen := s.pickActiveMember(op.ctx, tokens)
	switch {
	case bestToken != "":
		return bestToken, bestClientID, nil
	case anyMetaSeen:
		return "", "", storage.ErrRefreshTokenFamilyRevoked
	default:
		return "", "", storage.ErrRefreshTokenFamilyNotFound
	}
}

// pickActiveMember walks the family member set and returns the
// highest-generation non-revoked token + its client ID. The third
// return value reports whether any parseable metadata was observed —
// used by the caller to distinguish "family revoked" (every member
// flagged Revoked) from "family not found" (no metadata reachable at
// all, e.g. retention-cleanup deleted it).
func (s *Store) pickActiveMember(ctx context.Context, tokens []string) (token, clientID string, anyMetaSeen bool) {
	var bestGen int
	for _, candidate := range tokens {
		meta, err := getAndUnmarshal(ctx, s, s.refreshTokenMetaKey(candidate), storage.ErrRefreshTokenFamilyNotFound, fromRefreshTokenFamilyJSON)
		if err != nil || meta == nil {
			continue
		}
		anyMetaSeen = true
		if meta.Revoked {
			continue
		}
		if token == "" || meta.Generation > bestGen {
			token = candidate
			clientID = meta.ClientID
			bestGen = meta.Generation
		}
	}
	return token, clientID, anyMetaSeen
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

	for _, token := range tokens {
		s.revokeTokenInFamily(op.ctx, token, now)
		revokedCount++
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked refresh token family due to reuse detection",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"tokens_revoked", revokedCount)
	}

	return nil
}

// getFamilyTokens retrieves all tokens in a family.
func (s *Store) getFamilyTokens(ctx context.Context, familyID string) ([]string, error) {
	familySetKey := s.familyKey(familyID)

	tokens, err := s.client.Do(ctx, s.client.B().Smembers().Key(familySetKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			return nil, nil // Family doesn't exist or is empty
		}
		return nil, fmt.Errorf("failed to get family members: %w", err)
	}
	return tokens, nil
}

// revokeTokenInFamily revokes a single token within a family.
func (s *Store) revokeTokenInFamily(ctx context.Context, token string, now time.Time) {
	tokenPrefix := safeTruncate(token, tokenIDLogLength)

	s.markFamilyMetadataRevoked(ctx, token, now, tokenPrefix)
	s.deleteTokenKeys(ctx, token, tokenPrefix)
}

// markFamilyMetadataRevoked updates family metadata to mark as revoked.
func (s *Store) markFamilyMetadataRevoked(ctx context.Context, token string, now time.Time, tokenPrefix string) {
	metaKey := s.refreshTokenMetaKey(token)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
	if err != nil {
		return
	}

	var j refreshTokenFamilyJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return
	}

	j.Revoked = true
	j.RevokedAt = now.Unix()

	updatedData, _ := json.Marshal(&j)
	retentionTTL := time.Duration(s.revokedFamilyRetentionDays) * 24 * time.Hour
	if err := s.client.Do(
		ctx,
		s.client.B().Set().Key(metaKey).Value(string(updatedData)).Ex(retentionTTL).Build(),
	).Error(); err != nil {
		s.logger.Debug("Failed to update family metadata during revocation",
			"token_prefix", tokenPrefix,
			"error", err)
	}
}

// deleteTokenKeys deletes all keys associated with a token.
func (s *Store) deleteTokenKeys(ctx context.Context, token, tokenPrefix string) {
	s.deleteKey(ctx, s.refreshTokenKey(token), "refresh token", tokenPrefix)
	s.deleteKey(ctx, s.tokenKey(token), "provider token", tokenPrefix)
	s.deleteKey(ctx, s.tokenMetaKey(token), "token metadata", tokenPrefix)
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
	if err := validateTokenMetadataArgs(tokenID, metadata); err != nil {
		return err
	}

	data, err := json.Marshal(toTokenMetadataJSON(&metadata))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	if err := s.setTokenMetaKey(ctx, s.tokenMetaKey(tokenID), string(data), metadata.ExpiresAt); err != nil {
		return fmt.Errorf("failed to save token metadata: %w", err)
	}

	userClientKey := s.userClientKey(metadata.UserID, metadata.ClientID)
	if err := s.client.Do(
		ctx,
		s.client.B().Sadd().Key(userClientKey).Member(tokenID).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to user+client set",
			"user_id", metadata.UserID,
			"client_id", metadata.ClientID,
			"error", err)
	}

	s.logger.Debug("Saved token metadata",
		"token_type", metadata.TokenType,
		"user_id", metadata.UserID,
		"client_id", metadata.ClientID,
		"audience", metadata.Audience,
		"scopes", metadata.Scopes,
		"family_id", metadata.FamilyID)

	return nil
}

func validateTokenMetadataArgs(tokenID string, metadata storage.TokenMetadata) error {
	if tokenID == "" || metadata.UserID == "" || metadata.ClientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
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

// GetTokenMetadata retrieves metadata for a token (including RFC 8707 audience)
func (s *Store) GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error) {
	ctx := context.Background()
	metaKey := s.tokenMetaKey(tokenID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("token metadata not found")
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
	return nil
}

// getTokensForUserClient retrieves all token IDs for a user+client combination.
func (s *Store) getTokensForUserClient(ctx context.Context, userID, clientID string) ([]string, error) {
	userClientKey := s.userClientKey(userID, clientID)
	tokenIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(userClientKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}
	return tokenIDs, nil
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
		metaKey := s.refreshTokenMetaKey(tokenID)
		data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
		if err == nil {
			var j refreshTokenFamilyJSON
			if err := json.Unmarshal([]byte(data), &j); err == nil && j.FamilyID != "" {
				families[j.FamilyID] = true
			}
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
func (s *Store) deleteTokenAndMetadata(ctx context.Context, tokenID string) {
	tokenPrefix := safeTruncate(tokenID, tokenIDLogLength)

	if err := s.client.Do(ctx, s.client.B().Del().Key(s.tokenKey(tokenID)).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete token during user+client revocation", "token_prefix", tokenPrefix, "error", err)
	}

	if err := s.client.Do(ctx, s.client.B().Del().Key(s.refreshTokenKey(tokenID)).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete refresh token during user+client revocation", "token_prefix", tokenPrefix, "error", err)
	}

	if err := s.client.Do(ctx, s.client.B().Del().Key(s.tokenMetaKey(tokenID)).Build()).Error(); err != nil {
		s.logger.Debug("Failed to delete token metadata during user+client revocation", "token_prefix", tokenPrefix, "error", err)
	}
}

// deleteUserClientSet deletes the user+client token set.
func (s *Store) deleteUserClientSet(ctx context.Context, userID, clientID string) {
	userClientKey := s.userClientKey(userID, clientID)
	if err := s.client.Do(ctx, s.client.B().Del().Key(userClientKey).Build()).Error(); err != nil {
		s.logger.Warn("Failed to delete user+client set", "user_id", userID, "client_id", clientID, "error", err)
	}
}

// GetTokensByUserClient retrieves all token IDs for a user+client combination.
// This is primarily for testing and debugging purposes.
func (s *Store) GetTokensByUserClient(ctx context.Context, userID, clientID string) (tokens []string, err error) {
	op := s.startTracedOp(ctx, "get_tokens_by_user_client")
	defer op.end(&err)

	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("userID and clientID cannot be empty")
	}

	userClientKey := s.userClientKey(userID, clientID)

	tokens, err = s.client.Do(op.ctx, s.client.B().Smembers().Key(userClientKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}

	return tokens, nil
}
