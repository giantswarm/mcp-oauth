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
func (s *Store) SaveRefreshTokenWithFamily(ctx context.Context, refreshToken, userID, clientID, familyID string, generation int, expiresAt time.Time) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if familyID == "" {
		return fmt.Errorf("family ID cannot be empty")
	}

	// Calculate TTL
	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	// Save basic refresh token info (userID)
	refreshKey := s.refreshTokenKey(refreshToken)
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(refreshKey).Value(userID).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Save family metadata for reuse detection
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
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(metaKey).Value(string(metaData)).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save family metadata: %w", err)
	}

	// Add this token to the family set (for family-wide revocation)
	familySetKey := s.familyKey(familyID)
	if err := s.client.Do(ctx,
		s.client.B().Sadd().Key(familySetKey).Member(refreshToken).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to family set",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"error", err)
	}

	// Set TTL on family set (extends on each new token)
	if err := s.client.Do(ctx,
		s.client.B().Expire().Key(familySetKey).Seconds(int64(ttl.Seconds())).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to set TTL on family set",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"error", err)
	}

	// Save token metadata for revocation tracking (OAuth 2.1 code reuse detection)
	tokenMeta := &storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: "refresh",
	}

	tokenMetaData, err := json.Marshal(toTokenMetadataJSON(tokenMeta))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	tokenMetaKey := s.tokenMetaKey(refreshToken)
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(tokenMetaKey).Value(string(tokenMetaData)).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save token metadata: %w", err)
	}

	// Add token to user+client set (for bulk revocation)
	userClientKey := s.userClientKey(userID, clientID)
	if err := s.client.Do(ctx,
		s.client.B().Sadd().Key(userClientKey).Member(refreshToken).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to user+client set",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
	}

	s.logger.Debug("Saved refresh token with family tracking",
		"user_id", userID,
		"family_id", safeTruncate(familyID, tokenIDLogLength),
		"generation", generation,
		"expires_at", expiresAt)

	return nil
}

// GetRefreshTokenFamily retrieves family metadata for a refresh token
func (s *Store) GetRefreshTokenFamily(ctx context.Context, refreshToken string) (*storage.RefreshTokenFamilyMetadata, error) {
	metaKey := s.refreshTokenMetaKey(refreshToken)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, storage.ErrRefreshTokenFamilyNotFound
		}
		return nil, fmt.Errorf("failed to get family metadata: %w", err)
	}

	var j refreshTokenFamilyJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal family metadata: %w", err)
	}

	return fromRefreshTokenFamilyJSON(&j), nil
}

// RevokeRefreshTokenFamily revokes all tokens in a family (for reuse detection)
// This is called when token reuse is detected (OAuth 2.1 security requirement)
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	familySetKey := s.familyKey(familyID)

	// Get all tokens in the family
	tokens, err := s.client.Do(ctx, s.client.B().Smembers().Key(familySetKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			// Family doesn't exist or is empty
			return nil
		}
		return fmt.Errorf("failed to get family members: %w", err)
	}

	revokedCount := 0
	now := time.Now()

	for _, token := range tokens {
		tokenPrefix := safeTruncate(token, tokenIDLogLength)

		// Update family metadata to mark as revoked
		metaKey := s.refreshTokenMetaKey(token)

		data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
		if err == nil {
			var j refreshTokenFamilyJSON
			if err := json.Unmarshal([]byte(data), &j); err == nil {
				j.Revoked = true
				j.RevokedAt = now.Unix()

				updatedData, _ := json.Marshal(&j)
				// Keep metadata for forensics with retention TTL
				retentionTTL := time.Duration(s.revokedFamilyRetentionDays) * 24 * time.Hour
				if err := s.client.Do(ctx,
					s.client.B().Set().Key(metaKey).Value(string(updatedData)).Ex(retentionTTL).Build(),
				).Error(); err != nil {
					s.logger.Debug("Failed to update family metadata during revocation",
						"token_prefix", tokenPrefix,
						"error", err)
				}
			}
		}

		// Delete the refresh token itself
		refreshKey := s.refreshTokenKey(token)
		if err := s.client.Do(ctx, s.client.B().Del().Key(refreshKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete refresh token during family revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		// Delete the associated provider token
		tokenKey := s.tokenKey(token)
		if err := s.client.Do(ctx, s.client.B().Del().Key(tokenKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete provider token during family revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		// Delete token metadata
		tokenMetaKey := s.tokenMetaKey(token)
		if err := s.client.Do(ctx, s.client.B().Del().Key(tokenMetaKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete token metadata during family revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		revokedCount++
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked refresh token family due to reuse detection",
			"family_id", safeTruncate(familyID, tokenIDLogLength),
			"tokens_revoked", revokedCount)
	}

	return nil
}

// ============================================================
// TokenRevocationStore Implementation
// ============================================================

// SaveTokenMetadata saves metadata for a token (for revocation tracking)
func (s *Store) SaveTokenMetadata(tokenID, userID, clientID, tokenType string) error {
	return s.SaveTokenMetadataWithAudience(tokenID, userID, clientID, tokenType, "")
}

// SaveTokenMetadataWithAudience saves metadata for a token including RFC 8707 audience
func (s *Store) SaveTokenMetadataWithAudience(tokenID, userID, clientID, tokenType, audience string) error {
	return s.SaveTokenMetadataWithScopesAndAudience(tokenID, userID, clientID, tokenType, audience, nil)
}

// SaveTokenMetadataWithScopesAndAudience saves metadata for a token including RFC 8707 audience and MCP 2025-11-25 scopes
func (s *Store) SaveTokenMetadataWithScopesAndAudience(tokenID, userID, clientID, tokenType, audience string, scopes []string) error {
	if tokenID == "" || userID == "" || clientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
	}

	ctx := context.Background()

	meta := &storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: tokenType,
		Audience:  audience,
		Scopes:    scopes,
	}

	data, err := json.Marshal(toTokenMetadataJSON(meta))
	if err != nil {
		return fmt.Errorf("failed to marshal token metadata: %w", err)
	}

	metaKey := s.tokenMetaKey(tokenID)

	if err := s.client.Do(ctx,
		s.client.B().Set().Key(metaKey).Value(string(data)).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save token metadata: %w", err)
	}

	// Add to user+client set
	userClientKey := s.userClientKey(userID, clientID)
	if err := s.client.Do(ctx,
		s.client.B().Sadd().Key(userClientKey).Member(tokenID).Build(),
	).Error(); err != nil {
		s.logger.Warn("Failed to add token to user+client set",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
	}

	s.logger.Debug("Saved token metadata",
		"token_type", tokenType,
		"user_id", userID,
		"client_id", clientID,
		"audience", audience,
		"scopes", scopes)

	return nil
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
func (s *Store) RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" || clientID == "" {
		return 0, fmt.Errorf("userID and clientID cannot be empty")
	}

	userClientKey := s.userClientKey(userID, clientID)

	// Get all token IDs for this user+client
	tokenIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(userClientKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			return 0, nil // No tokens to revoke
		}
		return 0, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}

	revokedCount := 0
	familiesToRevoke := make(map[string]bool)

	// First pass: identify all families that need to be revoked
	for _, tokenID := range tokenIDs {
		// Get family metadata to find family ID
		metaKey := s.refreshTokenMetaKey(tokenID)
		data, err := s.client.Do(ctx, s.client.B().Get().Key(metaKey).Build()).ToString()
		if err == nil {
			var j refreshTokenFamilyJSON
			if err := json.Unmarshal([]byte(data), &j); err == nil && j.FamilyID != "" {
				familiesToRevoke[j.FamilyID] = true
			}
		}
	}

	// Revoke entire families
	for familyID := range familiesToRevoke {
		if err := s.RevokeRefreshTokenFamily(ctx, familyID); err != nil {
			s.logger.Warn("Failed to revoke token family",
				"family_id", safeTruncate(familyID, tokenIDLogLength),
				"error", err)
		}
	}

	// Second pass: revoke any remaining tokens (access tokens, tokens without families)
	for _, tokenID := range tokenIDs {
		tokenPrefix := safeTruncate(tokenID, tokenIDLogLength)

		// Delete token
		tokenKey := s.tokenKey(tokenID)
		if err := s.client.Do(ctx, s.client.B().Del().Key(tokenKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete token during user+client revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		// Delete refresh token if exists
		refreshKey := s.refreshTokenKey(tokenID)
		if err := s.client.Do(ctx, s.client.B().Del().Key(refreshKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete refresh token during user+client revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		// Delete token metadata
		metaKey := s.tokenMetaKey(tokenID)
		if err := s.client.Do(ctx, s.client.B().Del().Key(metaKey).Build()).Error(); err != nil {
			s.logger.Debug("Failed to delete token metadata during user+client revocation",
				"token_prefix", tokenPrefix,
				"error", err)
		}

		revokedCount++
	}

	// Delete the user+client set
	if err := s.client.Do(ctx, s.client.B().Del().Key(userClientKey).Build()).Error(); err != nil {
		s.logger.Warn("Failed to delete user+client set",
			"user_id", userID,
			"client_id", clientID,
			"error", err)
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

// GetTokensByUserClient retrieves all token IDs for a user+client combination.
// This is primarily for testing and debugging purposes.
func (s *Store) GetTokensByUserClient(ctx context.Context, userID, clientID string) ([]string, error) {
	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("userID and clientID cannot be empty")
	}

	userClientKey := s.userClientKey(userID, clientID)

	tokens, err := s.client.Do(ctx, s.client.B().Smembers().Key(userClientKey).Build()).AsStrSlice()
	if err != nil {
		if isNilError(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get tokens for user+client: %w", err)
	}

	return tokens, nil
}
