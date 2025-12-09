package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ============================================================
// TokenStore Implementation
// ============================================================

// SaveToken saves an oauth2.Token for a user
func (s *Store) SaveToken(ctx context.Context, userID string, token *oauth2.Token) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	key := s.tokenKey(userID)

	// Execute the appropriate command based on token expiry
	var execErr error
	if !token.Expiry.IsZero() {
		ttl := calculateTTL(token.Expiry)
		if ttl <= 0 {
			// Token already expired, don't store
			return fmt.Errorf("token already expired")
		}
		execErr = s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error()
	} else {
		execErr = s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error()
	}

	if execErr != nil {
		return fmt.Errorf("failed to save token: %w", execErr)
	}

	s.logger.Debug("Saved token", "user_id", userID)
	return nil
}

// GetToken retrieves an oauth2.Token for a user
func (s *Store) GetToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	key := s.tokenKey(userID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("%w: %s", storage.ErrTokenNotFound, userID)
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	var token oauth2.Token
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Check if expired (and no refresh token to recover)
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) && token.RefreshToken == "" {
		return nil, fmt.Errorf("%w: %s", storage.ErrTokenExpired, userID)
	}

	return &token, nil
}

// DeleteToken removes a token for a user
func (s *Store) DeleteToken(ctx context.Context, userID string) error {
	key := s.tokenKey(userID)

	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	s.logger.Debug("Deleted token", "user_id", userID)
	return nil
}

// SaveUserInfo saves user information
func (s *Store) SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if info == nil {
		return fmt.Errorf("userInfo cannot be nil")
	}

	data, err := json.Marshal(toUserInfoJSON(info))
	if err != nil {
		return fmt.Errorf("failed to marshal user info: %w", err)
	}

	key := s.userInfoKey(userID)

	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save user info: %w", err)
	}

	return nil
}

// GetUserInfo retrieves user information
func (s *Store) GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error) {
	key := s.userInfoKey(userID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("%w: %s", storage.ErrUserInfoNotFound, userID)
		}
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	var j userInfoJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	return fromUserInfoJSON(&j), nil
}

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
func (s *Store) SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}

	key := s.refreshTokenKey(refreshToken)

	// Store with TTL based on expiry
	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(userID).Ex(ttl).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	s.logger.Debug("Saved refresh token", "user_id", userID, "expires_at", expiresAt)
	return nil
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token
func (s *Store) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error) {
	key := s.refreshTokenKey(refreshToken)

	userID, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return "", storage.ErrTokenNotFound
		}
		return "", fmt.Errorf("failed to get refresh token info: %w", err)
	}

	// TTL is managed by Valkey, so if key exists, it's not expired
	return userID, nil
}

// DeleteRefreshToken removes a refresh token
func (s *Store) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	key := s.refreshTokenKey(refreshToken)

	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	s.logger.Debug("Deleted refresh token (rotation)")
	return nil
}

// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
// This prevents race conditions in refresh token rotation and reuse detection.
// Returns the userID and provider token if successful.
//
// SECURITY: This operation is atomic via Lua script - only ONE concurrent request can succeed.
func (s *Store) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (string, *oauth2.Token, error) {
	// Build key names for the Lua script
	refreshKey := s.refreshTokenKey(refreshToken)
	tokenKey := s.tokenKey(refreshToken)
	metaKey := s.tokenMetaKey(refreshToken)

	// Execute Lua script for atomic operation
	result, err := s.client.Do(ctx,
		s.client.B().Eval().Script(luaScriptAtomicGetAndDeleteRefresh).
			Numkeys(3).
			Key(refreshKey, tokenKey, metaKey).
			Arg(fmt.Sprintf("%d", time.Now().Unix())).
			Arg("-1"). // No separate expiry check, TTL handles it
			Build(),
	).ToString()

	if err != nil {
		return "", nil, fmt.Errorf("failed to execute atomic refresh token operation: %w", err)
	}

	switch result {
	case "NOT_FOUND":
		return "", nil, fmt.Errorf("%w: refresh token not found or already used", storage.ErrTokenNotFound)
	case "EXPIRED":
		return "", nil, fmt.Errorf("%w: refresh token expired", storage.ErrTokenExpired)
	case "TOKEN_NOT_FOUND":
		return "", nil, fmt.Errorf("%w: provider token not found", storage.ErrTokenNotFound)
	}

	// Parse the result JSON
	var resultData struct {
		UserID string        `json:"user_id"`
		Token  *oauth2.Token `json:"token"`
	}
	if err := json.Unmarshal([]byte(result), &resultData); err != nil {
		return "", nil, fmt.Errorf("failed to parse atomic operation result: %w", err)
	}

	s.logger.Debug("Atomically retrieved and deleted refresh token", "user_id", resultData.UserID)
	return resultData.UserID, resultData.Token, nil
}

// isNilError checks if the error indicates a nil/not-found result from Valkey.
// Uses the valkey-go library's built-in nil detection for robustness.
func isNilError(err error) bool {
	return valkeygo.IsValkeyNil(err)
}
