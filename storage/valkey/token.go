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

// serializableToken is a JSON-serializable representation of oauth2.Token.
// This is necessary because oauth2.Token stores extra fields (like id_token)
// in a private 'raw' field that is not included in standard JSON marshaling.
// This struct explicitly captures and serializes the Extra fields.
type serializableToken struct {
	AccessToken  string                 `json:"access_token"`
	TokenType    string                 `json:"token_type,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	Expiry       time.Time              `json:"expiry,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

// SaveToken saves an oauth2.Token for a user with optional encryption at rest
func (s *Store) SaveToken(ctx context.Context, userID string, token *oauth2.Token) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	// Validate input lengths to prevent DoS
	if err := validateStringLength(userID, MaxIDLength, "userID"); err != nil {
		return err
	}

	// Encrypt token if encryptor is configured
	tokenToStore, err := s.encryptToken(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	// Extract extra fields for serialization (they're in a private field of oauth2.Token)
	// This is critical for preserving id_token and other OIDC fields
	extra := storage.ExtractTokenExtra(tokenToStore)

	// Create serializable struct that explicitly includes Extra fields
	st := serializableToken{
		AccessToken:  tokenToStore.AccessToken,
		TokenType:    tokenToStore.TokenType,
		RefreshToken: tokenToStore.RefreshToken,
		Expiry:       tokenToStore.Expiry,
		Extra:        extra,
	}

	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Validate serialized size
	if len(data) > MaxTokenDataSize {
		return errInputTooLarge
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

	enc := s.getEncryptor()
	if enc != nil && enc.IsEnabled() {
		s.logger.Debug("Saved encrypted token", "user_id", userID)
	} else {
		s.logger.Debug("Saved token", "user_id", userID)
	}
	return nil
}

// GetToken retrieves an oauth2.Token for a user and decrypts if necessary
func (s *Store) GetToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	key := s.tokenKey(userID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, storage.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Unmarshal into serializableToken to preserve Extra fields
	var st serializableToken
	if err := json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Reconstruct oauth2.Token from serializable struct
	token := &oauth2.Token{
		AccessToken:  st.AccessToken,
		TokenType:    st.TokenType,
		RefreshToken: st.RefreshToken,
		Expiry:       st.Expiry,
	}

	// Restore Extra fields (critical for id_token and other OIDC fields)
	if st.Extra != nil {
		token = token.WithExtra(st.Extra)
	}

	// Check if expired (and no refresh token to recover)
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) && token.RefreshToken == "" {
		return nil, storage.ErrTokenExpired
	}

	// Decrypt token if encryptor is configured
	decrypted, err := s.decryptToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	return decrypted, nil
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

	// Validate input lengths to prevent DoS
	if err := validateStringLength(refreshToken, MaxTokenLength, "refreshToken"); err != nil {
		return err
	}
	if err := validateStringLength(userID, MaxIDLength, "userID"); err != nil {
		return err
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

	// Parse the result JSON using serializableToken for proper Extra field handling
	var resultData struct {
		UserID string            `json:"user_id"`
		Token  serializableToken `json:"token"`
	}
	if err := json.Unmarshal([]byte(result), &resultData); err != nil {
		return "", nil, fmt.Errorf("failed to parse atomic operation result: %w", err)
	}

	// Reconstruct oauth2.Token from serializable struct
	token := &oauth2.Token{
		AccessToken:  resultData.Token.AccessToken,
		TokenType:    resultData.Token.TokenType,
		RefreshToken: resultData.Token.RefreshToken,
		Expiry:       resultData.Token.Expiry,
	}

	// Restore Extra fields (critical for id_token and other OIDC fields)
	if resultData.Token.Extra != nil {
		token = token.WithExtra(resultData.Token.Extra)
	}

	// Decrypt token if encryptor is configured
	decryptedToken, err := s.decryptToken(token)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	s.logger.Debug("Atomically retrieved and deleted refresh token", "user_id", resultData.UserID)
	return resultData.UserID, decryptedToken, nil
}

// isNilError checks if the error indicates a nil/not-found result from Valkey.
// Uses the valkey-go library's built-in nil detection for robustness.
func isNilError(err error) bool {
	return valkeygo.IsValkeyNil(err)
}
