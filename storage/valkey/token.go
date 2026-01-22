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

// toSerializable converts an oauth2.Token to a serializableToken.
// This extracts the Extra fields (id_token, scope, etc.) that are stored
// in oauth2.Token's private 'raw' field and wouldn't be included in standard JSON marshaling.
func toSerializable(token *oauth2.Token) serializableToken {
	return serializableToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		Extra:        storage.ExtractTokenExtra(token),
	}
}

// toOAuth2Token converts a serializableToken back to an oauth2.Token.
// This restores the Extra fields using WithExtra(), which is the only way
// to populate oauth2.Token's private 'raw' field.
func (st serializableToken) toOAuth2Token() *oauth2.Token {
	token := &oauth2.Token{
		AccessToken:  st.AccessToken,
		TokenType:    st.TokenType,
		RefreshToken: st.RefreshToken,
		Expiry:       st.Expiry,
	}
	if st.Extra != nil {
		token = token.WithExtra(st.Extra)
	}
	return token
}

// SaveToken saves an oauth2.Token for a user with optional encryption at rest
func (s *Store) SaveToken(ctx context.Context, userID string, token *oauth2.Token) error {
	// Start span for tracing
	ctx, span := s.startStorageSpan(ctx, "save_token")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "save_token", err, startTime)
	}()

	if userID == "" {
		err = fmt.Errorf("userID cannot be empty")
		return err
	}
	if token == nil {
		err = fmt.Errorf("token cannot be nil")
		return err
	}

	// Validate input lengths to prevent DoS
	if err = validateStringLength(userID, MaxIDLength, "userID"); err != nil {
		return err
	}

	// Encrypt token if encryptor is configured
	tokenToStore, encErr := s.encryptToken(token)
	if encErr != nil {
		err = fmt.Errorf("failed to encrypt token: %w", encErr)
		return err
	}

	// Convert to serializable struct that explicitly includes Extra fields
	st := toSerializable(tokenToStore)

	data, marshalErr := json.Marshal(st)
	if marshalErr != nil {
		err = fmt.Errorf("failed to marshal token: %w", marshalErr)
		return err
	}

	// Validate serialized size
	if len(data) > MaxTokenDataSize {
		err = errInputTooLarge
		return err
	}

	key := s.tokenKey(userID)

	// Execute the appropriate command based on token expiry
	if !token.Expiry.IsZero() {
		ttl := calculateTTL(token.Expiry)
		if ttl <= 0 {
			// Token already expired, don't store
			err = fmt.Errorf("token already expired")
			return err
		}
		err = s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error()
	} else {
		err = s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error()
	}

	if err != nil {
		err = fmt.Errorf("failed to save token: %w", err)
		return err
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
	// Start span for tracing
	ctx, span := s.startStorageSpan(ctx, "get_token")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "get_token", err, startTime)
	}()

	key := s.tokenKey(userID)

	data, getErr := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if getErr != nil {
		if isNilError(getErr) {
			err = storage.ErrTokenNotFound
			return nil, err
		}
		err = fmt.Errorf("failed to get token: %w", getErr)
		return nil, err
	}

	// Unmarshal into serializableToken to preserve Extra fields
	var st serializableToken
	if unmarshalErr := json.Unmarshal([]byte(data), &st); unmarshalErr != nil {
		err = fmt.Errorf("failed to unmarshal token: %w", unmarshalErr)
		return nil, err
	}

	// Convert back to oauth2.Token (restores Extra fields like id_token)
	token := st.toOAuth2Token()

	// Check if expired (and no refresh token to recover)
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) && token.RefreshToken == "" {
		err = storage.ErrTokenExpired
		return nil, err
	}

	// Decrypt token if encryptor is configured
	decrypted, decErr := s.decryptToken(token)
	if decErr != nil {
		err = fmt.Errorf("failed to decrypt token: %w", decErr)
		return nil, err
	}

	return decrypted, nil
}

// DeleteToken removes a token for a user
func (s *Store) DeleteToken(ctx context.Context, userID string) error {
	// Start span for tracing
	ctx, span := s.startStorageSpan(ctx, "delete_token")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "delete_token", err, startTime)
	}()

	key := s.tokenKey(userID)

	if delErr := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); delErr != nil {
		err = fmt.Errorf("failed to delete token: %w", delErr)
		return err
	}

	s.logger.Debug("Deleted token", "user_id", userID)
	return nil
}

// SaveUserInfo saves user information
func (s *Store) SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error {
	// Start span for tracing
	ctx, span := s.startStorageSpan(ctx, "save_user_info")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "save_user_info", err, startTime)
	}()

	if userID == "" {
		err = fmt.Errorf("userID cannot be empty")
		return err
	}
	if info == nil {
		err = fmt.Errorf("userInfo cannot be nil")
		return err
	}

	data, marshalErr := json.Marshal(toUserInfoJSON(info))
	if marshalErr != nil {
		err = fmt.Errorf("failed to marshal user info: %w", marshalErr)
		return err
	}

	key := s.userInfoKey(userID)

	if setErr := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error(); setErr != nil {
		err = fmt.Errorf("failed to save user info: %w", setErr)
		return err
	}

	return nil
}

// GetUserInfo retrieves user information
func (s *Store) GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error) {
	// Start span for tracing
	ctx, span := s.startStorageSpan(ctx, "get_user_info")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "get_user_info", err, startTime)
	}()

	key := s.userInfoKey(userID)

	data, getErr := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if getErr != nil {
		if isNilError(getErr) {
			err = fmt.Errorf("%w: %s", storage.ErrUserInfoNotFound, userID)
			return nil, err
		}
		err = fmt.Errorf("failed to get user info: %w", getErr)
		return nil, err
	}

	var j userInfoJSON
	if unmarshalErr := json.Unmarshal([]byte(data), &j); unmarshalErr != nil {
		err = fmt.Errorf("failed to unmarshal user info: %w", unmarshalErr)
		return nil, err
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
// Returns the userID, clientID, and provider token if successful.
//
// SECURITY: This operation is atomic via Lua script - only ONE concurrent request can succeed.
// SECURITY: Returns clientID for client binding validation per OAuth 2.1 Section 6.
func (s *Store) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (string, string, *oauth2.Token, error) {
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
		return "", "", nil, fmt.Errorf("failed to execute atomic refresh token operation: %w", err)
	}

	switch result {
	case "NOT_FOUND":
		return "", "", nil, fmt.Errorf("%w: "+storage.ErrMsgRefreshTokenNotFoundOrUsed, storage.ErrTokenNotFound)
	case "EXPIRED":
		return "", "", nil, fmt.Errorf("%w: refresh token expired", storage.ErrTokenExpired)
	case "TOKEN_NOT_FOUND":
		return "", "", nil, fmt.Errorf("%w: provider token not found", storage.ErrTokenNotFound)
	}

	// Parse the result JSON using serializableToken for proper Extra field handling
	var resultData struct {
		UserID   string            `json:"user_id"`
		ClientID string            `json:"client_id"`
		Token    serializableToken `json:"token"`
	}
	if err := json.Unmarshal([]byte(result), &resultData); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse atomic operation result: %w", err)
	}

	// Convert back to oauth2.Token (restores Extra fields like id_token)
	token := resultData.Token.toOAuth2Token()

	// Decrypt token if encryptor is configured
	decryptedToken, err := s.decryptToken(token)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	s.logger.Debug("Atomically retrieved and deleted refresh token",
		"user_id", resultData.UserID,
		"client_id", resultData.ClientID)
	return resultData.UserID, resultData.ClientID, decryptedToken, nil
}

// isNilError checks if the error indicates a nil/not-found result from Valkey.
// Uses the valkey-go library's built-in nil detection for robustness.
func isNilError(err error) bool {
	return valkeygo.IsValkeyNil(err)
}
