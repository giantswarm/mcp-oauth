package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
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
func (s *Store) SaveToken(ctx context.Context, userID string, token *oauth2.Token) (err error) {
	op := s.startTracedOp(ctx, "save_token")
	defer op.end(&err)

	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if err = validateInputLength(userID); err != nil {
		return err
	}

	// Encrypt token if encryptor is configured
	tokenToStore, err := s.encryptToken(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	// Convert to serializable struct that explicitly includes Extra fields
	st := toSerializable(tokenToStore)

	data, err := json.Marshal(st) // #nosec G117 -- serializing the OAuth token (RFC 6749 access/refresh token) for persistence is this token store's purpose; the value is encrypted at rest by encryptToken above when an encryptor is configured, and written only to Valkey, never logged
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Validate serialized size
	if len(data) > s.maxTokenDataSize {
		return ErrInputTooLarge
	}

	if err = s.setTokenKeyWithDerivedTTL(op.ctx, s.tokenKey(userID), string(data), token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	if s.encryptor != nil && s.encryptor.IsEnabled() {
		s.logger.Debug("Saved encrypted token", "user_id_hash", helpers.HashForLogging(userID))
	} else {
		s.logger.Debug("Saved token", "user_id_hash", helpers.HashForLogging(userID))
	}
	return nil
}

// setTokenKeyWithDerivedTTL writes a serialized provider token, deriving the
// key TTL from the token's shape.
//
// Tokens with a RefreshToken use the configured refresh token TTL because
// token.Expiry reflects the short-lived upstream access token (e.g., 30
// minutes from Dex), not the lifetime of the MCP refresh token (e.g., 90
// days). Using the access token expiry as the key TTL would cause Valkey to
// evict the provider token while it can still be renewed, triggering false
// positive reuse detection.
func (s *Store) setTokenKeyWithDerivedTTL(ctx context.Context, key, data string, token *oauth2.Token) error {
	switch {
	case token.RefreshToken != "" && s.refreshTokenTTL > 0:
		return s.client.Do(ctx, s.client.B().Set().Key(key).Value(data).Ex(s.refreshTokenTTL).Build()).Error()
	case token.RefreshToken != "":
		return s.client.Do(ctx, s.client.B().Set().Key(key).Value(data).Build()).Error()
	case !token.Expiry.IsZero():
		ttl := calculateTTL(token.Expiry)
		if ttl <= 0 {
			return fmt.Errorf("token already expired")
		}
		return s.client.Do(ctx, s.client.B().Set().Key(key).Value(data).Ex(ttl).Build()).Error()
	default:
		return s.client.Do(ctx, s.client.B().Set().Key(key).Value(data).Build()).Error()
	}
}

// GetToken retrieves an oauth2.Token for a user and decrypts if necessary
func (s *Store) GetToken(ctx context.Context, userID string) (result *oauth2.Token, err error) {
	op := s.startTracedOp(ctx, "get_token")
	defer op.end(&err)

	data, err := s.client.Do(op.ctx, s.client.B().Get().Key(s.tokenKey(userID)).Build()).ToString()
	if err != nil && isNilError(err) {
		data, err = s.client.Do(op.ctx, s.client.B().Get().Key(s.legacyTokenKey(userID)).Build()).ToString()
	}
	if err != nil {
		if isNilError(err) {
			// Unified provider-token layout: the provider token is not stored
			// under this key directly. Resolve key → userID → shared provider
			// entry (storage.UserProviderTokenStore). A key that is not a
			// provider-token reference falls through to ErrTokenNotFound.
			if uid, refErr := s.GetProviderTokenRef(op.ctx, userID); refErr == nil {
				return s.GetUserProviderToken(op.ctx, uid)
			} else if !errors.Is(refErr, storage.ErrTokenNotFound) {
				return nil, refErr
			}
			return nil, storage.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Unmarshal into serializableToken to preserve Extra fields
	var st serializableToken
	if err = json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Convert back to oauth2.Token (restores Extra fields like id_token)
	token := st.toOAuth2Token()

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
func (s *Store) DeleteToken(ctx context.Context, userID string) (err error) {
	op := s.startTracedOp(ctx, "delete_token")
	defer op.end(&err)

	if err = s.client.Do(op.ctx, s.client.B().Del().Key(
		s.tokenKey(userID), s.legacyTokenKey(userID),
	).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	s.logger.Debug("Deleted token", "user_id", userID)
	return nil
}

// SaveUserInfo saves user information
func (s *Store) SaveUserInfo(ctx context.Context, userID string, info *storage.UserInfo) (err error) {
	op := s.startTracedOp(ctx, "save_user_info")
	defer op.end(&err)

	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if info == nil {
		return fmt.Errorf("userInfo cannot be nil")
	}
	if err = validateInputLength(userID); err != nil {
		return err
	}

	data, err := json.Marshal(toUserInfoJSON(info))
	if err != nil {
		return fmt.Errorf("failed to marshal user info: %w", err)
	}

	key := s.userInfoKey(userID)

	if err = s.client.Do(op.ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save user info: %w", err)
	}
	s.deleteKey(op.ctx, s.legacyUserInfoKey(userID), "legacy user info", safeTruncate(userID, tokenIDLogLength))

	return nil
}

// GetUserInfo retrieves user information
func (s *Store) GetUserInfo(ctx context.Context, userID string) (result *storage.UserInfo, err error) {
	op := s.startTracedOp(ctx, "get_user_info")
	defer op.end(&err)

	data, err := s.client.Do(op.ctx, s.client.B().Get().Key(s.userInfoKey(userID)).Build()).ToString()
	if err != nil && isNilError(err) {
		data, err = s.client.Do(op.ctx, s.client.B().Get().Key(s.legacyUserInfoKey(userID)).Build()).ToString()
	}
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("%w: %s", storage.ErrUserInfoNotFound, userID)
		}
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	var j userInfoJSON
	if err = json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	return fromUserInfoJSON(&j), nil
}

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
func (s *Store) SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) (err error) {
	op := s.startTracedOp(ctx, "save_refresh_token")
	defer op.end(&err)

	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if err = validateInputLength(refreshToken); err != nil {
		return err
	}
	if err = validateInputLength(userID); err != nil {
		return err
	}

	key := s.refreshTokenKey(refreshToken)

	// Store with TTL based on expiry
	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	if err = s.client.Do(op.ctx, s.client.B().Set().Key(key).Value(userID).Ex(ttl).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	s.logger.Debug("Saved refresh token", "user_id", userID, "expires_at", expiresAt)
	return nil
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token.
//
// It reads exactly the key the destructive counterpart
// (AtomicConsumeRefreshToken) checks — refreshTokenKey — and deliberately has
// NO legacyRefreshTokenKey fallback. This method serves as the
// non-destructive front check of the unified refresh grant
// (server.resolveRefreshGrant), and the unified layout is a hard cutover with
// no legacy read-fallback (v1.1.0 deploy note: leftover old-layout keys are
// never read). If this check accepted a legacy key that the consume script
// cannot see, a refresh grant would pass validation, burn the provider's
// single-use refresh rotation upstream, and then fail the atomic consume as
// NOT_FOUND — tripping reuse detection for a token that was never reused.
func (s *Store) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error) {
	return s.getUserIDByKey(ctx, "get_refresh_token_info", s.refreshTokenKey(refreshToken), "get refresh token info")
}

// DeleteRefreshToken removes a refresh token
func (s *Store) DeleteRefreshToken(ctx context.Context, refreshToken string) (err error) {
	op := s.startTracedOp(ctx, "delete_refresh_token")
	defer op.end(&err)

	if err = s.client.Do(op.ctx, s.client.B().Del().Key(
		s.refreshTokenKey(refreshToken), s.legacyRefreshTokenKey(refreshToken),
	).Build()).Error(); err != nil {
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
func (s *Store) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (resUserID, resClientID string, resToken *oauth2.Token, err error) {
	op := s.startTracedOp(ctx, "atomic_get_and_delete_refresh_token")
	defer op.end(&err)

	// Execute Lua script for atomic operation.
	result, err := s.runAtomicGetAndDelete(op.ctx,
		s.refreshTokenKey(refreshToken),
		s.tokenKey(refreshToken),
		s.tokenMetaKey(refreshToken))
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to execute atomic refresh token operation: %w", err)
	}
	// Legacy fallback for tokens written by pre-migration pods.
	if result == luaResultNotFound {
		result, err = s.runAtomicGetAndDelete(op.ctx,
			s.legacyRefreshTokenKey(refreshToken),
			s.legacyTokenKey(refreshToken),
			s.legacyTokenMetaKey(refreshToken))
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to execute atomic refresh token operation: %w", err)
		}
	}

	switch result {
	case luaResultNotFound:
		return "", "", nil, fmt.Errorf("%w: "+storage.ErrMsgRefreshTokenNotFoundOrUsed, storage.ErrTokenNotFound)
	case luaResultExpired:
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
	if err = json.Unmarshal([]byte(result), &resultData); err != nil {
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
