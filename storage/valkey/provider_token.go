package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// ============================================================
// UserProviderTokenStore Implementation
// ============================================================
//
// The shared per-user provider token lives in its own namespace
// ({prefix}providertoken:{sha256(userID)}), separate from the token:
// namespace that holds per-token copies written by pre-unification code.
// Access/refresh tokens resolve to the owning user through lightweight
// reference entries ({prefix}tokenref:{sha256(tokenID)} -> userID) instead
// of holding their own copy of the provider credential.

func (s *Store) userProviderTokenKey(userID string) string {
	return s.keyOf("providertoken", hashKeyComponent(userID))
}

func (s *Store) tokenRefKey(tokenID string) string {
	return s.keyOf("tokenref", hashKeyComponent(tokenID))
}

// SaveUserProviderToken writes the user's shared provider-token entry,
// replacing any previous value (storage.UserProviderTokenStore).
//
// The token's Expiry is persisted as-is (the provider's REAL expiry — later
// refresh coordination judges freshness on it). The Valkey key TTL is
// derived separately: entries with a refresh token live for the refresh
// token TTL because the provider can renew them long past the access token
// expiry; entries without one expire with the access token.
func (s *Store) SaveUserProviderToken(ctx context.Context, userID string, token *oauth2.Token) (err error) {
	op := s.startTracedOp(ctx, "save_user_provider_token")
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

	tokenToStore, err := s.encryptToken(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	st := toSerializable(tokenToStore)
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	if len(data) > s.maxTokenDataSize {
		return ErrInputTooLarge
	}

	if err = s.setTokenKeyWithDerivedTTL(op.ctx, s.userProviderTokenKey(userID), string(data), token); err != nil {
		return fmt.Errorf("failed to save shared provider token: %w", err)
	}

	s.logger.Debug("Saved shared provider token", "user_id", userID, "expiry", token.Expiry)
	return nil
}

// GetUserProviderToken returns the user's shared provider-token entry
// (storage.UserProviderTokenStore).
func (s *Store) GetUserProviderToken(ctx context.Context, userID string) (result *oauth2.Token, err error) {
	op := s.startTracedOp(ctx, "get_user_provider_token")
	defer op.end(&err)

	data, err := s.client.Do(op.ctx, s.client.B().Get().Key(s.userProviderTokenKey(userID)).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, storage.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get shared provider token: %w", err)
	}

	var st serializableToken
	if err = json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	token := st.toOAuth2Token()

	// An expired entry that still carries a refresh token is returned
	// normally — the caller refreshes it. Same contract as GetToken.
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) && token.RefreshToken == "" {
		return nil, storage.ErrTokenExpired
	}

	decrypted, err := s.decryptToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}
	return decrypted, nil
}

// DeleteUserProviderToken removes the user's shared provider-token entry
// (storage.UserProviderTokenStore).
func (s *Store) DeleteUserProviderToken(ctx context.Context, userID string) (err error) {
	op := s.startTracedOp(ctx, "delete_user_provider_token")
	defer op.end(&err)

	if err = s.client.Do(op.ctx, s.client.B().Del().Key(s.userProviderTokenKey(userID)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete shared provider token: %w", err)
	}
	s.logger.Debug("Deleted shared provider token", "user_id", userID)
	return nil
}

// SaveProviderTokenRef records that tokenID belongs to userID
// (storage.UserProviderTokenStore).
func (s *Store) SaveProviderTokenRef(ctx context.Context, tokenID, userID string, expiresAt time.Time) (err error) {
	op := s.startTracedOp(ctx, "save_provider_token_ref")
	defer op.end(&err)

	if tokenID == "" {
		return fmt.Errorf("tokenID cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if err = validateInputLength(userID); err != nil {
		return err
	}

	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("provider token reference already expired")
	}

	if err = s.client.Do(op.ctx, s.client.B().Set().Key(s.tokenRefKey(tokenID)).Value(userID).Ex(ttl).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save provider token reference: %w", err)
	}
	return nil
}

// GetProviderTokenRef resolves tokenID to the owning userID
// (storage.UserProviderTokenStore).
func (s *Store) GetProviderTokenRef(ctx context.Context, tokenID string) (userID string, err error) {
	op := s.startTracedOp(ctx, "get_provider_token_ref")
	defer op.end(&err)

	userID, err = s.client.Do(op.ctx, s.client.B().Get().Key(s.tokenRefKey(tokenID)).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return "", storage.ErrTokenNotFound
		}
		return "", fmt.Errorf("failed to get provider token reference: %w", err)
	}
	// TTL is managed by Valkey, so if the key exists it's not expired.
	return userID, nil
}

// DeleteProviderTokenRef removes the reference for tokenID
// (storage.UserProviderTokenStore).
func (s *Store) DeleteProviderTokenRef(ctx context.Context, tokenID string) (err error) {
	op := s.startTracedOp(ctx, "delete_provider_token_ref")
	defer op.end(&err)

	if err = s.client.Do(op.ctx, s.client.B().Del().Key(s.tokenRefKey(tokenID)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete provider token reference: %w", err)
	}
	return nil
}

// luaScriptAtomicConsumeRefresh atomically retrieves and deletes a refresh
// token under the unified provider-token layout. It is the counterpart of
// luaScriptAtomicGetAndDeleteRefresh minus the provider-token copy: the
// provider token lives in the shared per-user entry, so only the refresh
// token's own keys are consumed.
//
// Security: MUST be atomic - only ONE concurrent request can succeed. Any
// subsequent attempt gets "NOT_FOUND", feeding OAuth 2.1 reuse detection.
// Security: Returns clientID for client binding validation (Section 6).
//
// KEYS[1] = refresh token key (refresh token -> userID)
// KEYS[2] = token meta key (token metadata, carries client_id)
// KEYS[3] = token ref key (refresh token -> userID reference)
// KEYS[4] = token key (stray provider-token copy written by pre-unification code)
//
// Returns:
//   - JSON object {"user_id": "...", "client_id": "..."} on success
//   - "NOT_FOUND" if the refresh token key doesn't exist (may indicate reuse)
//
// Expiry is enforced by the key TTL set at save time, matching the -1
// (TTL-managed) mode of the copy-based script.
const luaScriptAtomicConsumeRefresh = `
local userID = redis.call('GET', KEYS[1])
if not userID then
    return 'NOT_FOUND'
end

local clientID = ""
local metaData = redis.call('GET', KEYS[2])
if metaData then
    local meta = cjson.decode(metaData)
    if meta and meta.client_id then
        clientID = meta.client_id
    end
end

redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
redis.call('DEL', KEYS[4])

return cjson.encode({user_id = userID, client_id = clientID})
`

// AtomicConsumeRefreshToken atomically retrieves and deletes a refresh token,
// returning its (userID, clientID) binding (storage.UserProviderTokenStore).
func (s *Store) AtomicConsumeRefreshToken(ctx context.Context, refreshToken string) (resUserID, resClientID string, err error) {
	op := s.startTracedOp(ctx, "atomic_consume_refresh_token")
	defer op.end(&err)

	result, err := s.client.Do(
		op.ctx,
		s.client.B().Eval().Script(luaScriptAtomicConsumeRefresh).
			Numkeys(4).
			Key(
				s.refreshTokenKey(refreshToken),
				s.tokenMetaKey(refreshToken),
				s.tokenRefKey(refreshToken),
				s.tokenKey(refreshToken),
			).
			Build(),
	).ToString()
	if err != nil {
		return "", "", fmt.Errorf("failed to execute atomic refresh token consume: %w", err)
	}

	if result == luaResultNotFound {
		return "", "", fmt.Errorf("%w: "+storage.ErrMsgRefreshTokenNotFoundOrUsed, storage.ErrTokenNotFound)
	}

	var resultData struct {
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
	}
	if err = json.Unmarshal([]byte(result), &resultData); err != nil {
		return "", "", fmt.Errorf("failed to parse atomic consume result: %w", err)
	}

	s.logger.Debug("Atomically consumed refresh token",
		"user_id", resultData.UserID,
		"client_id", resultData.ClientID)
	return resultData.UserID, resultData.ClientID, nil
}
