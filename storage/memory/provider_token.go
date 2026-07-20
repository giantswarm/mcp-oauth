package memory

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ============================================================
// UserProviderTokenStore Implementation
// ============================================================
//
// The shared per-user provider token lives in its own map, separate from
// s.tokens: the generic token map's cleanup treats an expired entry whose
// key is not an active refresh token as garbage, but the shared entry must
// outlive the provider access token's real expiry for as long as its
// refresh token can renew it.

// SaveUserProviderToken writes the user's shared provider-token entry,
// replacing any previous value (storage.UserProviderTokenStore).
func (s *Store) SaveUserProviderToken(_ context.Context, userID string, token *oauth2.Token) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	storedToken := token
	if s.encryptor != nil && s.encryptor.IsEnabled() {
		encrypted, err := s.encryptToken(token)
		if err != nil {
			return err
		}
		storedToken = encrypted
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.userProviderTokens[userID] = storedToken
	s.logger.Debug("Saved shared provider token", "user_id", userID, "expiry", token.Expiry)
	return nil
}

// GetUserProviderToken returns the user's shared provider-token entry
// (storage.UserProviderTokenStore).
func (s *Store) GetUserProviderToken(_ context.Context, userID string) (*oauth2.Token, error) {
	s.mu.RLock()
	encryptor := s.encryptor
	token, ok := s.userProviderTokens[userID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: shared provider token for user", storage.ErrTokenNotFound)
	}

	// An expired entry that still carries a refresh token is returned
	// normally — the caller refreshes it. Same contract as GetToken.
	if security.IsTokenExpired(token.Expiry) && token.RefreshToken == "" {
		return nil, fmt.Errorf("%w: shared provider token for user", storage.ErrTokenExpired)
	}

	if encryptor != nil && encryptor.IsEnabled() {
		return s.decryptToken(token, encryptor)
	}
	return token, nil
}

// DeleteUserProviderToken removes the user's shared provider-token entry
// (storage.UserProviderTokenStore).
func (s *Store) DeleteUserProviderToken(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.userProviderTokens, userID)
	s.logger.Debug("Deleted shared provider token", "user_id", userID)
	return nil
}

// SaveProviderTokenRef records that tokenID belongs to userID
// (storage.UserProviderTokenStore).
func (s *Store) SaveProviderTokenRef(_ context.Context, tokenID, userID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("tokenID cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.providerTokenRefs[tokenID] = userID
	s.providerTokenRefExpiries[tokenID] = expiresAt
	return nil
}

// GetProviderTokenRef resolves tokenID to the owning userID
// (storage.UserProviderTokenStore).
func (s *Store) GetProviderTokenRef(_ context.Context, tokenID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, ok := s.providerTokenRefs[tokenID]
	if !ok {
		return "", storage.ErrTokenNotFound
	}
	if expiresAt, hasExpiry := s.providerTokenRefExpiries[tokenID]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			return "", storage.ErrTokenNotFound
		}
	}
	return userID, nil
}

// DeleteProviderTokenRef removes the reference for tokenID
// (storage.UserProviderTokenStore).
func (s *Store) DeleteProviderTokenRef(_ context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteProviderTokenRefLocked(tokenID)
	return nil
}

// deleteProviderTokenRefLocked removes a reference. Must be called with s.mu held.
func (s *Store) deleteProviderTokenRefLocked(tokenID string) {
	delete(s.providerTokenRefs, tokenID)
	delete(s.providerTokenRefExpiries, tokenID)
}

// AtomicConsumeRefreshToken atomically retrieves and deletes a refresh token,
// returning its (userID, clientID) binding (storage.UserProviderTokenStore).
// Unlike AtomicGetAndDeleteRefreshToken it does not require a provider-token
// copy under the refresh-token key — the provider token lives in the shared
// per-user entry.
//
// SECURITY: atomic — only ONE concurrent request can succeed; the rest get
// ErrTokenNotFound, feeding OAuth 2.1 reuse detection exactly like the
// copy-based operation.
func (s *Store) AtomicConsumeRefreshToken(_ context.Context, refreshToken string) (string, string, error) {
	s.mu.Lock() // MUST use write lock for atomic get-and-delete
	defer s.mu.Unlock()

	userID, ok := s.refreshTokens[refreshToken]
	if !ok {
		return "", "", fmt.Errorf("%w: "+storage.ErrMsgRefreshTokenNotFoundOrUsed, storage.ErrTokenNotFound)
	}

	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			return "", "", fmt.Errorf("%w: refresh token expired", storage.ErrTokenExpired)
		}
	}

	var clientID string
	if metadata, hasMetadata := s.tokenMetadata[refreshToken]; hasMetadata {
		clientID = metadata.ClientID
	}

	// ATOMIC DELETE - ensures only one request succeeds
	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)
	delete(s.tokenMetadata, refreshToken)
	delete(s.tokens, refreshToken) // stray copy written by pre-unification code
	s.deleteProviderTokenRefLocked(refreshToken)
	// NOTE: refreshTokenFamilies deliberately persists for reuse detection,
	// same as AtomicGetAndDeleteRefreshToken.

	s.logger.Debug("Atomically consumed refresh token",
		"user_id", userID,
		"client_id", clientID)

	return userID, clientID, nil
}

// cleanupExpiredProviderTokenRefs removes expired token → user references.
// Must be called with s.mu held (from cleanup()).
func (s *Store) cleanupExpiredProviderTokenRefs() int {
	cleaned := 0
	for tokenID, expiresAt := range s.providerTokenRefExpiries {
		if security.IsTokenExpired(expiresAt) {
			delete(s.providerTokenRefs, tokenID)
			delete(s.providerTokenRefExpiries, tokenID)
			cleaned++
		}
	}
	return cleaned
}

// cleanupExpiredUserProviderTokens removes shared provider-token entries that
// have expired AND carry no refresh token to renew them. Entries with a
// refresh token are kept: the provider can renew them long past the access
// token expiry. Must be called with s.mu held (from cleanup()).
func (s *Store) cleanupExpiredUserProviderTokens() int {
	cleaned := 0
	for userID, token := range s.userProviderTokens {
		if token.RefreshToken == "" && security.IsTokenExpired(token.Expiry) {
			delete(s.userProviderTokens, userID)
			cleaned++
		}
	}
	return cleaned
}
