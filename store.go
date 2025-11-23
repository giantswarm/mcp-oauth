package oauth

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Store manages Google OAuth tokens in memory
// This is a simplified store that only handles Google tokens for authenticated users
//
// Security Considerations:
//   - Tokens are stored unencrypted in memory. If memory dumps are a concern,
//     consider implementing encryption at rest.
//   - Automatic cleanup runs periodically to remove expired tokens
//   - Clock skew grace period is applied to prevent false expiration errors
//   - Refresh tokens are protected and not deleted until explicitly expired
//
// Thread Safety:
//   - All operations use RWMutex for thread-safe concurrent access
//   - Cleanup operations use optimized locking to minimize contention
type Store struct {
	mu                   sync.RWMutex
	googleTokens         map[string]*oauth2.Token   // user email or access token -> Google token
	googleUserInfo       map[string]*GoogleUserInfo // user email -> Google user info
	refreshTokens        map[string]string          // refresh token -> user email
	refreshTokenExpiries map[string]int64           // refresh token -> expiry timestamp
	tokenToEmailMap      map[string]string          // access token -> user email (for cleanup)
	cleanupInterval      time.Duration              // How often to cleanup expired tokens
	logger               *slog.Logger
	stopCleanup          chan struct{} // Channel to stop cleanup goroutine
	manualCleanup        chan struct{} // Channel to trigger manual cleanup (for testing)
}

// NewStore creates a new in-memory Google token store with default cleanup interval
func NewStore() *Store {
	return NewStoreWithInterval(1 * time.Minute)
}

// NewStoreWithInterval creates a new in-memory Google token store with custom cleanup interval
func NewStoreWithInterval(cleanupInterval time.Duration) *Store {
	s := &Store{
		googleTokens:         make(map[string]*oauth2.Token),
		googleUserInfo:       make(map[string]*GoogleUserInfo),
		refreshTokens:        make(map[string]string),
		refreshTokenExpiries: make(map[string]int64),
		tokenToEmailMap:      make(map[string]string),
		cleanupInterval:      cleanupInterval,
		logger:               slog.Default(),
		stopCleanup:          make(chan struct{}),
		manualCleanup:        make(chan struct{}, 1), // Buffered to prevent blocking
	}

	// Start background cleanup goroutine
	go s.cleanupExpiredTokens()

	return s
}

// SetLogger sets a custom logger for the store
func (s *Store) SetLogger(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger
}

// Stop gracefully stops the cleanup goroutine
// This should be called when the store is no longer needed to prevent goroutine leaks
func (s *Store) Stop() {
	close(s.stopCleanup)
}

// TriggerCleanup manually triggers a cleanup cycle
// This is primarily used for testing to make tests deterministic
func (s *Store) TriggerCleanup() {
	select {
	case s.manualCleanup <- struct{}{}:
	default:
		// Channel full, cleanup already pending
	}
}

// SaveGoogleToken saves a Google OAuth token for a user
// The key can be either a user email (canonical storage) or an access token (for quick lookup)
func (s *Store) SaveGoogleToken(key string, token *oauth2.Token) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.googleTokens[key] = token
	s.logger.Debug("Saved Google token",
		"key_hash", HashForDisplay(key),
		"expiry", token.Expiry)
	return nil
}

// GetGoogleToken retrieves a Google OAuth token for a user
func (s *Store) GetGoogleToken(email string) (*oauth2.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.googleTokens[email]
	if !ok {
		return nil, fmt.Errorf("Google token not found for user: %s", email)
	}

	// Check if token is expired
	// Only return error if token is expired AND we don't have a refresh token
	// If we have a refresh token, we return the expired token so the caller can refresh it
	if token.Expiry.Before(time.Now()) && token.RefreshToken == "" {
		return nil, fmt.Errorf("Google token expired for user: %s", email)
	}

	return token, nil
}

// DeleteGoogleToken removes a Google OAuth token for a user
func (s *Store) DeleteGoogleToken(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.googleTokens, email)
	delete(s.googleUserInfo, email)

	// Also delete any refresh tokens for this user
	for refreshToken, userEmail := range s.refreshTokens {
		if userEmail == email {
			delete(s.refreshTokens, refreshToken)
		}
	}

	s.logger.Info("Deleted Google token and refresh tokens",
		"email_hash", HashForDisplay(email))
	return nil
}

// SaveGoogleUserInfo saves Google user info
func (s *Store) SaveGoogleUserInfo(email string, userInfo *GoogleUserInfo) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	if userInfo == nil {
		return fmt.Errorf("userInfo cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.googleUserInfo[email] = userInfo
	return nil
}

// GetGoogleUserInfo retrieves Google user info
func (s *Store) GetGoogleUserInfo(email string) (*GoogleUserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userInfo, ok := s.googleUserInfo[email]
	if !ok {
		return nil, fmt.Errorf("Google user info not found for user: %s", email)
	}

	return userInfo, nil
}

// cleanupExpiredTokens periodically removes expired tokens
// Uses optimized locking strategy to minimize write lock duration
// Re-validates expiration under write lock to prevent race conditions
//
// Security considerations:
//   - Tokens with valid refresh tokens are preserved even if access token expires
//   - Clock skew grace period applied to prevent premature deletion
//   - Comprehensive logging for audit trail (with sanitized data)
func (s *Store) cleanupExpiredTokens() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			// Graceful shutdown
			return
		case <-s.manualCleanup:
			// Manual trigger for testing
			s.performCleanup()
		case <-ticker.C:
			// Periodic cleanup
			s.performCleanup()
		}
	}
}

// performCleanup executes the actual cleanup logic
// Separated from cleanupExpiredTokens to allow manual triggering
func (s *Store) performCleanup() {
	expiredGoogleTokens := s.findExpiredGoogleTokens()
	expiredRefreshTokens := s.findExpiredRefreshTokens()

	// Only acquire write lock if there's work to do
	if len(expiredGoogleTokens) > 0 || len(expiredRefreshTokens) > 0 {
		s.mu.Lock()
		s.deleteExpiredGoogleTokens(expiredGoogleTokens)
		s.deleteExpiredRefreshTokens(expiredRefreshTokens)
		s.mu.Unlock()
	}
}

// findExpiredGoogleTokens finds Google tokens that are expired
func (s *Store) findExpiredGoogleTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expired := []string{}
	now := time.Now()

	for key, token := range s.googleTokens {
		if !token.Expiry.IsZero() && token.Expiry.Before(now) {
			expired = append(expired, key)
		}
	}

	return expired
}

// findExpiredRefreshTokens finds refresh tokens that are expired (with clock skew grace)
func (s *Store) findExpiredRefreshTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expired := []string{}
	nowUnix := time.Now().Unix()

	for refreshToken, expiresAt := range s.refreshTokenExpiries {
		if nowUnix > (expiresAt + ClockSkewGrace) {
			expired = append(expired, refreshToken)
		}
	}

	return expired
}

// deleteExpiredGoogleTokens deletes expired Google tokens (caller must hold write lock)
func (s *Store) deleteExpiredGoogleTokens(expiredKeys []string) {
	currentTime := time.Now()
	currentTimeUnix := currentTime.Unix()

	for _, key := range expiredKeys {
		token, ok := s.googleTokens[key]
		if !ok {
			continue // Token was already deleted
		}

		// Re-check expiration (token might have been refreshed)
		if !token.Expiry.IsZero() && !token.Expiry.Before(currentTime) {
			continue // No longer expired
		}

		// Don't delete if token has a valid refresh token
		if s.hasValidRefreshToken(token, currentTimeUnix) {
			continue
		}

		// Delete the token
		delete(s.googleTokens, key)
		s.deleteUserInfoIfNeeded(key)
		s.logger.Debug("Cleaned up expired Google token",
			"key_hash", HashForDisplay(key))
	}
}

// hasValidRefreshToken checks if a token has a refresh token that is still valid
func (s *Store) hasValidRefreshToken(token *oauth2.Token, nowUnix int64) bool {
	if token.RefreshToken == "" {
		return false
	}

	// If refresh token is tracked, check if it's expired
	if expiry, tracked := s.refreshTokenExpiries[token.RefreshToken]; tracked {
		return nowUnix <= (expiry + ClockSkewGrace)
	}

	// If not tracked, assume valid (safe default)
	return true
}

// deleteUserInfoIfNeeded deletes user info if this was the last token for the user
func (s *Store) deleteUserInfoIfNeeded(key string) {
	if email, hasEmail := s.tokenToEmailMap[key]; hasEmail {
		delete(s.tokenToEmailMap, key)
		// Check if this was the last token for this email
		if _, stillHasToken := s.googleTokens[email]; !stillHasToken {
			delete(s.googleUserInfo, email)
		}
	} else {
		// This is an email key
		delete(s.googleUserInfo, key)
	}
}

// deleteExpiredRefreshTokens deletes expired refresh tokens (caller must hold write lock)
func (s *Store) deleteExpiredRefreshTokens(expiredTokens []string) {
	currentTimeUnix := time.Now().Unix()

	for _, refreshToken := range expiredTokens {
		expiresAt, ok := s.refreshTokenExpiries[refreshToken]
		if !ok {
			continue // Already deleted
		}

		// Re-check expiration
		if currentTimeUnix <= (expiresAt + ClockSkewGrace) {
			continue // No longer expired
		}

		email := s.refreshTokens[refreshToken]
		delete(s.refreshTokens, refreshToken)
		delete(s.refreshTokenExpiries, refreshToken)
		s.logger.Debug("Cleaned up expired refresh token",
			"email_hash", HashForDisplay(email))
	}
}

// SaveRefreshToken saves a refresh token mapping to user email with expiry
func (s *Store) SaveRefreshToken(refreshToken, email string, expiresAt int64) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[refreshToken] = email
	s.refreshTokenExpiries[refreshToken] = expiresAt
	s.logger.Debug("Saved refresh token",
		"email_hash", HashForDisplay(email),
		"expires_at", time.Unix(expiresAt, 0))
	return nil
}

// GetRefreshToken retrieves the user email associated with a refresh token
// Returns an error if the token is expired
// Uses clock skew grace period to prevent false expiration errors due to time differences
func (s *Store) GetRefreshToken(refreshToken string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	email, ok := s.refreshTokens[refreshToken]
	if !ok {
		return "", fmt.Errorf("refresh token not found")
	}

	// Check if refresh token is expired
	// Security: Add grace period for clock skew to prevent false expiration errors
	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if time.Now().Unix() > (expiresAt + ClockSkewGrace) {
			return "", fmt.Errorf("refresh token expired")
		}
	}

	return email, nil
}

// DeleteRefreshToken removes a refresh token and its expiry tracking
func (s *Store) DeleteRefreshToken(refreshToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)
	s.logger.Debug("Deleted refresh token")
	return nil
}

// SaveTokenWithEmailMapping saves a Google token by both email and access token
// This is a convenience method to ensure tokens are stored consistently
func (s *Store) SaveTokenWithEmailMapping(email, accessToken string, token *oauth2.Token) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	if accessToken == "" {
		return fmt.Errorf("access token cannot be empty")
	}
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Save by email (canonical)
	s.googleTokens[email] = token
	// Save by access token (for quick lookup)
	s.googleTokens[accessToken] = token
	// Track the mapping for cleanup
	s.tokenToEmailMap[accessToken] = email

	s.logger.Debug("Saved Google token with email mapping",
		"email_hash", HashForDisplay(email),
		"token_hash", HashForDisplay(accessToken))
	return nil
}

// Stats returns statistics about the store
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]int{
		"google_tokens":          len(s.googleTokens),
		"user_info":              len(s.googleUserInfo),
		"refresh_tokens":         len(s.refreshTokens),
		"refresh_token_expiries": len(s.refreshTokenExpiries),
		"token_email_mappings":   len(s.tokenToEmailMap),
	}
}
