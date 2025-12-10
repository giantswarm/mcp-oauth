// Package memory provides an in-memory implementation of all storage interfaces.
// It is suitable for development, testing, and single-instance deployments.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/util"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	// tokenIDLogLength is the number of characters to include when logging token IDs
	// This provides enough uniqueness for debugging while keeping logs secure
	tokenIDLogLength = 8

	// maxFamilyMetadataEntries is the threshold for warning about excessive family metadata
	// This helps detect potential memory exhaustion attacks
	maxFamilyMetadataEntries = 10000

	// hardMaxFamilyMetadataEntries is the hard limit for family metadata entries
	// Exceeding this limit will cause SaveRefreshTokenWithFamily to fail
	// This prevents memory exhaustion attacks via repeated token rotation
	// Set to 5x the warning threshold for safety margin
	hardMaxFamilyMetadataEntries = 50000
)

// RefreshTokenFamily tracks a family of refresh tokens for reuse detection (OAuth 2.1)
type RefreshTokenFamily struct {
	FamilyID   string    // Unique identifier for this token family
	UserID     string    // User who owns this family
	ClientID   string    // Client who owns this family
	Generation int       // Increments with each rotation
	IssuedAt   time.Time // When this generation was issued
	Revoked    bool      // True if family has been revoked due to reuse detection
	RevokedAt  time.Time // When this family was revoked (for cleanup purposes)
}

// Store is an in-memory implementation of all storage interfaces.
// It implements TokenStore, ClientStore, FlowStore, RefreshTokenFamilyStore, and TokenRevocationStore.
type Store struct {
	mu sync.RWMutex

	// Token storage (encrypted at rest if encryptor is set)
	// Now uses oauth2.Token directly
	tokens   map[string]*oauth2.Token
	userInfo map[string]*providers.UserInfo

	// Refresh token tracking (for rotation and security)
	refreshTokens        map[string]string              // refresh token -> user ID
	refreshTokenExpiries map[string]time.Time           // refresh token -> expiry time
	refreshTokenFamilies map[string]*RefreshTokenFamily // refresh token -> family metadata

	// Token metadata tracking (for revocation by user+client)
	tokenMetadata map[string]*storage.TokenMetadata // token ID (access or refresh) -> metadata

	// Client storage
	clients      map[string]*storage.Client
	clientsPerIP map[string]int // IP address -> client count (for DoS protection)

	// Flow storage
	authStates map[string]*storage.AuthorizationState
	authCodes  map[string]*storage.AuthorizationCode

	// Security
	encryptor *security.Encryptor // Token encryption at rest (optional)

	// Instrumentation
	instrumentation *instrumentation.Instrumentation
	tracer          trace.Tracer
	meter           metric.Meter

	// Atomic counters for metrics (lock-free access during metric collection)
	tokensCountAtomic        atomic.Int64
	clientsCountAtomic       atomic.Int64
	authStatesCountAtomic    atomic.Int64
	familiesCountAtomic      atomic.Int64
	refreshTokensCountAtomic atomic.Int64

	// Cleanup
	cleanupInterval            time.Duration
	revokedFamilyRetentionDays int64 // configurable retention period for revoked families
	stopCleanup                chan struct{}
	logger                     *slog.Logger
}

// Compile-time interface checks to ensure Store implements all storage interfaces
var (
	_ storage.TokenStore              = (*Store)(nil)
	_ storage.ClientStore             = (*Store)(nil)
	_ storage.FlowStore               = (*Store)(nil)
	_ storage.RefreshTokenFamilyStore = (*Store)(nil)
	_ storage.TokenRevocationStore    = (*Store)(nil)
)

// New creates a new in-memory store with default cleanup interval (1 minute)
// and default revoked family retention (90 days)
func New() *Store {
	return NewWithInterval(time.Minute)
}

// SetRevokedFamilyRetentionDays sets the retention period for revoked token family metadata.
// This should be called after New() and before starting the server.
// The retention period is used for forensics and security auditing.
// Default: 90 days (if not set)
func (s *Store) SetRevokedFamilyRetentionDays(days int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedFamilyRetentionDays = days
	s.logger.Info("Set revoked family retention period",
		"retention_days", days)
}

// NewWithInterval creates a new in-memory store with custom cleanup interval.
// If cleanupInterval is 0 or negative, uses default of 1 minute.
func NewWithInterval(cleanupInterval time.Duration) *Store {
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}

	s := &Store{
		tokens:                     make(map[string]*oauth2.Token),
		userInfo:                   make(map[string]*providers.UserInfo),
		refreshTokens:              make(map[string]string),
		refreshTokenExpiries:       make(map[string]time.Time),
		refreshTokenFamilies:       make(map[string]*RefreshTokenFamily),
		tokenMetadata:              make(map[string]*storage.TokenMetadata),
		clients:                    make(map[string]*storage.Client),
		clientsPerIP:               make(map[string]int),
		authStates:                 make(map[string]*storage.AuthorizationState),
		authCodes:                  make(map[string]*storage.AuthorizationCode),
		cleanupInterval:            cleanupInterval,
		revokedFamilyRetentionDays: 90, // default: 90 days for security auditing
		stopCleanup:                make(chan struct{}),
		logger:                     slog.Default(),
	}

	// Start background cleanup
	go s.cleanupLoop()

	return s
}

// SetLogger sets a custom logger
func (s *Store) SetLogger(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger
}

// SetEncryptor sets the token encryptor for encryption at rest
func (s *Store) SetEncryptor(enc *security.Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = enc
	if enc != nil && enc.IsEnabled() {
		s.logger.Info("Token encryption at rest enabled for storage")
	}
}

// SetInstrumentation sets OpenTelemetry instrumentation for the store
func (s *Store) SetInstrumentation(inst *instrumentation.Instrumentation) {
	s.mu.Lock()
	s.instrumentation = inst
	if inst != nil {
		s.tracer = inst.Tracer("storage")
		s.meter = inst.Meter("storage")
	}

	// Initialize atomic counters with current counts
	s.tokensCountAtomic.Store(int64(len(s.tokens)))
	s.clientsCountAtomic.Store(int64(len(s.clients)))
	s.authStatesCountAtomic.Store(int64(len(s.authStates)))
	s.familiesCountAtomic.Store(int64(len(s.refreshTokenFamilies)))
	s.refreshTokensCountAtomic.Store(int64(len(s.refreshTokens)))
	s.mu.Unlock()

	if inst != nil {
		// Register storage size callbacks using atomic counters (lock-free)
		// These callbacks provide real-time visibility into storage size for
		// capacity planning, memory leak detection, and DoS attack monitoring
		err := inst.RegisterStorageSizeCallbacks(
			func() int64 { return s.tokensCountAtomic.Load() },
			func() int64 { return s.clientsCountAtomic.Load() },
			func() int64 { return s.authStatesCountAtomic.Load() },
			func() int64 { return s.familiesCountAtomic.Load() },
			func() int64 { return s.refreshTokensCountAtomic.Load() },
		)
		if err != nil {
			s.logger.Warn("Failed to register storage size callbacks", "error", err)
		}
	}
}

// Stop gracefully stops the cleanup goroutine
func (s *Store) Stop() {
	close(s.stopCleanup)
}

// ============================================================
// TokenStore Implementation
// ============================================================

// SaveToken saves an oauth2.Token for a user with optional encryption
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

	s.mu.Lock()
	defer s.mu.Unlock()

	// Track if this is a new token (for atomic counter)
	_, existed := s.tokens[userID]

	// Encrypt token if encryptor is configured
	storedToken := token
	if s.encryptor != nil && s.encryptor.IsEnabled() {
		encrypted, err := s.encryptToken(token)
		if err != nil {
			return err
		}
		storedToken = encrypted
		s.logger.Debug("Saved encrypted token", "user_id", userID)
	} else {
		s.logger.Debug("Saved token", "user_id", userID)
	}

	s.tokens[userID] = storedToken

	// Update atomic counter if this is a new token
	if !existed {
		s.tokensCountAtomic.Add(1)
	}

	return nil
}

// encryptToken encrypts sensitive fields in an oauth2.Token
// Returns a new token with encrypted fields, leaving the original unchanged.
// IMPORTANT: Preserves the Extra field (id_token, scope) which is critical for OIDC flows.
// SECURITY: Encrypts access_token, refresh_token, and id_token (contains PII).
func (s *Store) encryptToken(token *oauth2.Token) (*oauth2.Token, error) {
	// Extract extra fields before creating new token (they're in a private field)
	extra := storage.ExtractTokenExtra(token)

	// Create a copy to avoid modifying the original
	encrypted := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	}

	// Encrypt access token
	if encrypted.AccessToken != "" {
		enc, err := s.encryptor.Encrypt(encrypted.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt access token: %w", err)
		}
		encrypted.AccessToken = enc
	}

	// Encrypt refresh token
	if encrypted.RefreshToken != "" {
		enc, err := s.encryptor.Encrypt(encrypted.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		encrypted.RefreshToken = enc
	}

	// Encrypt sensitive extra fields (id_token contains PII)
	if extra != nil {
		encryptedExtra, err := storage.EncryptExtraFields(extra, s.encryptor)
		if err != nil {
			return nil, err
		}
		encrypted = encrypted.WithExtra(encryptedExtra)
	}

	return encrypted, nil
}

// decryptToken decrypts sensitive fields in an oauth2.Token
// Returns a new token with decrypted fields, leaving the original unchanged.
// IMPORTANT: Preserves the Extra field (id_token, scope) which is critical for OIDC flows.
// SECURITY: Decrypts access_token, refresh_token, and id_token (contains PII).
func (s *Store) decryptToken(token *oauth2.Token, encryptor *security.Encryptor) (*oauth2.Token, error) {
	// Extract extra fields before creating new token (they're in a private field)
	extra := storage.ExtractTokenExtra(token)

	// Create a copy to avoid modifying the stored version
	decrypted := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	}

	// Decrypt access token
	if decrypted.AccessToken != "" {
		dec, err := encryptor.Decrypt(decrypted.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}
		decrypted.AccessToken = dec
	}

	// Decrypt refresh token
	if decrypted.RefreshToken != "" {
		dec, err := encryptor.Decrypt(decrypted.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
		decrypted.RefreshToken = dec
	}

	// Decrypt sensitive extra fields (id_token contains PII)
	if extra != nil {
		decryptedExtra, err := storage.DecryptExtraFields(extra, encryptor)
		if err != nil {
			return nil, err
		}
		decrypted = decrypted.WithExtra(decryptedExtra)
	}

	return decrypted, nil
}

// GetToken retrieves an oauth2.Token for a user and decrypts if necessary
func (s *Store) GetToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	// Start span and track metrics
	ctx, span := s.startStorageSpan(ctx, "get_token")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "get_token", err, startTime)
	}()

	s.mu.RLock()
	encryptor := s.encryptor
	token, ok := s.tokens[userID]
	s.mu.RUnlock()

	if !ok {
		err = fmt.Errorf("%w: %s", storage.ErrTokenNotFound, userID)
		return nil, err
	}

	// Check if expired with clock skew grace period (and no refresh token)
	// This prevents false expiration errors due to time synchronization issues
	if security.IsTokenExpired(token.Expiry) && token.RefreshToken == "" {
		err = fmt.Errorf("%w: %s", storage.ErrTokenExpired, userID)
		return nil, err
	}

	// Decrypt if encryptor is configured
	if encryptor != nil && encryptor.IsEnabled() {
		decrypted, decryptErr := s.decryptToken(token, encryptor)
		if decryptErr != nil {
			err = decryptErr
			return nil, err
		}
		return decrypted, nil
	}

	return token, nil
}

// DeleteToken removes a token for a user
func (s *Store) DeleteToken(ctx context.Context, userID string) error {
	// Start span and track metrics
	ctx, span := s.startStorageSpan(ctx, "delete_token")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "delete_token", err, startTime)
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Track if the token existed (for atomic counter)
	_, existed := s.tokens[userID]

	delete(s.tokens, userID)

	// Update atomic counter if token was deleted
	if existed {
		s.tokensCountAtomic.Add(-1)
	}

	s.logger.Debug("Deleted token", "user_id", userID)
	return nil
}

// SaveUserInfo saves user information
func (s *Store) SaveUserInfo(ctx context.Context, userID string, info *providers.UserInfo) error {
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

	s.mu.Lock()
	defer s.mu.Unlock()

	s.userInfo[userID] = info
	return nil
}

// GetUserInfo retrieves user information
func (s *Store) GetUserInfo(ctx context.Context, userID string) (*providers.UserInfo, error) {
	ctx, span := s.startStorageSpan(ctx, "get_user_info")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "get_user_info", err, startTime)
	}()

	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.userInfo[userID]
	if !ok {
		err = fmt.Errorf("%w: %s", storage.ErrUserInfoNotFound, userID)
		return nil, err
	}

	return info, nil
}

// ============================================================
// ClientStore Implementation
// ============================================================

// SaveClient saves a registered client and tracks IP for DoS protection
func (s *Store) SaveClient(ctx context.Context, client *storage.Client) error {
	// Start span and track metrics
	ctx, span := s.startStorageSpan(ctx, "save_client")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "save_client", err, startTime)
	}()

	if client == nil || client.ClientID == "" {
		err = fmt.Errorf("invalid client")
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Track if this is a new client (for atomic counter)
	_, existed := s.clients[client.ClientID]

	s.clients[client.ClientID] = client

	// Update atomic counter if this is a new client
	if !existed {
		s.clientsCountAtomic.Add(1)
	}

	s.logger.Debug("Saved client", "client_id", client.ClientID)
	return nil
}

// CheckIPLimit checks if an IP has reached the client registration limit
func (s *Store) CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if maxClientsPerIP <= 0 {
		return nil // No limit
	}

	count := s.clientsPerIP[ip]
	if count >= maxClientsPerIP {
		return fmt.Errorf("client registration limit reached for IP %s (%d/%d clients)", ip, count, maxClientsPerIP)
	}

	return nil
}

// TrackClientIP increments the client count for an IP address
func (s *Store) TrackClientIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientsPerIP[ip]++
}

// ============================================================
// Refresh Token Management (OAuth 2.1 Security)
// ============================================================

// SaveRefreshToken saves a refresh token mapping to user ID with expiry
// For OAuth 2.1 compliance, also tracks token family for reuse detection
func (s *Store) SaveRefreshToken(ctx context.Context, refreshToken, userID string, expiresAt time.Time) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[refreshToken] = userID
	s.refreshTokenExpiries[refreshToken] = expiresAt
	s.logger.Debug("Saved refresh token", "user_id", userID, "expires_at", expiresAt)
	return nil
}

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

	s.mu.Lock()
	defer s.mu.Unlock()

	// SECURITY: Enforce hard limit on family metadata to prevent memory exhaustion attacks
	// Check if we're adding a NEW family entry (not updating existing)
	if _, exists := s.refreshTokenFamilies[refreshToken]; !exists {
		currentCount := len(s.refreshTokenFamilies)
		if currentCount >= hardMaxFamilyMetadataEntries {
			s.logger.Error("CRITICAL: Refresh token family metadata limit exceeded - blocking save to prevent memory exhaustion",
				"current_count", currentCount,
				"hard_limit", hardMaxFamilyMetadataEntries,
				"user_id", userID,
				"client_id", clientID)
			return fmt.Errorf("refresh token family metadata limit exceeded (%d entries) - possible memory exhaustion attack", currentCount)
		}
	}

	// Save basic refresh token info
	s.refreshTokens[refreshToken] = userID
	s.refreshTokenExpiries[refreshToken] = expiresAt

	// Save family metadata for reuse detection
	s.refreshTokenFamilies[refreshToken] = &RefreshTokenFamily{
		FamilyID:   familyID,
		UserID:     userID,
		ClientID:   clientID,
		Generation: generation,
		IssuedAt:   time.Now(),
		Revoked:    false,
	}

	// Save token metadata for revocation tracking (OAuth 2.1 code reuse detection)
	s.tokenMetadata[refreshToken] = &storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: "refresh",
	}

	s.logger.Debug("Saved refresh token with family tracking",
		"user_id", userID,
		"family_id", util.SafeTruncate(familyID, tokenIDLogLength),
		"generation", generation,
		"expires_at", expiresAt)
	return nil
}

// GetRefreshTokenFamily retrieves family metadata for a refresh token
func (s *Store) GetRefreshTokenFamily(ctx context.Context, refreshToken string) (*storage.RefreshTokenFamilyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	family, ok := s.refreshTokenFamilies[refreshToken]
	if !ok {
		return nil, storage.ErrRefreshTokenFamilyNotFound
	}

	// Convert internal type to interface type
	return &storage.RefreshTokenFamilyMetadata{
		FamilyID:   family.FamilyID,
		UserID:     family.UserID,
		ClientID:   family.ClientID,
		Generation: family.Generation,
		IssuedAt:   family.IssuedAt,
		Revoked:    family.Revoked,
		RevokedAt:  family.RevokedAt,
	}, nil
}

// RevokeRefreshTokenFamily revokes all tokens in a family (for reuse detection)
// This is called when token reuse is detected (OAuth 2.1 security requirement)
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	revokedCount := 0
	now := time.Now()

	// Find and revoke all tokens in this family
	for token, family := range s.refreshTokenFamilies {
		if family.FamilyID == familyID {
			family.Revoked = true
			family.RevokedAt = now // Track when revoked for cleanup purposes
			// Also delete the token to prevent any further use
			delete(s.refreshTokens, token)
			delete(s.refreshTokenExpiries, token)
			delete(s.tokens, token) // Also delete provider token mapping
			revokedCount++
		}
	}

	if revokedCount > 0 {
		s.logger.Warn("Revoked refresh token family due to reuse detection",
			"family_id", util.SafeTruncate(familyID, tokenIDLogLength),
			"tokens_revoked", revokedCount)
	}

	return nil
}

// GetRefreshTokenInfo retrieves the user ID for a refresh token
// Returns error if token is not found or expired (with clock skew grace)
func (s *Store) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, ok := s.refreshTokens[refreshToken]
	if !ok {
		return "", storage.ErrTokenNotFound
	}

	// Check if expired with clock skew grace period
	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			return "", storage.ErrTokenExpired
		}
	}

	return userID, nil
}

// DeleteRefreshToken removes a refresh token (used for rotation)
func (s *Store) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)
	s.logger.Debug("Deleted refresh token (rotation)")
	return nil
}

// AtomicGetAndDeleteRefreshToken atomically retrieves and deletes a refresh token.
// This prevents race conditions in refresh token rotation and reuse detection.
// Returns the userID and provider token if successful.
//
// SECURITY: This operation is atomic - only ONE concurrent request can succeed.
// All other concurrent requests will receive a "token not found" error.
func (s *Store) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (string, *oauth2.Token, error) {
	s.mu.Lock() // MUST use write lock for atomic get-and-delete
	defer s.mu.Unlock()

	// Get user ID
	userID, ok := s.refreshTokens[refreshToken]
	if !ok {
		// Use typed error to allow callers to distinguish "not found" from transient errors
		return "", nil, fmt.Errorf("%w: refresh token not found or already used", storage.ErrTokenNotFound)
	}

	// Check if expired with clock skew grace period
	if expiresAt, hasExpiry := s.refreshTokenExpiries[refreshToken]; hasExpiry {
		if security.IsTokenExpired(expiresAt) {
			// Use typed error to distinguish expiry from not-found
			return "", nil, fmt.Errorf("%w: refresh token expired", storage.ErrTokenExpired)
		}
	}

	// Get provider token
	providerToken, ok := s.tokens[refreshToken]
	if !ok {
		// Provider token missing is a not-found condition (token data incomplete)
		return "", nil, fmt.Errorf("%w: provider token not found", storage.ErrTokenNotFound)
	}

	// ATOMIC DELETE - ensures only one request succeeds
	delete(s.refreshTokens, refreshToken)
	delete(s.refreshTokenExpiries, refreshToken)
	delete(s.tokenMetadata, refreshToken) // Prevent metadata orphaning
	delete(s.tokens, refreshToken)        // CRITICAL: Also delete provider token to prevent memory leak
	// NOTE: We deliberately DON'T delete refreshTokenFamilies here!
	// Family metadata must persist to enable reuse detection (OAuth 2.1 requirement).
	// It will be cleaned up by the background cleanup goroutine after retention period.

	s.logger.Debug("Atomically retrieved and deleted refresh token",
		"user_id", userID)

	return userID, providerToken, nil
}

// GetClient retrieves a client by ID
func (s *Store) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	// Start span and track metrics
	ctx, span := s.startStorageSpan(ctx, "get_client")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "get_client", err, startTime)
	}()

	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[clientID]
	if !ok {
		err = fmt.Errorf("%w: %s", storage.ErrClientNotFound, clientID)
		return nil, err
	}

	return client, nil
}

// ValidateClientSecret validates a client's secret using bcrypt
// Uses constant-time operations to prevent timing attacks
func (s *Store) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error {
	// SECURITY: Always perform the same operations to prevent timing attacks
	// that could reveal whether a client exists or not

	// Pre-computed dummy hash for non-existent clients (bcrypt hash of "test")
	// This ensures we always perform a bcrypt comparison even if client doesn't exist
	dummyHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

	client, err := s.GetClient(ctx, clientID)

	// Determine which hash to use (real or dummy)
	hashToCompare := dummyHash
	isPublicClient := false

	if err == nil {
		if client.ClientType == "public" {
			isPublicClient = true
		} else if client.ClientSecretHash != "" {
			hashToCompare = client.ClientSecretHash
		}
	}

	// ALWAYS perform bcrypt comparison (constant-time by design)
	// This prevents timing attacks based on whether we skip the comparison
	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(clientSecret))

	// For public clients, authentication always succeeds
	if isPublicClient && err == nil {
		return nil
	}

	// If client lookup failed, return error (but only after bcrypt comparison)
	if err != nil {
		return fmt.Errorf("invalid client credentials")
	}

	// If bcrypt comparison failed, return error
	if bcryptErr != nil {
		return fmt.Errorf("invalid client credentials")
	}

	return nil
}

// ListClients lists all registered clients
func (s *Store) ListClients(ctx context.Context) ([]*storage.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]*storage.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	return clients, nil
}

// ============================================================
// FlowStore Implementation
// ============================================================

// SaveAuthorizationState saves the state of an ongoing authorization flow
// Stores by both client state (StateID) and provider state (ProviderState) for dual lookup
func (s *Store) SaveAuthorizationState(ctx context.Context, state *storage.AuthorizationState) error {
	if state == nil || state.StateID == "" {
		return fmt.Errorf("invalid authorization state")
	}
	if state.ProviderState == "" {
		return fmt.Errorf("provider state is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store by both StateID and ProviderState for dual lookup
	// StateID is used when validating client requests
	// ProviderState is used when validating provider callbacks
	s.authStates[state.StateID] = state
	s.authStates[state.ProviderState] = state
	s.logger.Debug("Saved authorization state", "state_id", state.StateID, "provider_state_prefix", util.SafeTruncate(state.ProviderState, tokenIDLogLength))
	return nil
}

// GetAuthorizationState retrieves an authorization state by client state
func (s *Store) GetAuthorizationState(ctx context.Context, stateID string) (*storage.AuthorizationState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.authStates[stateID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", storage.ErrAuthorizationStateNotFound, stateID)
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(state.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization state expired", storage.ErrTokenExpired)
	}

	return state, nil
}

// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
// This is used during provider callback validation (separate from client state)
func (s *Store) GetAuthorizationStateByProviderState(ctx context.Context, providerState string) (*storage.AuthorizationState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.authStates[providerState]
	if !ok {
		return nil, fmt.Errorf("%w: provider state", storage.ErrAuthorizationStateNotFound)
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(state.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization state expired", storage.ErrTokenExpired)
	}

	return state, nil
}

// DeleteAuthorizationState removes an authorization state
// Removes both client state and provider state entries
func (s *Store) DeleteAuthorizationState(ctx context.Context, stateID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the state first to find both keys
	state, ok := s.authStates[stateID]
	if ok {
		// Delete both the client state and provider state entries
		delete(s.authStates, state.StateID)
		delete(s.authStates, state.ProviderState)
		s.logger.Debug("Deleted authorization state (both entries)", "state_id", state.StateID)
	} else {
		// stateID might be the provider state, try direct delete
		delete(s.authStates, stateID)
		s.logger.Debug("Deleted authorization state", "state_id", stateID)
	}
	return nil
}

// SaveAuthorizationCode saves an issued authorization code
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *storage.AuthorizationCode) error {
	// Start span and track metrics
	ctx, span := s.startStorageSpan(ctx, "save_authorization_code")
	defer span.End()

	startTime := time.Now()
	var err error

	defer func() {
		s.recordStorageOperation(ctx, span, "save_authorization_code", err, startTime)
	}()

	if code == nil || code.Code == "" {
		err = fmt.Errorf("invalid authorization code")
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.authCodes[code.Code] = code
	s.logger.Debug("Saved authorization code", "code_prefix", util.SafeTruncate(code.Code, tokenIDLogLength))
	return nil
}

// GetAuthorizationCode retrieves an authorization code without modifying it.
// The code is kept marked as "Used" to detect reuse attempts (OAuth 2.1 requirement).
// Expired/used codes are cleaned up by the background cleanup goroutine.
//
// NOTE: For actual code exchange, use AtomicCheckAndMarkAuthCodeUsed instead
// to prevent race conditions.
func (s *Store) GetAuthorizationCode(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	s.mu.Lock() // Use write lock to ensure consistent read
	defer s.mu.Unlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, storage.ErrAuthorizationCodeNotFound
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(authCode.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization code expired", storage.ErrTokenExpired)
	}

	// Return a COPY to prevent caller from modifying our stored version
	codeCopy := *authCode
	return &codeCopy, nil
}

// AtomicCheckAndMarkAuthCodeUsed atomically checks if a code is unused and marks it as used.
// This prevents race conditions in authorization code reuse detection.
// Returns the auth code if successful, or an error if code is already used.
//
// SECURITY: This operation is atomic - only ONE concurrent request can succeed.
// All other concurrent requests will receive an "already used" error.
//
// IMPORTANT: The authCode is ONLY returned on reuse errors (Used=true) to enable
// detection and revocation. For other errors (not found, expired), nil is returned
// to prevent information leakage.
func (s *Store) AtomicCheckAndMarkAuthCodeUsed(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	s.mu.Lock() // MUST use write lock for atomic check-and-set
	defer s.mu.Unlock()

	authCode, ok := s.authCodes[code]
	if !ok {
		// Not found - return nil to prevent information leakage
		return nil, storage.ErrAuthorizationCodeNotFound
	}

	// Check if expired with clock skew grace period
	if security.IsTokenExpired(authCode.ExpiresAt) {
		// Expired - return nil to prevent information leakage
		return nil, fmt.Errorf("%w: authorization code expired", storage.ErrTokenExpired)
	}

	// ATOMIC check-and-set: Only one thread can pass this check
	if authCode.Used {
		// SECURITY: Code already used - return authCode to enable reuse detection
		// The caller needs userID/clientID for token revocation
		return authCode, storage.ErrAuthorizationCodeUsed
	}

	// Mark as used atomically
	authCode.Used = true
	s.logger.Debug("Marked authorization code as used",
		"code_prefix", util.SafeTruncate(code, tokenIDLogLength))

	// Return the code for token issuance
	return authCode, nil
}

// DeleteAuthorizationCode removes an authorization code
func (s *Store) DeleteAuthorizationCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authCodes, code)
	s.logger.Debug("Deleted authorization code")
	return nil
}

// ============================================================
// Cleanup
// ============================================================

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleaned := 0

	// Cleanup expired tokens (with clock skew grace period)
	for userID, token := range s.tokens {
		if security.IsTokenExpired(token.Expiry) && token.RefreshToken == "" {
			delete(s.tokens, userID)
			delete(s.userInfo, userID)
			cleaned++
		}
	}

	// Cleanup expired authorization states (with clock skew grace period)
	for stateID, state := range s.authStates {
		if security.IsTokenExpired(state.ExpiresAt) {
			delete(s.authStates, stateID)
			cleaned++
		}
	}

	// Cleanup expired authorization codes (with clock skew grace period)
	for code, authCode := range s.authCodes {
		if security.IsTokenExpired(authCode.ExpiresAt) {
			delete(s.authCodes, code)
			cleaned++
		}
	}

	// Cleanup expired refresh tokens (with clock skew grace period)
	for refreshToken, expiresAt := range s.refreshTokenExpiries {
		if security.IsTokenExpired(expiresAt) {
			delete(s.refreshTokens, refreshToken)
			delete(s.refreshTokenExpiries, refreshToken)
			delete(s.refreshTokenFamilies, refreshToken) // Also cleanup family metadata
			cleaned++
		}
	}

	// Cleanup revoked token families (keep metadata for a while for forensics, then cleanup)
	// Use configurable retention period (default: 90 days)
	// This provides retention for security audits and forensics
	retentionDays := s.revokedFamilyRetentionDays
	if retentionDays == 0 {
		retentionDays = 90 // fallback to default
	}
	revokedFamilyCleanupThreshold := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for refreshToken, family := range s.refreshTokenFamilies {
		if family.Revoked {
			// Use RevokedAt if available, otherwise fall back to IssuedAt
			revokedTime := family.RevokedAt
			if revokedTime.IsZero() {
				revokedTime = family.IssuedAt
			}
			if revokedTime.Before(revokedFamilyCleanupThreshold) {
				delete(s.refreshTokenFamilies, refreshToken)
				cleaned++
			}
		}
	}

	// Cleanup orphaned token metadata (tokens that no longer exist)
	// SECURITY NOTE: Orphaned metadata can occur if the process crashes between deletes.
	// This is expected for in-memory storage. For production use with persistent storage,
	// implement proper transaction support to prevent orphaning.
	for tokenID := range s.tokenMetadata {
		// Check if token still exists (either as a regular token or refresh token)
		if _, existsAsToken := s.tokens[tokenID]; !existsAsToken {
			if _, existsAsRefresh := s.refreshTokens[tokenID]; !existsAsRefresh {
				delete(s.tokenMetadata, tokenID)
				cleaned++
			}
		}
	}

	// SECURITY MONITORING: Check for excessive family metadata growth
	// This could indicate a memory exhaustion attack via repeated token reuse
	familyCount := len(s.refreshTokenFamilies)
	if familyCount > maxFamilyMetadataEntries {
		s.logger.Warn("Refresh token family metadata approaching limit - possible memory exhaustion attack",
			"current_count", familyCount,
			"max_threshold", maxFamilyMetadataEntries,
			"recommendation", "Review security logs for repeated token reuse attempts")
	}

	if cleaned > 0 {
		s.logger.Debug("Cleaned up expired entries", "count", cleaned, "family_metadata_count", familyCount)
	}
}

// ============================================================
// TokenRevocationStore Implementation (OAuth 2.1 Security)
// ============================================================

// SaveTokenMetadata saves metadata for a token (for revocation tracking)
// This should be called whenever a token is issued to a user for a client
func (s *Store) SaveTokenMetadata(tokenID, userID, clientID, tokenType string) error {
	return s.SaveTokenMetadataWithAudience(tokenID, userID, clientID, tokenType, "")
}

// SaveTokenMetadataWithAudience saves metadata for a token including RFC 8707 audience
// This should be called whenever a token is issued to a user for a client
func (s *Store) SaveTokenMetadataWithAudience(tokenID, userID, clientID, tokenType, audience string) error {
	return s.SaveTokenMetadataWithScopesAndAudience(tokenID, userID, clientID, tokenType, audience, nil)
}

// SaveTokenMetadataWithScopesAndAudience saves metadata for a token including RFC 8707 audience and MCP 2025-11-25 scopes
// This should be called whenever a token is issued to a user for a client
func (s *Store) SaveTokenMetadataWithScopesAndAudience(tokenID, userID, clientID, tokenType, audience string, scopes []string) error {
	if tokenID == "" || userID == "" || clientID == "" {
		return fmt.Errorf("tokenID, userID, and clientID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokenMetadata[tokenID] = &storage.TokenMetadata{
		UserID:    userID,
		ClientID:  clientID,
		IssuedAt:  time.Now(),
		TokenType: tokenType,
		Audience:  audience,
		Scopes:    scopes,
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	metadata, exists := s.tokenMetadata[tokenID]
	if !exists {
		return nil, fmt.Errorf("token metadata not found")
	}

	return metadata, nil
}

// RevokeAllTokensForUserClient revokes all tokens (access + refresh) for a specific user+client combination.
// This implements the OAuth 2.1 requirement for authorization code reuse detection.
// Returns the number of tokens revoked and any error encountered.
func (s *Store) RevokeAllTokensForUserClient(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" || clientID == "" {
		return 0, fmt.Errorf("userID and clientID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	revokedCount := 0

	// Step 1: Identify all token families to revoke
	familiesToRevoke := make(map[string]bool)
	tokensToRevoke := make([]string, 0)

	for tokenID, metadata := range s.tokenMetadata {
		if metadata.UserID == userID && metadata.ClientID == clientID {
			tokensToRevoke = append(tokensToRevoke, tokenID)

			// Track family IDs that need complete revocation
			if family, hasFam := s.refreshTokenFamilies[tokenID]; hasFam {
				familiesToRevoke[family.FamilyID] = true
			}
		}
	}

	// Step 2: Revoke ENTIRE token families (finds ALL family members, not just tracked ones)
	now := time.Now()
	for familyID := range familiesToRevoke {
		familyRevokedCount := 0
		for tokenID, family := range s.refreshTokenFamilies {
			if family.FamilyID == familyID {
				// Mark family as revoked (keeps metadata for forensics/detection)
				// CRITICAL: Must update the map entry directly, not the loop copy
				s.refreshTokenFamilies[tokenID].Revoked = true
				s.refreshTokenFamilies[tokenID].RevokedAt = now

				// Delete the actual tokens
				delete(s.refreshTokens, tokenID)
				delete(s.refreshTokenExpiries, tokenID)
				delete(s.tokens, tokenID)
				delete(s.tokenMetadata, tokenID)

				revokedCount++
				familyRevokedCount++

				s.logger.Debug("Revoked token from family",
					"user_id", userID,
					"client_id", clientID,
					"token_id", util.SafeTruncate(tokenID, tokenIDLogLength),
					"family_id", util.SafeTruncate(familyID, tokenIDLogLength),
					"generation", family.Generation)
			}
		}

		if familyRevokedCount > 0 {
			s.logger.Info("Revoked entire refresh token family",
				"user_id", userID,
				"client_id", clientID,
				"family_id", util.SafeTruncate(familyID, tokenIDLogLength),
				"tokens_revoked", familyRevokedCount,
				"reason", "authorization_code_reuse_detected")
		}
	}

	// Step 3: Revoke remaining tokens (access tokens, tokens without families)
	for _, tokenID := range tokensToRevoke {
		// Skip if already deleted as part of family revocation
		if _, exists := s.tokens[tokenID]; !exists {
			continue
		}

		// Delete the token itself
		delete(s.tokens, tokenID)
		delete(s.tokenMetadata, tokenID)
		revokedCount++

		s.logger.Debug("Revoked access token",
			"user_id", userID,
			"client_id", clientID,
			"token_id", util.SafeTruncate(tokenID, tokenIDLogLength))
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

	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens := make([]string, 0)
	for tokenID, metadata := range s.tokenMetadata {
		if metadata.UserID == userID && metadata.ClientID == clientID {
			tokens = append(tokens, tokenID)
		}
	}

	return tokens, nil
}

// ============================================================
// Instrumentation Helpers
// ============================================================

// startStorageSpan starts a new span for a storage operation
// Returns a context with the span attached and the span itself
func (s *Store) startStorageSpan(ctx context.Context, operation string) (context.Context, trace.Span) {
	if s.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}

	ctx, span := s.tracer.Start(ctx, fmt.Sprintf("storage.%s", operation),
		trace.WithAttributes(
			attribute.String("operation", operation),
		))

	return ctx, span
}

// recordStorageOperation records metrics for a storage operation and sets span status
func (s *Store) recordStorageOperation(ctx context.Context, span trace.Span, operation string, err error, startTime time.Time) {
	if s.instrumentation == nil {
		return
	}

	durationMs := float64(time.Since(startTime).Milliseconds())
	result := "success"
	if err != nil {
		result = "error"
		// Set span error status
		if span != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
	} else {
		// Set span success status
		if span != nil {
			span.SetStatus(codes.Ok, "")
		}
	}

	// Record operation with count and duration
	s.instrumentation.Metrics().RecordStorageOperation(ctx, operation, result, durationMs)
}
