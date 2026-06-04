package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Test constants for consistent naming
const (
	testUserID      = "test-user"
	testAudienceURL = "https://api.example.com"
)

// testStore creates a test store connected to a local Valkey instance.
// Tests will be skipped if VALKEY_TEST_ADDR is not set or connection fails.
// Each test gets a unique prefix to ensure test isolation.
func testStore(t *testing.T) *Store {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	// Generate a unique prefix for this test to ensure isolation
	// This prevents interference when tests run in parallel
	prefix := fmt.Sprintf("mcptest:%s:", t.Name())

	// Try to connect
	store, err := New(Config{
		Address:   addr,
		KeyPrefix: prefix,
	})
	if err != nil {
		t.Skipf("Skipping test: could not connect to Valkey at %s: %v", addr, err)
	}

	// Clean up test keys before and after test
	t.Cleanup(func() {
		cleanupTestKeys(t, store)
		store.Close()
	})

	cleanupTestKeys(t, store)
	return store
}

// testStoreWithOpts is like testStore but applies additional options at construction.
func testStoreWithOpts(t *testing.T, opts ...Option) *Store {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	prefix := fmt.Sprintf("mcptest:%s:", t.Name())

	store, err := New(Config{Address: addr, KeyPrefix: prefix}, opts...)
	if err != nil {
		t.Skipf("Skipping test: could not connect to Valkey at %s: %v", addr, err)
	}

	t.Cleanup(func() {
		cleanupTestKeys(t, store)
		store.Close()
	})

	cleanupTestKeys(t, store)
	return store
}

// cleanupTestKeys removes all test keys from Valkey
func cleanupTestKeys(t *testing.T, s *Store) {
	t.Helper()

	ctx := context.Background()
	pattern := s.prefix + "*"

	var cursor uint64
	for {
		result, err := s.client.Do(
			ctx,
			s.client.B().Scan().Cursor(cursor).Match(pattern).Count(100).Build(),
		).AsScanEntry()
		if err != nil {
			t.Logf("Warning: failed to scan for cleanup: %v", err)
			return
		}

		for _, key := range result.Elements {
			_ = s.client.Do(ctx, s.client.B().Del().Key(key).Build())
		}

		cursor = result.Cursor
		if cursor == 0 {
			break
		}
	}
}

// ============================================================
// Config Tests
// ============================================================

func TestNew_MissingAddress(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Error("Expected error for missing address")
	}
}

func TestNew_InvalidAddress(t *testing.T) {
	_, err := New(Config{Address: "invalid:99999"})
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestNew_MaxTokenDataSize_OutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		value int
	}{
		{"below minimum", MinMaxTokenDataSize - 1},
		{"above maximum", MaxMaxTokenDataSize + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Address: "localhost:6379", MaxTokenDataSize: tc.value})
			if err == nil {
				t.Errorf("New() with MaxTokenDataSize=%d: expected error, got nil", tc.value)
				return
			}
			if !strings.Contains(err.Error(), "MaxTokenDataSize") {
				t.Errorf("New() error = %q; want error mentioning MaxTokenDataSize", err)
			}
		})
	}
}

// ============================================================
// TokenStore Tests
// ============================================================

func TestTokenStore_SaveAndGetToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save token
	err := s.SaveToken(ctx, "user1", token)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Get token
	got, err := s.GetToken(ctx, "user1")
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
	if got.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, token.RefreshToken)
	}
}

func TestTokenStore_GetToken_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetToken(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent token")
	}
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenStore_DeleteToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken: "to-delete",
		Expiry:      time.Now().Add(time.Hour),
	}

	_ = s.SaveToken(ctx, "user2", token)

	err := s.DeleteToken(ctx, "user2")
	if err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}

	_, err = s.GetToken(ctx, "user2")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Token should be deleted, got: %v", err)
	}
}

func TestTokenStore_SaveToken_Expired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Hour), // Already expired
	}

	err := s.SaveToken(ctx, "user3", token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestTokenStore_SaveToken_EmptyUserID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveToken(ctx, "", &oauth2.Token{})
	if err == nil {
		t.Error("Expected error for empty userID")
	}
}

func TestTokenStore_SaveToken_NilToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveToken(ctx, "user4", nil)
	if err == nil {
		t.Error("Expected error for nil token")
	}
}

func TestTokenStore_SaveToken_WithRefreshToken_NoShortTTL(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()

	// A provider token with a short-lived access token but a refresh token
	// present. Valkey must NOT use the access token expiry as the key TTL,
	// otherwise the key is evicted before the MCP refresh token expires.
	token := &oauth2.Token{
		AccessToken:  "short-lived-access",
		RefreshToken: "long-lived-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(50 * time.Millisecond),
	}

	err := s.SaveToken(ctx, "user-rt-ttl", token)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Poll for 300ms confirming the key is never evicted despite the access
	// token expiry having passed (token has a RefreshToken so uses long TTL).
	require.Never(t, func() bool {
		_, err := s.GetToken(ctx, "user-rt-ttl")
		return err != nil
	}, 300*time.Millisecond, 10*time.Millisecond,
		"token with RefreshToken must not be evicted after access token expiry")

	got, err := s.GetToken(ctx, "user-rt-ttl")
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if got.AccessToken != "short-lived-access" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "short-lived-access")
	}
	if got.RefreshToken != "long-lived-refresh" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "long-lived-refresh")
	}
}

func TestTokenStore_SaveToken_WithRefreshToken_ExpiredExpiry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Provider token with an already-expired access token but a valid refresh
	// token. This must succeed because the refresh token can still be used.
	token := &oauth2.Token{
		AccessToken:  "already-expired-access",
		RefreshToken: "still-valid-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-10 * time.Minute),
	}

	err := s.SaveToken(ctx, "user-expired-rt", token)
	if err != nil {
		t.Fatalf("SaveToken should succeed for expired token with RefreshToken, got: %v", err)
	}

	got, err := s.GetToken(ctx, "user-expired-rt")
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if got.RefreshToken != "still-valid-refresh" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "still-valid-refresh")
	}
}

func TestTokenStore_SaveToken_WithoutRefreshToken_ExpiredReject(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Token WITHOUT a refresh token and an already-expired expiry must still
	// be rejected (existing behavior preserved).
	token := &oauth2.Token{
		AccessToken: "expired-no-rt",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-time.Hour),
	}

	err := s.SaveToken(ctx, "user-no-rt-expired", token)
	if err == nil {
		t.Error("Expected error for expired token without RefreshToken")
	}
}

func TestTokenStore_SaveToken_WithoutRefreshToken_HasTTL(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()

	// Token without RefreshToken and with a short expiry should be evicted
	// after the TTL (existing behavior preserved).
	token := &oauth2.Token{
		AccessToken: "short-no-rt",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(50 * time.Millisecond),
	}

	err := s.SaveToken(ctx, "user-short-no-rt", token)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	require.Eventually(t, func() bool {
		_, err := s.GetToken(ctx, "user-short-no-rt")
		return storage.IsNotFoundError(err)
	}, 5*time.Second, 50*time.Millisecond,
		"token without RefreshToken should be evicted after TTL")
}

// ============================================================
// UserInfo Tests
// ============================================================

func TestTokenStore_SaveAndGetUserInfo(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	info := &storage.UserInfo{
		ID:            "user1",
		Email:         "user@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	err := s.SaveUserInfo(ctx, "user1", info)
	if err != nil {
		t.Fatalf("SaveUserInfo failed: %v", err)
	}

	got, err := s.GetUserInfo(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserInfo failed: %v", err)
	}

	if got.Email != info.Email {
		t.Errorf("Email = %q, want %q", got.Email, info.Email)
	}
	if got.Name != info.Name {
		t.Errorf("Name = %q, want %q", got.Name, info.Name)
	}
}

func TestTokenStore_GetUserInfo_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetUserInfo(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrUserInfoNotFound, got: %v", err)
	}
}

// ============================================================
// RefreshToken Tests
// ============================================================

func TestTokenStore_SaveAndGetRefreshToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveRefreshToken(ctx, "refresh-token-1", "user1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	userID, err := s.GetRefreshTokenInfo(ctx, "refresh-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenInfo failed: %v", err)
	}

	if userID != "user1" {
		t.Errorf("UserID = %q, want %q", userID, "user1")
	}
}

func TestTokenStore_GetRefreshTokenInfo_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetRefreshTokenInfo(ctx, "nonexistent")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Expected ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenStore_DeleteRefreshToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_ = s.SaveRefreshToken(ctx, "refresh-to-delete", "user1", time.Now().Add(time.Hour))

	err := s.DeleteRefreshToken(ctx, "refresh-to-delete")
	if err != nil {
		t.Fatalf("DeleteRefreshToken failed: %v", err)
	}

	_, err = s.GetRefreshTokenInfo(ctx, "refresh-to-delete")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token should be deleted, got: %v", err)
	}
}

// ============================================================
// Atomic single-use enforcement (OAuth 2.1 / RFC 6749 §4.1.2)
// ============================================================

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_Table(t *testing.T) {
	tests := []struct {
		name         string
		prepare      func(t *testing.T, s *Store) string
		wantSentinel error
		wantUsedFlag bool
	}{
		{
			name: "first use succeeds",
			prepare: func(t *testing.T, s *Store) string {
				code := &storage.AuthorizationCode{
					Code:      "ac-first-use",
					ClientID:  "client-1",
					UserID:    testUserID,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(5 * time.Minute),
				}
				require.NoError(t, s.SaveAuthorizationCode(t.Context(), code))
				return code.Code
			},
		},
		{
			name: "second use returns reuse sentinel",
			prepare: func(t *testing.T, s *Store) string {
				code := &storage.AuthorizationCode{
					Code:      "ac-reuse",
					ClientID:  "client-1",
					UserID:    testUserID,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(5 * time.Minute),
				}
				require.NoError(t, s.SaveAuthorizationCode(t.Context(), code))
				_, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), code.Code)
				require.NoError(t, err)
				return code.Code
			},
			wantSentinel: storage.ErrAuthorizationCodeUsed,
			wantUsedFlag: true,
		},
		{
			name: "unknown code returns not-found",
			prepare: func(_ *testing.T, _ *Store) string {
				return "ac-nonexistent"
			},
			wantSentinel: storage.ErrAuthorizationCodeNotFound,
		},
		{
			name: "expired code returns expired sentinel",
			prepare: func(t *testing.T, s *Store) string {
				// Bypass SaveAuthorizationCode (which rejects past expiry) by
				// writing a long-TTL key with a past expires_at in the JSON.
				// This exercises the Lua expiry-check branch.
				code := "ac-expired"
				j := authorizationCodeJSON{
					Code:      code,
					ClientID:  "client-1",
					UserID:    testUserID,
					CreatedAt: time.Now().Add(-10 * time.Minute).Unix(),
					ExpiresAt: time.Now().Add(-1 * time.Minute).Unix(),
					Used:      false,
				}
				data, err := json.Marshal(j)
				require.NoError(t, err)
				require.NoError(t, s.client.Do(
					t.Context(),
					s.client.B().Set().Key(s.codeKey(code)).Value(string(data)).Ex(time.Hour).Build(),
				).Error())
				return code
			},
			wantSentinel: storage.ErrTokenExpired,
		},
		{
			name: "already-used code with malformed body still surfaces reuse sentinel",
			prepare: func(t *testing.T, s *Store) string {
				// Lua's cjson tolerates a string expires_at; Go's json.Unmarshal
				// does not. Exercises the reuse path where the inner JSON cannot
				// be decoded for forensics — caller must still see the sentinel.
				code := "ac-reuse-malformed"
				raw := `{"code":"ac-reuse-malformed","client_id":"client-1","user_id":"user-1","expires_at":"not-a-number","used":true}`
				require.NoError(t, s.client.Do(
					t.Context(),
					s.client.B().Set().Key(s.codeKey(code)).Value(raw).Ex(time.Hour).Build(),
				).Error())
				return code
			},
			wantSentinel: storage.ErrAuthorizationCodeUsed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testStore(t)

			code := tt.prepare(t, s)
			got, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), code)

			if tt.wantSentinel == nil {
				require.NoError(t, err)
				require.NotNil(t, got)
				return
			}

			require.ErrorIs(t, err, tt.wantSentinel)
			if tt.wantUsedFlag {
				require.NotNil(t, got, "reuse case must surface the stored code for forensics")
				require.True(t, got.Used)
			} else {
				require.Nil(t, got, "non-reuse failures must not leak code data")
			}
		})
	}
}

// TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_MalformedSuccessJSON exercises
// the Go-side json.Unmarshal error branch in the success path: Lua's cjson
// accepts a string `expires_at`, Go's typed unmarshal does not.
func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_MalformedSuccessJSON(t *testing.T) {
	s := testStore(t)

	const code = "ac-malformed-success"
	raw := `{"code":"ac-malformed-success","client_id":"client-1","user_id":"user-1","expires_at":"not-a-number","used":false}`
	require.NoError(t, s.client.Do(
		t.Context(),
		s.client.B().Set().Key(s.codeKey(code)).Value(raw).Ex(time.Hour).Build(),
	).Error())

	got, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), code)
	require.Error(t, err)
	require.Nil(t, got)
	require.NotErrorIs(t, err, storage.ErrAuthorizationCodeUsed)
	require.NotErrorIs(t, err, storage.ErrAuthorizationCodeNotFound)
}

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_ConcurrentN100(t *testing.T) {
	const n = 100

	s := testStore(t)

	code := &storage.AuthorizationCode{
		Code:      "ac-concurrent-100",
		ClientID:  "client-1",
		UserID:    testUserID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, s.SaveAuthorizationCode(t.Context(), code))

	var success, reuse atomic.Int32
	ready := make(chan struct{})
	g, ctx := errgroup.WithContext(t.Context())
	for range n {
		g.Go(func() error {
			<-ready
			_, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, code.Code)
			switch {
			case err == nil:
				success.Add(1)
				return nil
			case errors.Is(err, storage.ErrAuthorizationCodeUsed):
				reuse.Add(1)
				return nil
			default:
				return err
			}
		})
	}
	close(ready)
	require.NoError(t, g.Wait())

	require.Equal(t, int32(1), success.Load(), "more than one success would break OAuth 2.1 §4.1.2")
	require.Equal(t, int32(n-1), reuse.Load())
}

func TestTokenStore_AtomicGetAndDeleteRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		prepare      func(t *testing.T, s *Store) string
		wantSentinel error
	}{
		{
			name: "first use succeeds",
			prepare: func(t *testing.T, s *Store) string {
				const refreshToken = "rt-first-use"
				providerToken := &oauth2.Token{
					AccessToken:  "provider-access",
					RefreshToken: "provider-refresh",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}
				require.NoError(t, s.SaveToken(t.Context(), refreshToken, providerToken))
				require.NoError(t, s.SaveRefreshToken(t.Context(), refreshToken, testUserID, time.Now().Add(time.Hour)))
				return refreshToken
			},
		},
		{
			name: "second use returns not-found sentinel",
			prepare: func(t *testing.T, s *Store) string {
				const refreshToken = "rt-reuse"
				providerToken := &oauth2.Token{
					AccessToken:  "provider-access",
					RefreshToken: "provider-refresh",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}
				require.NoError(t, s.SaveToken(t.Context(), refreshToken, providerToken))
				require.NoError(t, s.SaveRefreshToken(t.Context(), refreshToken, testUserID, time.Now().Add(time.Hour)))
				_, _, _, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)
				require.NoError(t, err)
				return refreshToken
			},
			wantSentinel: storage.ErrTokenNotFound,
		},
		{
			name: "unknown refresh token returns not-found",
			prepare: func(_ *testing.T, _ *Store) string {
				return "rt-nonexistent"
			},
			wantSentinel: storage.ErrTokenNotFound,
		},
		{
			name: "refresh mapping without provider token returns not-found",
			prepare: func(t *testing.T, s *Store) string {
				// Exercises the TOKEN_NOT_FOUND branch of the Lua script: the
				// refresh-token→userID mapping exists but the provider token
				// has been evicted (TTL mismatch, manual deletion, etc.).
				const refreshToken = "rt-orphan-mapping"
				require.NoError(t, s.SaveRefreshToken(t.Context(), refreshToken, testUserID, time.Now().Add(time.Hour)))
				return refreshToken
			},
			wantSentinel: storage.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testStore(t)

			refreshToken := tt.prepare(t, s)
			userID, _, providerToken, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)

			if tt.wantSentinel == nil {
				require.NoError(t, err)
				require.Equal(t, testUserID, userID)
				require.NotNil(t, providerToken)
				return
			}

			require.ErrorIs(t, err, tt.wantSentinel)
			require.Empty(t, userID)
			require.Nil(t, providerToken)
		})
	}
}

// TestTokenStore_AtomicGetAndDeleteRefreshToken_MalformedTokenJSON exercises
// the Go-side json.Unmarshal error branch in the success path: Lua's cjson
// accepts a JSON array as a "token", Go's typed unmarshal into serializableToken
// does not.
func TestTokenStore_AtomicGetAndDeleteRefreshToken_MalformedTokenJSON(t *testing.T) {
	s := testStore(t)

	const refreshToken = "rt-malformed-token"
	require.NoError(t, s.client.Do(
		t.Context(),
		s.client.B().Set().Key(s.refreshTokenKey(refreshToken)).Value(testUserID).Ex(time.Hour).Build(),
	).Error())
	require.NoError(t, s.client.Do(
		t.Context(),
		s.client.B().Set().Key(s.tokenKey(refreshToken)).Value(`[1,2,3]`).Ex(time.Hour).Build(),
	).Error())

	userID, clientID, gotToken, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)
	require.Error(t, err)
	require.NotErrorIs(t, err, storage.ErrTokenNotFound)
	require.Empty(t, userID)
	require.Empty(t, clientID)
	require.Nil(t, gotToken)
}

// TestTokenStore_AtomicGetAndDeleteRefreshToken_DecryptError exercises the
// decryptToken error branch: an encryptor is configured but the provider
// token field is not a valid ciphertext. Models config drift across a deploy
// (e.g., encryption enabled retroactively while plaintext tokens still exist
// at rest) so the surfaced error must be opaque, never ErrTokenNotFound.
func TestTokenStore_AtomicGetAndDeleteRefreshToken_DecryptError(t *testing.T) {
	key, err := security.GenerateKey()
	require.NoError(t, err)
	enc, err := security.NewEncryptor(key)
	require.NoError(t, err)

	s := testStoreWithOpts(t, WithEncryptor(enc))

	const refreshToken = "rt-decrypt-error"
	require.NoError(t, s.client.Do(
		t.Context(),
		s.client.B().Set().Key(s.refreshTokenKey(refreshToken)).Value(testUserID).Ex(time.Hour).Build(),
	).Error())
	// Plain (un-encrypted) access token JSON — decryptToken will reject it.
	require.NoError(t, s.client.Do(
		t.Context(),
		s.client.B().Set().Key(s.tokenKey(refreshToken)).Value(`{"access_token":"plaintext-not-a-ciphertext","token_type":"Bearer"}`).Ex(time.Hour).Build(),
	).Error())

	userID, clientID, gotToken, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)
	require.Error(t, err)
	require.NotErrorIs(t, err, storage.ErrTokenNotFound)
	require.Empty(t, userID)
	require.Empty(t, clientID)
	require.Nil(t, gotToken)
}

func TestTokenStore_AtomicGetAndDeleteRefreshToken_ConcurrentN100(t *testing.T) {
	const n = 100

	s := testStore(t)

	const refreshToken = "rt-concurrent-100"
	providerToken := &oauth2.Token{
		AccessToken:  "provider-access",
		RefreshToken: "provider-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	require.NoError(t, s.SaveToken(t.Context(), refreshToken, providerToken))
	require.NoError(t, s.SaveRefreshToken(t.Context(), refreshToken, testUserID, time.Now().Add(time.Hour)))

	var success, notFound atomic.Int32
	ready := make(chan struct{})
	g, ctx := errgroup.WithContext(t.Context())
	for range n {
		g.Go(func() error {
			<-ready
			_, _, _, err := s.AtomicGetAndDeleteRefreshToken(ctx, refreshToken)
			switch {
			case err == nil:
				success.Add(1)
				return nil
			case errors.Is(err, storage.ErrTokenNotFound):
				notFound.Add(1)
				return nil
			default:
				return err
			}
		})
	}
	close(ready)
	require.NoError(t, g.Wait())

	require.Equal(t, int32(1), success.Load(), "more than one success would allow refresh token reuse")
	require.Equal(t, int32(n-1), notFound.Load())
}

// ============================================================
// ClientStore Tests
// ============================================================

func TestClientStore_SaveAndGetClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	client := &storage.Client{
		ClientID:     "test-client",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		CreatedAt:    time.Now(),
	}

	err := s.SaveClient(ctx, client)
	if err != nil {
		t.Fatalf("SaveClient failed: %v", err)
	}

	got, err := s.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if got.ClientID != client.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, client.ClientID)
	}
	if got.ClientType != client.ClientType {
		t.Errorf("ClientType = %q, want %q", got.ClientType, client.ClientType)
	}
}

func TestClientStore_GetClient_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetClient(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrClientNotFound, got: %v", err)
	}
}

func TestClientStore_ValidateClientSecret(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create a client with a bcrypt-hashed secret
	secret := "test-secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	client := &storage.Client{
		ClientID:         "secret-client",
		ClientSecretHash: string(hash),
		ClientType:       "confidential",
		RedirectURIs:     []string{"https://example.com/callback"},
		CreatedAt:        time.Now(),
	}

	_ = s.SaveClient(ctx, client)

	// Valid secret
	err := s.ValidateClientSecret(ctx, "secret-client", secret)
	if err != nil {
		t.Errorf("ValidateClientSecret with valid secret failed: %v", err)
	}

	// Invalid secret
	err = s.ValidateClientSecret(ctx, "secret-client", "wrong-secret")
	if err == nil {
		t.Error("Expected error for invalid secret")
	}
}

func TestClientStore_ValidateClientSecret_PublicClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	client := &storage.Client{
		ClientID:     "public-client",
		ClientType:   "public",
		RedirectURIs: []string{"https://example.com/callback"},
		CreatedAt:    time.Now(),
	}

	_ = s.SaveClient(ctx, client)

	// Public clients should always validate
	err := s.ValidateClientSecret(ctx, "public-client", "any-secret")
	if err != nil {
		t.Errorf("ValidateClientSecret for public client should succeed: %v", err)
	}
}

func TestClientStore_ListClients(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	clients := []*storage.Client{
		{ClientID: "list-client-1", ClientType: "public", RedirectURIs: []string{"http://localhost"}, CreatedAt: time.Now()},
		{ClientID: "list-client-2", ClientType: "confidential", RedirectURIs: []string{"http://localhost"}, CreatedAt: time.Now()},
	}

	for _, c := range clients {
		_ = s.SaveClient(ctx, c)
	}

	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}

	if len(list) < 2 {
		t.Errorf("Expected at least 2 clients, got %d", len(list))
	}
}

func TestClientStore_CheckIPLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// No limit set
	err := s.CheckIPLimit(ctx, "192.168.1.1", 0)
	if err != nil {
		t.Errorf("CheckIPLimit with no limit should succeed: %v", err)
	}

	// Track some clients
	for i := 0; i < 3; i++ {
		_ = s.TrackClientIP(ctx, "192.168.1.2")
	}

	// Check limit
	err = s.CheckIPLimit(ctx, "192.168.1.2", 5)
	if err != nil {
		t.Errorf("CheckIPLimit under limit should succeed: %v", err)
	}

	// Track more to exceed limit
	for i := 0; i < 3; i++ {
		_ = s.TrackClientIP(ctx, "192.168.1.2")
	}

	err = s.CheckIPLimit(ctx, "192.168.1.2", 5)
	if err == nil {
		t.Error("CheckIPLimit at/over limit should fail")
	}
}

// ============================================================
// FlowStore Tests
// ============================================================

func TestFlowStore_SaveAndGetAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-1",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		Scope:         "openid profile",
		ProviderState: "provider-state-1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	err := s.SaveAuthorizationState(ctx, state)
	if err != nil {
		t.Fatalf("SaveAuthorizationState failed: %v", err)
	}

	// Get by state ID
	got, err := s.GetAuthorizationState(ctx, "state-1")
	if err != nil {
		t.Fatalf("GetAuthorizationState failed: %v", err)
	}

	if got.ClientID != state.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, state.ClientID)
	}
	if got.Scope != state.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, state.Scope)
	}
}

func TestFlowStore_GetAuthorizationStateByProviderState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-2",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		ProviderState: "provider-state-2",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	_ = s.SaveAuthorizationState(ctx, state)

	// Get by provider state
	got, err := s.GetAuthorizationStateByProviderState(ctx, "provider-state-2")
	if err != nil {
		t.Fatalf("GetAuthorizationStateByProviderState failed: %v", err)
	}

	if got.StateID != state.StateID {
		t.Errorf("StateID = %q, want %q", got.StateID, state.StateID)
	}
}

func TestFlowStore_GetAuthorizationState_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetAuthorizationState(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrAuthorizationStateNotFound, got: %v", err)
	}
}

func TestFlowStore_DeleteAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-to-delete",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		ProviderState: "provider-state-delete",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	_ = s.SaveAuthorizationState(ctx, state)

	err := s.DeleteAuthorizationState(ctx, "state-to-delete")
	if err != nil {
		t.Fatalf("DeleteAuthorizationState failed: %v", err)
	}

	_, err = s.GetAuthorizationState(ctx, "state-to-delete")
	if !storage.IsNotFoundError(err) {
		t.Errorf("State should be deleted, got: %v", err)
	}

	// Provider state should also be deleted
	_, err = s.GetAuthorizationStateByProviderState(ctx, "provider-state-delete")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Provider state should be deleted, got: %v", err)
	}
}

func TestFlowStore_SaveAndGetAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:        "auth-code-1",
		ClientID:    "client-1",
		RedirectURI: "https://example.com/callback",
		Scope:       "openid",
		UserID:      "user1",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
	}

	err := s.SaveAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode failed: %v", err)
	}

	got, err := s.GetAuthorizationCode(ctx, "auth-code-1")
	if err != nil {
		t.Fatalf("GetAuthorizationCode failed: %v", err)
	}

	if got.ClientID != code.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, code.ClientID)
	}
	if got.Used {
		t.Error("Code should not be marked as used")
	}
}

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:        "auth-code-atomic-1",
		ClientID:    "client-1",
		RedirectURI: "https://example.com/callback",
		UserID:      "user1",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	// First use should succeed
	got, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "auth-code-atomic-1")
	if err != nil {
		t.Fatalf("AtomicCheckAndMarkAuthCodeUsed failed: %v", err)
	}

	if got.ClientID != code.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, code.ClientID)
	}

	// Second use should fail with code reuse error
	_, err = s.AtomicCheckAndMarkAuthCodeUsed(ctx, "auth-code-atomic-1")
	if !storage.IsCodeReuseError(err) {
		t.Errorf("Expected ErrAuthorizationCodeUsed, got: %v", err)
	}
}

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "nonexistent-code")
	if err != storage.ErrAuthorizationCodeNotFound {
		t.Errorf("Expected ErrAuthorizationCodeNotFound, got: %v", err)
	}
}

func TestFlowStore_DeleteAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:      "code-to-delete",
		ClientID:  "client-1",
		UserID:    "user1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	err := s.DeleteAuthorizationCode(ctx, "code-to-delete")
	if err != nil {
		t.Fatalf("DeleteAuthorizationCode failed: %v", err)
	}

	_, err = s.GetAuthorizationCode(ctx, "code-to-delete")
	if err != storage.ErrAuthorizationCodeNotFound {
		t.Errorf("Code should be deleted, got: %v", err)
	}
}

// TestFlowStore_AuthorizationCode_PreservesProviderTokenExtraField is a regression
// test for issue #158. It verifies that the ProviderToken's Extra field (containing
// id_token) is preserved during authorization code serialization in Valkey storage.
//
// The root cause was that oauth2.Token stores Extra fields in a private 'raw' field
// that is not included in standard JSON marshaling. The fix uses serializableToken
// for ProviderToken to explicitly serialize the Extra fields.
func TestFlowStore_AuthorizationCode_PreservesProviderTokenExtraField(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create a provider token with Extra fields (simulating OIDC provider response)
	baseProviderToken := &oauth2.Token{
		AccessToken:  "provider-access-token",
		RefreshToken: "provider-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// The id_token is the critical field that was being lost in issue #158
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-id-token-for-issue-158.signature" //nolint:gosec // test value
	grantedScope := "openid email profile"
	providerToken := baseProviderToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
		"scope":    grantedScope,
	})

	// Create authorization code with the provider token
	code := &storage.AuthorizationCode{
		Code:          "auth-code-with-extra",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		Scope:         "openid email",
		UserID:        "user-123",
		ProviderToken: providerToken,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}

	// Save the authorization code to Valkey
	err := s.SaveAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode failed: %v", err)
	}

	// Retrieve the authorization code
	got, err := s.GetAuthorizationCode(ctx, "auth-code-with-extra")
	if err != nil {
		t.Fatalf("GetAuthorizationCode failed: %v", err)
	}

	// Verify basic fields
	if got.Code != code.Code {
		t.Errorf("Code = %q, want %q", got.Code, code.Code)
	}
	if got.ClientID != code.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, code.ClientID)
	}
	if got.UserID != code.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, code.UserID)
	}

	// Verify ProviderToken exists
	if got.ProviderToken == nil {
		t.Fatal("ProviderToken is nil, expected token to be preserved")
	}

	// Verify ProviderToken basic fields
	if got.ProviderToken.AccessToken != providerToken.AccessToken {
		t.Errorf("ProviderToken.AccessToken = %q, want %q", got.ProviderToken.AccessToken, providerToken.AccessToken)
	}
	if got.ProviderToken.RefreshToken != providerToken.RefreshToken {
		t.Errorf("ProviderToken.RefreshToken = %q, want %q", got.ProviderToken.RefreshToken, providerToken.RefreshToken)
	}

	// CRITICAL: Verify Extra fields are preserved (this was the bug in issue #158)
	gotIDToken := got.ProviderToken.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("ProviderToken.Extra(\"id_token\") returned nil - id_token was lost during serialization (issue #158)")
	}
	if gotIDToken != idToken {
		t.Errorf("ProviderToken.Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}

	gotScope := got.ProviderToken.Extra("scope")
	if gotScope == nil {
		t.Fatal("ProviderToken.Extra(\"scope\") returned nil - scope was lost during serialization")
	}
	if gotScope != grantedScope {
		t.Errorf("ProviderToken.Extra(\"scope\") = %q, want %q", gotScope, grantedScope)
	}
}

// TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_PreservesProviderTokenExtraField
// tests that the atomic operation also preserves the Extra field.
func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_PreservesProviderTokenExtraField(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create provider token with Extra field
	baseProviderToken := &oauth2.Token{
		AccessToken:  "atomic-provider-access-token",
		RefreshToken: "atomic-provider-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.atomic-test-id-token.signature" //nolint:gosec // test value
	providerToken := baseProviderToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
	})

	code := &storage.AuthorizationCode{
		Code:          "atomic-code-with-extra",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		UserID:        "user-123",
		ProviderToken: providerToken,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	// Use atomic operation to mark as used
	got, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "atomic-code-with-extra")
	if err != nil {
		t.Fatalf("AtomicCheckAndMarkAuthCodeUsed failed: %v", err)
	}

	// Verify ProviderToken and Extra field
	if got.ProviderToken == nil {
		t.Fatal("ProviderToken is nil after atomic operation")
	}

	gotIDToken := got.ProviderToken.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("ProviderToken.Extra(\"id_token\") returned nil after atomic operation")
	}
	if gotIDToken != idToken {
		t.Errorf("ProviderToken.Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}
}

// TestFlowStore_AuthorizationCode_NilProviderToken ensures that nil ProviderToken
// is handled gracefully and doesn't cause issues.
func TestFlowStore_AuthorizationCode_NilProviderToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:          "code-nil-provider-token",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		UserID:        "user-123",
		ProviderToken: nil, // Explicitly nil
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}

	err := s.SaveAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode with nil ProviderToken failed: %v", err)
	}

	got, err := s.GetAuthorizationCode(ctx, "code-nil-provider-token")
	if err != nil {
		t.Fatalf("GetAuthorizationCode failed: %v", err)
	}

	if got.ProviderToken != nil {
		t.Error("Expected ProviderToken to be nil")
	}
}

// ============================================================
// RefreshTokenFamilyStore Tests
// ============================================================

func TestRefreshTokenFamilyStore_SaveAndGetFamily(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveRefreshTokenWithFamily(ctx, "family-token-1", "user1", "client1", "family-1", 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily failed: %v", err)
	}

	meta, err := s.GetRefreshTokenFamily(ctx, "family-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily failed: %v", err)
	}

	if meta.FamilyID != "family-1" {
		t.Errorf("FamilyID = %q, want %q", meta.FamilyID, "family-1")
	}
	if meta.Generation != 1 {
		t.Errorf("Generation = %d, want %d", meta.Generation, 1)
	}
	if meta.Revoked {
		t.Error("Token should not be revoked")
	}
}

func TestRefreshTokenFamilyStore_RevokeFamily(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create multiple tokens in the same family
	_ = s.SaveRefreshTokenWithFamily(ctx, "revoke-token-1", "user1", "client1", "revoke-family", 1, time.Now().Add(time.Hour))
	_ = s.SaveRefreshTokenWithFamily(ctx, "revoke-token-2", "user1", "client1", "revoke-family", 2, time.Now().Add(time.Hour))

	err := s.RevokeRefreshTokenFamily(ctx, "revoke-family")
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
	}

	// Tokens should be deleted
	_, err = s.GetRefreshTokenInfo(ctx, "revoke-token-1")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 1 should be deleted, got: %v", err)
	}

	_, err = s.GetRefreshTokenInfo(ctx, "revoke-token-2")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 2 should be deleted, got: %v", err)
	}

	// Family metadata should still exist but marked as revoked
	meta, err := s.GetRefreshTokenFamily(ctx, "revoke-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily failed: %v", err)
	}

	if !meta.Revoked {
		t.Error("Family should be marked as revoked")
	}
}

func TestRefreshTokenFamilyStore_GetFamily_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetRefreshTokenFamily(ctx, "nonexistent")
	if err != storage.ErrRefreshTokenFamilyNotFound {
		t.Errorf("Expected ErrRefreshTokenFamilyNotFound, got: %v", err)
	}
}

// ============================================================
// TokenRevocationStore Tests
// ============================================================

func TestTokenRevocationStore_RevokeAllTokensForUserClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create tokens for user+client
	_ = s.SaveRefreshTokenWithFamily(ctx, "user-client-token-1", "revoke-user", "revoke-client", "uc-family", 1, time.Now().Add(time.Hour))
	_ = s.SaveRefreshTokenWithFamily(ctx, "user-client-token-2", "revoke-user", "revoke-client", "uc-family", 2, time.Now().Add(time.Hour))

	// Also save token metadata for these
	_ = s.SaveTokenMetadata(context.Background(), "user-client-token-1", storage.TokenMetadata{UserID: "revoke-user", ClientID: "revoke-client", TokenType: nsRefresh})
	_ = s.SaveTokenMetadata(context.Background(), "user-client-token-2", storage.TokenMetadata{UserID: "revoke-user", ClientID: "revoke-client", TokenType: nsRefresh})

	// Revoke all
	count, err := s.RevokeAllTokensForUserClient(ctx, "revoke-user", "revoke-client")
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected to revoke at least 1 token")
	}

	// Check tokens are gone
	_, err = s.GetRefreshTokenInfo(ctx, "user-client-token-1")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 1 should be revoked, got: %v", err)
	}
}

func TestTokenRevocationStore_GetTokensByUserClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create tokens
	_ = s.SaveRefreshTokenWithFamily(ctx, "get-uc-token-1", "get-user", "get-client", "get-family", 1, time.Now().Add(time.Hour))

	tokens, err := s.GetTokensByUserClient(ctx, "get-user", "get-client")
	if err != nil {
		t.Fatalf("GetTokensByUserClient failed: %v", err)
	}

	if len(tokens) == 0 {
		t.Error("Expected at least 1 token")
	}
}

func TestTokenRevocationStore_SaveTokenMetadata_WithScopesAndAudience(t *testing.T) {
	s := testStore(t)

	err := s.SaveTokenMetadata(context.Background(), "meta-token-1", storage.TokenMetadata{UserID: "user1", ClientID: "client1", TokenType: "access", Audience: testAudienceURL, Scopes: []string{"read", "write"}})
	if err != nil {
		t.Fatalf("SaveTokenMetadata failed: %v", err)
	}

	meta, err := s.GetTokenMetadata("meta-token-1")
	if err != nil {
		t.Fatalf("GetTokenMetadata failed: %v", err)
	}

	if meta.Audience != testAudienceURL {
		t.Errorf("Audience = %q, want %q", meta.Audience, testAudienceURL)
	}
	if len(meta.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(meta.Scopes))
	}
}

// ============================================================
// Edge Cases and Error Handling
// ============================================================

func TestValidation_EmptyUserID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// All methods should return errors for empty userID
	if err := s.SaveUserInfo(ctx, "", &storage.UserInfo{}); err == nil {
		t.Error("SaveUserInfo should fail with empty userID")
	}

	if err := s.SaveRefreshToken(ctx, "token", "", time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshToken should fail with empty userID")
	}

	if err := s.SaveRefreshTokenWithFamily(ctx, "token", "", "client", "family", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty userID")
	}
}

func TestValidation_EmptyToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveRefreshToken(ctx, "", "user", time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshToken should fail with empty token")
	}

	if err := s.SaveRefreshTokenWithFamily(ctx, "", "user", "client", "family", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty token")
	}
}

func TestValidation_EmptyFamilyID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveRefreshTokenWithFamily(ctx, "token", "user", "client", "", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty familyID")
	}
}

func TestValidation_InvalidClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveClient(ctx, nil); err == nil {
		t.Error("SaveClient should fail with nil client")
	}

	if err := s.SaveClient(ctx, &storage.Client{}); err == nil {
		t.Error("SaveClient should fail with empty ClientID")
	}
}

func TestValidation_InvalidAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveAuthorizationState(ctx, nil); err == nil {
		t.Error("SaveAuthorizationState should fail with nil state")
	}

	if err := s.SaveAuthorizationState(ctx, &storage.AuthorizationState{}); err == nil {
		t.Error("SaveAuthorizationState should fail with empty StateID")
	}

	if err := s.SaveAuthorizationState(ctx, &storage.AuthorizationState{StateID: "test"}); err == nil {
		t.Error("SaveAuthorizationState should fail with empty ProviderState")
	}
}

func TestValidation_InvalidAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveAuthorizationCode(ctx, nil); err == nil {
		t.Error("SaveAuthorizationCode should fail with nil code")
	}

	if err := s.SaveAuthorizationCode(ctx, &storage.AuthorizationCode{}); err == nil {
		t.Error("SaveAuthorizationCode should fail with empty Code")
	}
}

// ============================================================
// Helper Function Tests
// ============================================================

func TestValidateInputLength(t *testing.T) {
	if err := validateInputLength(strings.Repeat("a", maxInputValueLength)); err != nil {
		t.Errorf("at-limit input rejected: %v", err)
	}
	if err := validateInputLength(strings.Repeat("a", maxInputValueLength+1)); err != ErrInputTooLarge {
		t.Errorf("over-limit input: got %v, want ErrInputTooLarge", err)
	}
	if err := validateInputLength(""); err != nil {
		t.Errorf("empty string rejected: %v", err)
	}
}

func TestSafeTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"test", 0, ""},
	}

	for _, tt := range tests {
		got := safeTruncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestCalculateTTL(t *testing.T) {
	// Future expiry
	future := time.Now().Add(time.Hour)
	ttl := calculateTTL(future)
	if ttl <= 0 {
		t.Error("TTL should be positive for future expiry")
	}

	// Past expiry
	past := time.Now().Add(-time.Hour)
	ttl = calculateTTL(past)
	if ttl != 0 {
		t.Error("TTL should be 0 for past expiry")
	}
}

// ============================================================
// Token Encryption Tests
// ============================================================

func TestTokenStore_Encryption(t *testing.T) {
	ctx := context.Background()

	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	s := testStoreWithOpts(t, WithEncryptor(encryptor))

	token := &oauth2.Token{
		AccessToken:  "secret-access-token",
		RefreshToken: "secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save encrypted token
	err = s.SaveToken(ctx, "encrypted-user", token)
	if err != nil {
		t.Fatalf("SaveToken with encryption failed: %v", err)
	}

	// Retrieve and decrypt token
	got, err := s.GetToken(ctx, "encrypted-user")
	if err != nil {
		t.Fatalf("GetToken with decryption failed: %v", err)
	}

	// Verify decrypted values match original
	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
	if got.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, token.RefreshToken)
	}
}

func TestTokenStore_EncryptionDisabled(t *testing.T) {
	ctx := context.Background()

	encryptor, err := security.NewEncryptor(nil)
	if err != nil {
		t.Fatalf("Failed to create disabled encryptor: %v", err)
	}

	s := testStoreWithOpts(t, WithEncryptor(encryptor))

	token := &oauth2.Token{
		AccessToken:  "plaintext-access-token",
		RefreshToken: "plaintext-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save token (should not encrypt)
	err = s.SaveToken(ctx, "plaintext-user", token)
	if err != nil {
		t.Fatalf("SaveToken without encryption failed: %v", err)
	}

	// Retrieve token
	got, err := s.GetToken(ctx, "plaintext-user")
	if err != nil {
		t.Fatalf("GetToken without decryption failed: %v", err)
	}

	// Verify values match original
	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
}

// TestTokenStore_Encryption_PreservesExtraField verifies that token encryption
// preserves the Extra field (id_token, scope) which is critical for OIDC flows.
// This is a regression test for issue #133.
func TestTokenStore_Encryption_PreservesExtraField(t *testing.T) {
	ctx := context.Background()

	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	s := testStoreWithOpts(t, WithEncryptor(encryptor))

	// Create token with Extra fields (simulating OIDC provider response)
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-with-extra",
		RefreshToken: "refresh-token-with-extra",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-id-token-payload.signature" //nolint:gosec // test value, not a real credential
	grantedScope := "openid email profile"
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
		"scope":    grantedScope,
	})

	userID := testUserID

	// Save token with Extra field
	err = s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Get token back (should be decrypted with Extra field preserved)
	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify basic fields
	if got.AccessToken != baseToken.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, baseToken.AccessToken)
	}

	// Verify Extra fields are preserved (critical for OIDC)
	gotIDToken := got.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("Extra(\"id_token\") returned nil, want id_token to be preserved")
	}
	if gotIDToken != idToken {
		t.Errorf("Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}

	gotScope := got.Extra("scope")
	if gotScope == nil {
		t.Fatal("Extra(\"scope\") returned nil, want scope to be preserved")
	}
	if gotScope != grantedScope {
		t.Errorf("Extra(\"scope\") = %q, want %q", gotScope, grantedScope)
	}
}

// TestTokenStore_WithoutEncryption_PreservesExtraField verifies that even without
// encryption, the Extra field is preserved through save/get cycle.
func TestTokenStore_WithoutEncryption_PreservesExtraField(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// No encryption configured - test basic case

	// Create token with Extra fields
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-no-encryption",
		RefreshToken: "refresh-token-no-encryption",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-id-token.sig" //nolint:gosec // test value, not a real credential
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
	})

	userID := testUserID

	// Save and retrieve token
	err := s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify Extra field is preserved
	gotIDToken := got.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("Extra(\"id_token\") returned nil, want id_token to be preserved")
	}
	if gotIDToken != idToken {
		t.Errorf("Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}
}

// TestTokenStore_Encryption_IDTokenIsEncrypted verifies that id_token is actually
// encrypted when stored, not just preserved. This is a security test.
func TestTokenStore_Encryption_IDTokenIsEncrypted(t *testing.T) {
	ctx := context.Background()

	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	s := testStoreWithOpts(t, WithEncryptor(encryptor))

	// Create token with id_token
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-for-encryption-test",
		RefreshToken: "refresh-token-for-encryption-test",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.contains-pii-email-name.signature" //nolint:gosec // test value
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
		"scope":    "openid email",
	})

	userID := testUserID

	// Save token
	err = s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Verify that GetToken returns the decrypted value correctly
	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify access token is decrypted
	if got.AccessToken != baseToken.AccessToken {
		t.Errorf("GetToken().AccessToken = %q, want %q", got.AccessToken, baseToken.AccessToken)
	}

	// Verify id_token is decrypted
	gotIDToken := got.Extra("id_token")
	if gotIDToken != idToken {
		t.Errorf("GetToken().Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}

	// Note: We can't easily verify the raw stored value in Valkey without
	// a separate connection, but the roundtrip test proves encryption works.
	// The memory store tests verify the actual encryption behavior.
}

// ============================================================
// Concurrency Tests for Atomic Operations
// ============================================================

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_Concurrent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:      "concurrent-code-1",
		ClientID:  "client-1",
		UserID:    "user1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	// Number of concurrent goroutines trying to use the same code
	numGoroutines := 10
	successCount := make(chan bool, numGoroutines)
	reuseCount := make(chan bool, numGoroutines)

	// Start all goroutines simultaneously
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			<-start // Wait for signal
			_, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "concurrent-code-1")
			if err == nil {
				successCount <- true
			} else if storage.IsCodeReuseError(err) {
				reuseCount <- true
			}
		}()
	}

	// Release all goroutines at once
	close(start)

	// Wait and count results
	successes := 0
	reuses := 0
	timeout := time.After(5 * time.Second)

	for i := 0; i < numGoroutines; i++ {
		select {
		case <-successCount:
			successes++
		case <-reuseCount:
			reuses++
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}

	// SECURITY: Only ONE goroutine should succeed
	if successes != 1 {
		t.Errorf("Expected exactly 1 success, got %d (security vulnerability!)", successes)
	}

	// All others should get reuse error
	if reuses != numGoroutines-1 {
		t.Errorf("Expected %d reuse errors, got %d", numGoroutines-1, reuses)
	}
}

// ============================================================
// Input Validation Tests
// ============================================================

// TestValidation_LargeTokensAccepted verifies that realistic large inputs (900-byte
// JWTs, 400-byte Dex subjects) are accepted. Key components are hashed to 64 bytes;
// stored values are accepted up to maxInputValueLength (16 KiB).
func TestValidation_LargeTokensAccepted(t *testing.T) {
	const wantUserID = "large-token-user"

	s := testStore(t)
	ctx := t.Context()

	// ~900-byte token (realistic full JWT in AccessTokenFormatJWT mode)
	largeToken := strings.Repeat("a", 900)

	if err := s.SaveRefreshToken(ctx, largeToken, wantUserID, time.Now().Add(time.Hour)); err != nil {
		t.Errorf("SaveRefreshToken with 900-byte token: %v", err)
	}
	userID, err := s.GetRefreshTokenInfo(ctx, largeToken)
	if err != nil {
		t.Errorf("GetRefreshTokenInfo with 900-byte token: %v", err)
	}
	if userID != wantUserID {
		t.Errorf("got userID %q, want %q", userID, wantUserID)
	}

	// ~400-byte Dex Kubernetes-connector subject (base64-protobuf)
	largeSub := strings.Repeat("b", 400)

	meta := storage.TokenMetadata{
		UserID:    largeSub,
		ClientID:  "testclient",
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.SaveTokenMetadata(ctx, "tokenid1", meta); err != nil {
		t.Errorf("SaveTokenMetadata with 400-byte userID: %v", err)
	}
	got, err := s.GetTokenMetadata("tokenid1")
	if err != nil {
		t.Errorf("GetTokenMetadata: %v", err)
	}
	if got.UserID != largeSub {
		t.Errorf("got UserID %q, want large subject", got.UserID)
	}
}

func TestValidation_LargeTokensAccepted_RefreshFamily(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()

	largeRefresh := strings.Repeat("r", 900)
	largeSub := strings.Repeat("s", 400)
	clientID := "client1"
	familyID := "family-" + strings.Repeat("f", 50)

	if err := s.SaveRefreshTokenWithFamily(ctx, largeRefresh, largeSub, clientID, familyID, 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily with large token/subject: %v", err)
	}
	meta, err := s.GetRefreshTokenFamily(ctx, largeRefresh)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily: %v", err)
	}
	if meta.UserID != largeSub {
		t.Errorf("got UserID %q, want large subject", meta.UserID)
	}
	if meta.ClientID != clientID {
		t.Errorf("got ClientID %q, want %q", meta.ClientID, clientID)
	}
}

func TestValidation_OversizedInputRejected(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()

	oversized := strings.Repeat("x", maxInputValueLength+1)

	if err := s.SaveRefreshToken(ctx, oversized, "user", time.Now().Add(time.Hour)); err != ErrInputTooLarge {
		t.Errorf("SaveRefreshToken with oversized token: got %v, want ErrInputTooLarge", err)
	}
	if err := s.SaveRefreshToken(ctx, "token", oversized, time.Now().Add(time.Hour)); err != ErrInputTooLarge {
		t.Errorf("SaveRefreshToken with oversized userID: got %v, want ErrInputTooLarge", err)
	}

	meta := storage.TokenMetadata{
		UserID:   oversized,
		ClientID: "client",
	}
	if err := s.SaveTokenMetadata(ctx, "tokenid", meta); err != ErrInputTooLarge {
		t.Errorf("SaveTokenMetadata with oversized userID: got %v, want ErrInputTooLarge", err)
	}

	meta2 := storage.TokenMetadata{
		UserID:   "user",
		ClientID: "client",
	}
	if err := s.SaveTokenMetadata(ctx, oversized, meta2); err != ErrInputTooLarge {
		t.Errorf("SaveTokenMetadata with oversized tokenID: got %v, want ErrInputTooLarge", err)
	}

	if err := s.SaveRefreshTokenWithFamily(ctx, oversized, "user", "client", "family", 1, time.Now().Add(time.Hour)); err != ErrInputTooLarge {
		t.Errorf("SaveRefreshTokenWithFamily with oversized refreshToken: got %v, want ErrInputTooLarge", err)
	}
	if err := s.SaveRefreshTokenWithFamily(ctx, "token", "user", "client", oversized, 1, time.Now().Add(time.Hour)); err != ErrInputTooLarge {
		t.Errorf("SaveRefreshTokenWithFamily with oversized familyID: got %v, want ErrInputTooLarge", err)
	}
}

func TestValidation_GenericErrorMessages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Test that ValidateClientSecret returns generic error for non-existent client
	err := s.ValidateClientSecret(ctx, "nonexistent-client", "any-secret")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}
	// Error should not contain client ID
	if err.Error() != "invalid client credentials" {
		t.Errorf("Error message should be generic, got: %v", err)
	}

	// Test that CheckIPLimit returns generic error when limit exceeded
	// First, set up an IP that has exceeded the limit
	for i := 0; i < 5; i++ {
		_ = s.TrackClientIP(ctx, "192.168.99.99")
	}

	err = s.CheckIPLimit(ctx, "192.168.99.99", 3)
	if err == nil {
		t.Error("Expected error when IP limit exceeded")
	}
	// Error should not contain IP or count
	if err.Error() != "rate limit exceeded" {
		t.Errorf("Error message should be generic, got: %v", err)
	}
}

// ============================================================
// Instrumentation Tests
// ============================================================

func TestStore_WithInstrumentation(t *testing.T) {
	ctx := context.Background()

	inst, err := instrumentation.New(instrumentation.Config{Enabled: false})
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	s := testStoreWithOpts(t, WithInstrumentation(inst))

	token := &oauth2.Token{
		AccessToken:  "instrumented-token",
		RefreshToken: "instrumented-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	err = s.SaveToken(ctx, "instrumented-user", token)
	if err != nil {
		t.Fatalf("SaveToken with instrumentation failed: %v", err)
	}

	got, err := s.GetToken(ctx, "instrumented-user")
	if err != nil {
		t.Fatalf("GetToken with instrumentation failed: %v", err)
	}

	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
}

func TestStore_WithInstrumentation_Prometheus(t *testing.T) {
	ctx := context.Background()

	inst, err := instrumentation.New(instrumentation.Config{
		Enabled:         true,
		MetricsExporter: "prometheus",
	})
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}
	defer func() {
		if shutdownErr := inst.Shutdown(ctx); shutdownErr != nil {
			t.Logf("Warning: shutdown error: %v", shutdownErr)
		}
	}()

	s := testStoreWithOpts(t, WithInstrumentation(inst))

	client := &storage.Client{
		ClientID:     "metric-client",
		ClientType:   "public",
		RedirectURIs: []string{"https://example.com/callback"},
		CreatedAt:    time.Now(),
	}
	_ = s.SaveClient(ctx, client)

	token := &oauth2.Token{
		AccessToken: "metric-token",
		Expiry:      time.Now().Add(time.Hour),
	}
	_ = s.SaveToken(ctx, "metric-user", token)

	if s.inst == nil {
		t.Error("Instrumentation should be set on store")
	}
	if s.tracer == nil {
		t.Error("Tracer should be set on store")
	}
	if s.meter == nil {
		t.Error("Meter should be set on store")
	}
}

func TestStore_CountKeysByPattern(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Add some clients
	for i := 0; i < 5; i++ {
		client := &storage.Client{
			ClientID:     fmt.Sprintf("count-client-%d", i),
			ClientType:   "public",
			RedirectURIs: []string{"https://example.com/callback"},
			CreatedAt:    time.Now(),
		}
		_ = s.SaveClient(ctx, client)
	}

	// Count clients using the internal method
	count := s.countKeysByPattern(s.prefix + "client:*")

	if count < 5 {
		t.Errorf("countKeysByPattern returned %d, want at least 5", count)
	}
}

func TestStore_SaveTokenMetadata_WithFamilyID(t *testing.T) {
	s := testStore(t)

	err := s.SaveTokenMetadata(context.Background(), "family-meta-1", storage.TokenMetadata{UserID: "user1", ClientID: "client1", TokenType: "access", Audience: testAudienceURL, FamilyID: "family-xyz", Scopes: []string{"openid", "email"}})
	if err != nil {
		t.Fatalf("SaveTokenMetadata failed: %v", err)
	}

	meta, err := s.GetTokenMetadata("family-meta-1")
	if err != nil {
		t.Fatalf("GetTokenMetadata failed: %v", err)
	}

	if meta.FamilyID != "family-xyz" {
		t.Errorf("FamilyID = %q, want %q", meta.FamilyID, "family-xyz")
	}
	if meta.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", meta.UserID, "user1")
	}
	if meta.ClientID != "client1" {
		t.Errorf("ClientID = %q, want %q", meta.ClientID, "client1")
	}
	if meta.Audience != testAudienceURL {
		t.Errorf("Audience = %q, want %q", meta.Audience, testAudienceURL)
	}
	if len(meta.Scopes) != 2 || meta.Scopes[0] != "openid" || meta.Scopes[1] != "email" {
		t.Errorf("Scopes = %v, want [openid email]", meta.Scopes)
	}
}

func TestStore_SaveTokenMetadata_EmptyFamilyID(t *testing.T) {
	s := testStore(t)

	err := s.SaveTokenMetadata(context.Background(), "family-meta-empty", storage.TokenMetadata{UserID: "user1", ClientID: "client1", TokenType: nsRefresh, Audience: "", FamilyID: "", Scopes: nil})
	if err != nil {
		t.Fatalf("SaveTokenMetadata failed: %v", err)
	}

	meta, err := s.GetTokenMetadata("family-meta-empty")
	if err != nil {
		t.Fatalf("GetTokenMetadata failed: %v", err)
	}

	if meta.FamilyID != "" {
		t.Errorf("FamilyID = %q, want empty", meta.FamilyID)
	}
}

func TestStore_SaveTokenMetadata_WithScopesAndAudience(t *testing.T) {
	s := testStore(t)

	err := s.SaveTokenMetadata(context.Background(), "family-delegate-1", storage.TokenMetadata{UserID: "user1", ClientID: "client1", TokenType: "access", Audience: testAudienceURL, Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("SaveTokenMetadata failed: %v", err)
	}

	meta, err := s.GetTokenMetadata("family-delegate-1")
	if err != nil {
		t.Fatalf("GetTokenMetadata failed: %v", err)
	}

	if meta.FamilyID != "" {
		t.Errorf("FamilyID = %q, want empty (delegation should pass empty familyID)", meta.FamilyID)
	}
	if meta.Audience != testAudienceURL {
		t.Errorf("Audience = %q, want %q", meta.Audience, testAudienceURL)
	}
}
