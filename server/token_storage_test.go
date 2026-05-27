package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// failingTokenStore wraps a storage.TokenStore so individual save paths can be
// forced to return an error, letting tests assert how saveUserInfoAndToken
// classifies each failure (fatal vs best-effort).
type failingTokenStore struct {
	storage.TokenStore
	saveTokenByIDErr       error
	saveTokenByEmailErr    error
	saveUserInfoByIDErr    error
	saveUserInfoByEmailErr error
}

func (f *failingTokenStore) SaveToken(ctx context.Context, userID string, token *oauth2.Token) error {
	if userID == testUserID && f.saveTokenByIDErr != nil {
		return f.saveTokenByIDErr
	}
	if userID == testUserEmail && f.saveTokenByEmailErr != nil {
		return f.saveTokenByEmailErr
	}
	return f.TokenStore.SaveToken(ctx, userID, token)
}

func (f *failingTokenStore) SaveUserInfo(ctx context.Context, userID string, info *storage.UserInfo) error {
	if userID == testUserID && f.saveUserInfoByIDErr != nil {
		return f.saveUserInfoByIDErr
	}
	if userID == testUserEmail && f.saveUserInfoByEmailErr != nil {
		return f.saveUserInfoByEmailErr
	}
	return f.TokenStore.SaveUserInfo(ctx, userID, info)
}

func testProviderToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  "upstream-access",
		RefreshToken: "upstream-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
}

func testUserInfo() *providers.UserInfo {
	return &providers.UserInfo{
		ID:    testUserID,
		Email: testUserEmail,
	}
}

func TestSaveUserInfoAndToken_IDPathFailureIsFatal(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(*failingTokenStore)
		wantInErr string
		wantAudit string
	}{
		{
			name: "SaveToken by ID fails",
			setup: func(f *failingTokenStore) {
				f.saveTokenByIDErr = errors.New("input exceeds maximum allowed size")
			},
			wantInErr: "save provider token by id",
			wantAudit: "save_token_by_id",
		},
		{
			name: "SaveUserInfo by ID fails",
			setup: func(f *failingTokenStore) {
				f.saveUserInfoByIDErr = errors.New("backend unavailable")
			},
			wantInErr: "save user info by id",
			wantAudit: "save_user_info_by_id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem := memory.New()
			t.Cleanup(func() { mem.Stop() })
			fts := &failingTokenStore{TokenStore: mem}
			tc.setup(fts)

			logger, auditBuf := captureLogger()
			provider := mock.NewProvider()
			config := &Config{
				Issuer:                      "https://auth.example.com",
				SupportedScopes:             []string{"openid", "email"},
				DisableNonceEchoRequirement: true,
			}
			srv, err := New(provider, fts, mem, mem, config, logger)
			require.NoError(t, err)
			srv.auditor = security.NewAuditor(logger, true)

			err = srv.saveUserInfoAndToken(context.Background(), testUserInfo(), testProviderToken())
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantInErr)
			require.True(t,
				containsAuditEvent(auditBuf.String(), security.EventProviderTokenStorageFailed),
				"audit event %s missing from log: %s", security.EventProviderTokenStorageFailed, auditBuf.String())
			require.Contains(t, auditBuf.String(), tc.wantAudit)
		})
	}
}

func TestSaveUserInfoAndToken_EmailPathFailureIsBestEffort(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(*failingTokenStore)
		wantAudit string
	}{
		{
			name: "SaveToken by email fails",
			setup: func(f *failingTokenStore) {
				f.saveTokenByEmailErr = errors.New("input exceeds maximum allowed size")
			},
			wantAudit: "save_token_by_email",
		},
		{
			name: "SaveUserInfo by email fails",
			setup: func(f *failingTokenStore) {
				f.saveUserInfoByEmailErr = errors.New("backend unavailable")
			},
			wantAudit: "save_user_info_by_email",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem := memory.New()
			t.Cleanup(func() { mem.Stop() })
			fts := &failingTokenStore{TokenStore: mem}
			tc.setup(fts)

			logger, auditBuf := captureLogger()
			provider := mock.NewProvider()
			config := &Config{
				Issuer:                      "https://auth.example.com",
				SupportedScopes:             []string{"openid", "email"},
				DisableNonceEchoRequirement: true,
			}
			srv, err := New(provider, fts, mem, mem, config, logger)
			require.NoError(t, err)
			srv.auditor = security.NewAuditor(logger, true)

			err = srv.saveUserInfoAndToken(context.Background(), testUserInfo(), testProviderToken())
			require.NoError(t, err, "email-keyed failures must not fail the auth flow")
			require.True(t,
				containsAuditEvent(auditBuf.String(), security.EventProviderTokenStorageFailed),
				"audit event %s missing from log: %s", security.EventProviderTokenStorageFailed, auditBuf.String())
			require.Contains(t, auditBuf.String(), tc.wantAudit)
		})
	}
}

func TestSaveUserInfoAndToken_MissingSubjectIsFatal(t *testing.T) {
	mem := memory.New()
	t.Cleanup(func() { mem.Stop() })

	logger, auditBuf := captureLogger()
	provider := mock.NewProvider()
	config := &Config{
		Issuer:                      "https://auth.example.com",
		DisableNonceEchoRequirement: true,
	}
	srv, err := New(provider, mem, mem, mem, config, logger)
	require.NoError(t, err)
	srv.auditor = security.NewAuditor(logger, true)

	err = srv.saveUserInfoAndToken(context.Background(), &providers.UserInfo{Email: testUserEmail}, testProviderToken())
	require.Error(t, err)
	require.Contains(t, err.Error(), "UserInfo.ID is empty")
	require.True(t,
		containsAuditEvent(auditBuf.String(), security.EventProviderTokenStorageFailed),
		"audit event %s missing", security.EventProviderTokenStorageFailed)
	require.Contains(t, auditBuf.String(), "missing_subject")
}
