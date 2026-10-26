package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// providerRevocations records the credentials the provider was asked to revoke.
type providerRevocations struct {
	mu      sync.Mutex
	revoked []string
}

func (r *providerRevocations) revoke(_ context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, token)
	return nil
}

func (r *providerRevocations) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.revoked...)
}

// recordSessionRevocations makes srv record the families its session
// revocation handler is called for.
func recordSessionRevocations(srv *Server) func() []string {
	var mu sync.Mutex
	var families []string
	srv.sessionRevocationHandler = func(_ context.Context, _, familyID string) {
		mu.Lock()
		defer mu.Unlock()
		families = append(families, familyID)
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), families...)
	}
}

// TestRefreshTokenReuse_RevokesOnlyReusedFamily: reusing a refresh token
// revokes that family alone. The user's second family on the same client and
// a third on another client keep refreshing, and the shared Dex grant they
// refresh through is neither revoked at Dex nor deleted.
func TestRefreshTokenReuse_RevokesOnlyReusedFamily(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)
	revocations := &providerRevocations{}
	srv.provider.(*mock.Provider).RevokeTokenFunc = revocations.revoke
	sessionRevocations := recordSessionRevocations(srv)

	otherClient, _, err := srv.RegisterClient(ctx, "muster", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	require.NoError(t, err)

	rtA := loginRaceSession(t, srv, store, dex, clientID)
	rtB := loginRaceSession(t, srv, store, dex, clientID)
	rtC := loginRaceSession(t, srv, store, dex, otherClient.ClientID)
	familyA, err := store.GetRefreshTokenFamily(ctx, rtA)
	require.NoError(t, err)
	familyB, err := store.GetRefreshTokenFamily(ctx, rtB)
	require.NoError(t, err)
	require.NotEqual(t, familyA.FamilyID, familyB.FamilyID)

	tokA2, err := srv.RefreshAccessToken(ctx, rtA, clientID)
	require.NoError(t, err)

	_, err = srv.RefreshAccessToken(ctx, rtA, clientID)
	require.ErrorIs(t, err, errInvalidGrant, "reuse of a rotated-away refresh token must be rejected")

	_, err = srv.RefreshAccessToken(ctx, tokA2.RefreshToken, clientID)
	require.Error(t, err, "the reused family's successor must be revoked")
	_, err = store.GetToken(ctx, tokA2.AccessToken)
	require.Error(t, err, "the reused family's access token must be revoked")
	tokens, err := store.GetTokensByUserClient(ctx, familyA.UserID, clientID)
	require.NoError(t, err)
	require.NotContains(t, tokens, tokA2.AccessToken)
	require.NotContains(t, tokens, tokA2.RefreshToken)

	tokB2, err := srv.RefreshAccessToken(ctx, rtB, clientID)
	require.NoError(t, err, "the user's other family on the same client must stay valid")
	_, err = srv.RefreshAccessToken(ctx, rtC, otherClient.ClientID)
	require.NoError(t, err, "the user's family on another client must stay valid")
	_, err = srv.RefreshAccessToken(ctx, tokB2.RefreshToken, clientID)
	require.NoError(t, err, "the other family must keep rotating")

	_, err = store.GetUserProviderToken(ctx, familyA.UserID)
	require.NoError(t, err, "the shared Dex grant must be kept")
	require.Empty(t, revocations.list(), "the shared Dex grant must not be revoked at Dex")
	require.Equal(t, []string{familyA.FamilyID}, sessionRevocations())
}

// legacyLayoutStore is a memory store without storage.UserProviderTokenStore:
// every token holds its own copy of its family's provider grant.
type legacyLayoutStore struct {
	storage.Combined
	storage.RefreshTokenFamilyStore
	storage.TokenRevocationStore
	storage.TokenFamilyRevocationStore
	storage.TokenMetadataStore
	storage.TokenMetadataGetter
}

// TestRefreshTokenReuse_LegacyLayoutRevokesFamilyGrantOnly: in the legacy
// layout each login holds its own Dex grant; reuse revokes the reused
// family's grant at Dex and leaves the other family's grant and session
// alone.
func TestRefreshTokenReuse_LegacyLayoutRevokesFamilyGrantOnly(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	t.Cleanup(mem.Stop)
	store := legacyLayoutStore{
		Combined: mem, RefreshTokenFamilyStore: mem, TokenRevocationStore: mem,
		TokenFamilyRevocationStore: mem, TokenMetadataStore: mem, TokenMetadataGetter: mem,
	}
	provider := mock.NewProvider()
	revocations := &providerRevocations{}
	provider.RevokeTokenFunc = revocations.revoke
	var logins int
	provider.ExchangeCodeFunc = func(context.Context, string, string) (*oauth2.Token, error) {
		logins++
		return &oauth2.Token{
			AccessToken:  fmt.Sprintf("dex-at-login-%d", logins),
			RefreshToken: fmt.Sprintf("dex-rt-login-%d", logins),
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}
	srv, err := New(provider, store, store, store, &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email"},
		AccessTokenTTL:              600,
		RefreshTokenTTL:             86400,
		AllowRefreshTokenRotation:   true,
		DisableNonceEchoRequirement: true,
	}, nil)
	require.NoError(t, err)
	_, unified := srv.userProviderTokenStore()
	require.False(t, unified, "the fixture must use the legacy layout")
	client, secret, err := srv.RegisterClient(ctx, "gateway", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	require.NoError(t, err)
	f := &faultyGrantFixture{srv: srv, store: mem, clientID: client.ClientID, clientSecret: secret}

	rtA := f.login(t).RefreshToken
	rtB := f.login(t).RefreshToken
	tokA2, err := srv.RefreshAccessToken(ctx, rtA, f.clientID)
	require.NoError(t, err)

	_, err = srv.RefreshAccessToken(ctx, rtA, f.clientID)
	require.ErrorIs(t, err, errInvalidGrant)
	_, err = srv.RefreshAccessToken(ctx, tokA2.RefreshToken, f.clientID)
	require.Error(t, err, "the reused family's successor must be revoked")

	require.Contains(t, revocations.list(), "dex-rt-login-1", "the reused family's Dex grant must be revoked")
	require.NotContains(t, revocations.list(), "dex-rt-login-2", "the other family's Dex grant must be kept")
	_, err = srv.RefreshAccessToken(ctx, rtB, f.clientID)
	require.NoError(t, err, "the user's other family must stay valid")
}

// SECURITY: the token_reuse_detected event that alerts are set on reports
// the family revocation that happened, at the client that presented the token.
func TestRefreshTokenReuse_AuditsTheFamilyRevocation(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)
	logger, logs := captureLogger()
	srv.Auditor = security.NewAuditor(logger, true)
	rt := loginRaceSession(t, srv, store, dex, clientID)
	_, err := srv.RefreshAccessToken(ctx, rt, clientID)
	require.NoError(t, err)
	logs.Reset()

	_, err = srv.RefreshAccessToken(ctx, rt, clientID)

	require.ErrorIs(t, err, errInvalidGrant)
	var event string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, "event_type="+security.EventTokenReuseDetected) {
			event = line
		}
	}
	require.NotEmpty(t, event, logs.String())
	require.Contains(t, event, "action:family_revoked")
	require.Contains(t, event, "audit.client_id="+clientID)
	require.Contains(t, event, `audit.ip_address=""`, "the client is not reported as the IP address")
	require.NotContains(t, event, "all_tokens_revoked")
}
