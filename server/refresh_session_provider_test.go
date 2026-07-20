package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// setupProviderRefreshServer builds a server like setupFlowTestServer but with
// an optional TokenRefreshHandler registered, so the RefreshSessionProvider
// tests can assert whether (and with what) the handler fires.
func setupProviderRefreshServer(t *testing.T, handler TokenRefreshHandler) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		AllowPKCEPlain:              false,
		ClockSkewGracePeriod:        5,
		DisableNonceEchoRequirement: true,
	}

	var opts []Option
	if handler != nil {
		opts = append(opts, WithTokenRefreshHandler(handler))
	}

	srv, err := New(provider, store, store, store, config, nil, opts...)
	require.NoError(t, err)
	return srv, store, provider
}

// TestRefreshSessionProvider_DoesNotRotateClientRefreshToken is the defect-#2
// guard: the background provider-only refresh must repopulate the id_token
// WITHOUT rotating the client-facing mcp refresh token. Contrast with
// RefreshSession (see TestRefreshSession_HappyPath), which delegates to
// RefreshAccessToken and DOES rotate the family's active refresh token — the
// rotation that eventually trips OAuth 2.1 reuse detection and deauths the user.
func TestRefreshSessionProvider_DoesNotRotateClientRefreshToken(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)
	ctx := context.Background()

	const (
		userID       = "user-1"
		clientID     = "client-x"
		familyID     = "fam-provider-only"
		refreshToken = "rt-provider-only-1"
	)
	seedFamilyForRefresh(t, store, userID, clientID, familyID, refreshToken)

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}).WithExtra(map[string]any{"id_token": "new.id.token"}), nil
	}

	// Precondition: this refresh token is the family's active member.
	before, _, err := store.GetActiveRefreshTokenByFamily(ctx, familyID)
	require.NoError(t, err)
	require.Equal(t, refreshToken, before)

	got, err := srv.RefreshSessionProvider(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "new.id.token", ExtractIDToken(got), "fresh id_token must be forwarded to the caller")

	// THE INVARIANT: the client's active refresh token is byte-identical after
	// the call — no rotation, no new family generation, no reuse-detection window.
	after, _, err := store.GetActiveRefreshTokenByFamily(ctx, familyID)
	require.NoError(t, err)
	require.Equal(t, refreshToken, after,
		"RefreshSessionProvider must NOT rotate the client refresh token (defect #2)")
}

// TestRefreshSessionProvider_FiresHandlerWhenIDTokenPresent verifies the
// TokenRefreshHandler fires with the resolved userID/familyID and the fresh
// id_token, so an SSO integration (muster) can repopulate its proxy store.
func TestRefreshSessionProvider_FiresHandlerWhenIDTokenPresent(t *testing.T) {
	type call struct{ userID, familyID, idToken string }
	var mu sync.Mutex
	var calls []call
	handler := func(_ context.Context, userID, familyID string, tok *oauth2.Token) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{userID, familyID, ExtractIDToken(tok)})
	}

	srv, store, provider := setupProviderRefreshServer(t, handler)
	ctx := context.Background()

	const (
		userID       = "user-1"
		familyID     = "fam-handler"
		refreshToken = "rt-handler"
	)
	seedFamilyForRefresh(t, store, userID, "client-x", familyID, refreshToken)

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return (&oauth2.Token{
			AccessToken:  "a",
			RefreshToken: "r",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}).WithExtra(map[string]any{"id_token": "fresh.id.jwt"}), nil
	}

	_, err := srv.RefreshSessionProvider(ctx, familyID)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, calls, 1, "handler must fire exactly once")
	require.Equal(t, userID, calls[0].userID)
	require.Equal(t, familyID, calls[0].familyID)
	require.Equal(t, "fresh.id.jwt", calls[0].idToken)
}

// TestRefreshSessionProvider_DoesNotFireHandlerWhenNoIDToken guards Finding #1:
// a provider refresh that returns no id_token (preserveRefreshToken carries the
// refresh token forward but never the id_token) writes an id_token-less shared
// entry. Firing muster's handler with that token would drive its
// handleUpstreamRefreshFailure eviction from the background loop. The method
// must therefore NOT fire the handler when the refreshed token has no id_token;
// a genuinely broken chain is still caught by the caller's own stale-token
// eviction.
func TestRefreshSessionProvider_DoesNotFireHandlerWhenNoIDToken(t *testing.T) {
	var count atomic.Int32
	handler := func(_ context.Context, _, _ string, _ *oauth2.Token) { count.Add(1) }

	srv, store, provider := setupProviderRefreshServer(t, handler)
	ctx := context.Background()

	const (
		userID       = "user-1"
		familyID     = "fam-no-idtoken"
		refreshToken = "rt-no-idtoken" //nolint:gosec // G101 false positive — test fixture label, not a credential
	)
	seedFamilyForRefresh(t, store, userID, "client-x", familyID, refreshToken)

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "a",
			RefreshToken: "r",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}, nil // no id_token in Extra
	}

	got, err := srv.RefreshSessionProvider(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, ExtractIDToken(got))
	require.Equal(t, int32(0), count.Load(),
		"handler must not fire when the refreshed token carries no id_token")
}

// TestRefreshSessionProvider_AdoptsFreshEntryWithoutProviderCall verifies the
// single-flight coordinator's adopt path: when the shared per-user provider
// entry is already fresh, the method returns it (with its still-valid id_token)
// without a provider round-trip — so a tight background retry loop cannot
// hammer the upstream IdP.
func TestRefreshSessionProvider_AdoptsFreshEntryWithoutProviderCall(t *testing.T) {
	var providerCalls atomic.Int32
	srv, store, provider := setupFlowTestServer(t)
	ctx := context.Background()

	const (
		userID       = "user-1"
		familyID     = "fam-adopt"
		refreshToken = "rt-adopt"
	)
	require.NoError(t, store.SaveRefreshTokenWithFamily(
		ctx, refreshToken, userID, "client-x", familyID, 0, time.Now().Add(24*time.Hour),
	))
	// Fresh shared provider entry carrying an id_token: far-future expiry so the
	// freshness check adopts it rather than refreshing.
	require.NoError(t, store.SaveUserProviderToken(ctx, userID, (&oauth2.Token{
		AccessToken:  "provider-access",
		RefreshToken: "provider-refresh",
		Expiry:       time.Now().Add(24 * time.Hour),
		TokenType:    "Bearer",
	}).WithExtra(map[string]any{"id_token": "cached.id.jwt"})))

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		providerCalls.Add(1)
		return &oauth2.Token{AccessToken: "should-not-be-used"}, nil
	}

	got, err := srv.RefreshSessionProvider(ctx, familyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, int32(0), providerCalls.Load(),
		"a fresh shared entry must be adopted without a provider round-trip")
	require.Equal(t, "cached.id.jwt", ExtractIDToken(got))
}

func TestRefreshSessionProvider_FamilyNotFound(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	_, err := srv.RefreshSessionProvider(context.Background(), "no-such-family")
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrRefreshTokenFamilyNotFound),
		"want wrapped ErrRefreshTokenFamilyNotFound, got %v", err)
}

func TestRefreshSessionProvider_RevokedFamily(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)
	ctx := context.Background()

	const familyID = "fam-revoked-provider"
	seedFamilyForRefresh(t, store, "user-1", "client-x", familyID, "rt-revoked-provider")
	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, familyID))

	_, err := srv.RefreshSessionProvider(ctx, familyID)
	require.Error(t, err, "RefreshSessionProvider on a revoked family must fail")
	require.True(t, errors.Is(err, storage.ErrRefreshTokenFamilyRevoked),
		"want wrapped ErrRefreshTokenFamilyRevoked, got %v", err)
}

func TestRefreshSessionProvider_RequiresFamilyID(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	_, err := srv.RefreshSessionProvider(context.Background(), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "familyID is required")
}
