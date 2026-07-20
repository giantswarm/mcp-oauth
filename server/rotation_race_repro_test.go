package server

// Reproduction of the refresh-token rotation race described in
// giantswarm/giantswarm#37164 (root cause 2) and the bumblebee-plans
// mcp-oauth-rotation-race PRD.
//
// Scenario: one user, two MCP sessions (same OAuth client). Both sessions'
// provider-token copies hold the SAME single-use dex refresh token — exactly
// the state silent authentication / the login-time sub/email keys produce.
// dex rotates on first use; the loser gets "already claimed", its mcp refresh
// token was already deleted (refresh.go: delete at AtomicGetAndDeleteRefreshToken
// happens BEFORE the provider call), the client's retry re-presents the deleted
// token → reuse detection → RevokeAllTokensForUserClient → every session dies.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// singleUseDex emulates dex's refresh-token rotation: a refresh token is
// valid exactly once; reusing a rotated-away token fails like dex does
// ("Refresh token is invalid or has already been claimed by another client").
type singleUseDex struct {
	mu        sync.Mutex
	currentRT string
	gen       int
	calls     int
}

func newSingleUseDex() *singleUseDex {
	return &singleUseDex{currentRT: "dex-rt-0"}
}

func (d *singleUseDex) refresh(_ context.Context, rt string) (*oauth2.Token, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if rt != d.currentRT {
		return nil, fmt.Errorf(`oauth2: "invalid_request" "Refresh token is invalid or has already been claimed by another client"`)
	}
	d.gen++
	d.currentRT = fmt.Sprintf("dex-rt-%d", d.gen)
	return &oauth2.Token{
		AccessToken:  fmt.Sprintf("dex-at-%d", d.gen),
		TokenType:    "Bearer",
		RefreshToken: d.currentRT,
		Expiry:       time.Now().Add(30 * time.Minute),
	}, nil
}

func (d *singleUseDex) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// loginRaceSession runs the full auth-code flow for the test user and returns
// the session's mcp refresh token. The provider (dex) hands out its CURRENT
// refresh token on code exchange — so every session of the user ends up
// holding the same single-use dex RT, as in production.
func loginRaceSession(t *testing.T, srv *Server, store *memory.Store, dex *singleUseDex, clientID string) string {
	t.Helper()
	ctx := context.Background()

	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err := srv.StartAuthorizationFlow(ctx, clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email", "", codeChallenge, PKCEMethodS256, clientState, nil)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}
	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}
	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, clientID,
		"https://example.com/callback", "", codeVerifier, "")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}
	if token.RefreshToken == "" {
		t.Fatal("login produced no refresh token")
	}
	return token.RefreshToken
}

func setupRaceServer(t *testing.T) (*Server, *memory.Store, *singleUseDex, string) {
	t.Helper()
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400
	srv.Config.TokenRefreshThreshold = 300 // 5m proactive threshold (production default)

	dex := newSingleUseDex()
	// Code exchange hands out dex's current RT with a SHORT expiry (2m,
	// below the 5m proactive threshold) so the first refresh genuinely
	// needs to talk to dex.
	provider.ExchangeCodeFunc = func(context.Context, string, string) (*oauth2.Token, error) {
		dex.mu.Lock()
		defer dex.mu.Unlock()
		return &oauth2.Token{
			AccessToken:  "dex-at-login",
			TokenType:    "Bearer",
			RefreshToken: dex.currentRT,
			Expiry:       time.Now().Add(2 * time.Minute),
		}, nil
	}
	provider.RefreshTokenFunc = dex.refresh

	client, _, err := srv.RegisterClient(ctx, "Claude Code", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	return srv, store, dex, client.ClientID
}

// TestRotationRace_TwoSessions reproduces the session-killing collision
// deterministically (no goroutines needed — the divergent copies make the
// race a certainty, not a timing accident):
//
//	v1.0.10 behavior (BUG): session B's refresh fails (provider_refresh_failed),
//	its retry trips reuse detection, and the revocation kills session A too.
//
//	Fixed behavior (plan): B's refresh succeeds without ever calling dex
//	(reads the shared fresh token), both sessions live, dex called exactly once.
func TestRotationRace_TwoSessions(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)

	rtA := loginRaceSession(t, srv, store, dex, clientID) // session A (e.g. Claude Code)
	rtB := loginRaceSession(t, srv, store, dex, clientID) // session B (e.g. claude.ai) — silent-auth copy of the same dex RT

	// Session A refreshes first and wins: dex rotates its RT.
	tokA2, err := srv.RefreshAccessToken(ctx, rtA, clientID)
	if err != nil {
		t.Fatalf("session A refresh should succeed, got: %v", err)
	}

	// Session B refreshes with its (now stale) copy of the dex RT.
	tokB2, errB := srv.RefreshAccessToken(ctx, rtB, clientID)
	if errB != nil {
		t.Logf("REPRODUCED bug step 1: session B refresh failed: %v", errB)
		// The MCP client retries — its refresh token was silently orphaned.
		_, retryErr := srv.RefreshAccessToken(ctx, rtB, clientID)
		t.Logf("REPRODUCED bug step 2: session B retry: %v (this is the reuse-detection nuke)", retryErr)
		// Collateral damage: session A's fresh token is revoked too.
		if _, errA2 := srv.RefreshAccessToken(ctx, tokA2.RefreshToken, clientID); errA2 != nil {
			t.Logf("REPRODUCED bug step 3: session A (innocent winner) killed as collateral: %v", errA2)
		}
		t.Fatalf("rotation race reproduced: benign concurrent sessions nuked (dex calls: %d)", dex.callCount())
	}

	// Fixed behavior: the colliding window produced exactly ONE dex call
	// (A refreshed, B adopted the shared fresh token without calling dex).
	if got := dex.callCount(); got != 1 {
		t.Fatalf("dex RefreshToken calls during collision = %d, want exactly 1 (single-flight)", got)
	}
	// And both sessions keep working afterwards.
	if _, err := srv.RefreshAccessToken(ctx, tokA2.RefreshToken, clientID); err != nil {
		t.Fatalf("session A follow-up refresh failed: %v", err)
	}
	if _, err := srv.RefreshAccessToken(ctx, tokB2.RefreshToken, clientID); err != nil {
		t.Fatalf("session B follow-up refresh failed: %v", err)
	}
}

// TestRotationRace_ConcurrentRefresh drives N sessions of one user into a
// truly concurrent refresh and asserts the plan's headline property: all
// sessions survive and dex is called exactly once.
func TestRotationRace_ConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)

	const n = 4
	rts := make([]string, n)
	for i := range rts {
		rts[i] = loginRaceSession(t, srv, store, dex, clientID)
	}

	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = srv.RefreshAccessToken(ctx, rts[i], clientID)
		}(i)
	}
	close(start)
	wg.Wait()

	failed := 0
	for i, err := range errs {
		if err != nil {
			failed++
			t.Logf("session %d refresh failed: %v", i, err)
		}
	}
	if failed > 0 {
		t.Fatalf("rotation race reproduced under concurrency: %d/%d sessions failed (dex calls: %d)", failed, n, dex.callCount())
	}
	if got := dex.callCount(); got != 1 {
		t.Fatalf("dex RefreshToken calls = %d, want exactly 1", got)
	}
}
