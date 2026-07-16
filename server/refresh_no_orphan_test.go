package server

// L2 no-orphan reordering of the mcp refresh token — rotation-race slice 4
// (giantswarm/giantswarm#37164 root cause 2, giantswarm/mcp-oauth#515).
//
// Before this slice, RefreshAccessToken deleted the mcp refresh token BEFORE
// calling the provider, with no rollback: a transient provider hiccup orphaned
// an otherwise-valid session, and the client's retry re-presented the now-gone
// token → reuse detection → RevokeAllTokensForUserClient nuked every session of
// the user. After the reorder the token is rotated only once the shared provider
// token is confirmed fresh, so a blip no longer destroys a valid session while
// genuine refresh-token reuse still revokes the family and all user+client
// tokens.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// setupNoOrphanServer builds the same one-user/unified topology as the rotation
// race repro, but hands back the mock provider so the test can drive a transient
// refresh failure. Login issues a provider token with a short expiry (below the
// proactive threshold) so the first grant genuinely reaches the provider.
func setupNoOrphanServer(t *testing.T, dex *singleUseDex, refreshFn func(context.Context, string) (*oauth2.Token, error)) (*Server, string, string) {
	t.Helper()
	ctx := context.Background()

	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400
	srv.Config.TokenRefreshThreshold = 300 // 5m proactive threshold (production default)

	// Login hands out dex's current RT with a short expiry (below the proactive
	// threshold) so the first grant genuinely needs to reach the provider.
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
	provider.RefreshTokenFunc = refreshFn

	client, _, err := srv.RegisterClient(ctx, "Claude Code", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	rt := loginRaceSession(t, srv, store, dex, client.ClientID)
	return srv, client.ClientID, rt
}

// TestRefreshAccessToken_TransientProviderFailure_NoOrphan is the headline
// acceptance test for slice 4: a transient provider-refresh failure must leave
// the session's mcp refresh token intact and usable, so the client's retry
// succeeds instead of orphaning the session and tripping the reuse nuke.
func TestRefreshAccessToken_TransientProviderFailure_NoOrphan(t *testing.T) {
	ctx := context.Background()

	dex := newSingleUseDex()
	// The provider is down for the first refresh call (a transient dex hiccup),
	// then recovers and behaves like a normal single-use rotating provider.
	var calls atomic.Int32
	refreshFn := func(reqCtx context.Context, rt string) (*oauth2.Token, error) {
		if calls.Add(1) == 1 {
			return nil, fmt.Errorf(`transient: oauth2 "temporarily_unavailable"`)
		}
		return dex.refresh(reqCtx, rt)
	}

	srv, clientID, rt := setupNoOrphanServer(t, dex, refreshFn)

	// First refresh: the provider is down → the grant fails.
	if _, err := srv.RefreshAccessToken(ctx, rt, clientID); err == nil {
		t.Fatal("expected the transient provider failure to fail the refresh grant")
	}

	// NO ORPHAN: the failed provider refresh must NOT have deleted the mcp
	// refresh token. It is still present and bound to the session.
	if _, err := srv.tokenStore.GetRefreshTokenInfo(ctx, rt); err != nil {
		t.Fatalf("refresh token was orphaned by the transient provider failure: %v", err)
	}

	// The client retries with the SAME refresh token; the provider has recovered.
	// The retry must succeed (no reuse nuke) and rotate the token normally.
	tok, err := srv.RefreshAccessToken(ctx, rt, clientID)
	if err != nil {
		t.Fatalf("retry after transient provider failure should succeed, got: %v", err)
	}
	if tok.RefreshToken == "" || tok.RefreshToken == rt {
		t.Fatalf("retry should have rotated the refresh token, got %q", tok.RefreshToken)
	}

	// No collateral damage: the rotated session keeps working, proving the
	// benign failure did not revoke the user's token family.
	if _, err := srv.RefreshAccessToken(ctx, tok.RefreshToken, clientID); err != nil {
		t.Fatalf("session should keep working after recovery, got: %v", err)
	}
}

// TestRefreshAccessToken_GenuineReuse_StillRevokes asserts the reorder did not
// weaken OAuth 2.1 reuse detection: a rotated-away refresh token re-presented by
// the client still trips reuse detection and revokes the whole family, so the
// legitimately rotated sibling token is revoked as collateral (real theft
// protection). This is the security counterpart to the no-orphan test above:
// unify + reorder removes only the BENIGN trigger.
func TestRefreshAccessToken_GenuineReuse_StillRevokes(t *testing.T) {
	ctx := context.Background()

	dex := newSingleUseDex()
	srv, clientID, rt := setupNoOrphanServer(t, dex, dex.refresh)

	// Legitimate refresh rotates the token (rt -> tok2.RefreshToken).
	tok2, err := srv.RefreshAccessToken(ctx, rt, clientID)
	if err != nil {
		t.Fatalf("legitimate refresh should succeed, got: %v", err)
	}
	if tok2.RefreshToken == rt {
		t.Fatal("refresh token should have been rotated")
	}

	// Genuine reuse: re-present the rotated-away token. Reuse detection must fire.
	if _, err := srv.RefreshAccessToken(ctx, rt, clientID); err == nil {
		t.Fatal("reuse of a rotated-away refresh token must be rejected")
	}

	// Family revocation nuked the legitimately rotated sibling too, so it no
	// longer works — the reuse-detection + family-revocation machinery is intact.
	if _, err := srv.RefreshAccessToken(ctx, tok2.RefreshToken, clientID); err == nil {
		t.Fatal("reuse detection should have revoked the whole family, including the rotated sibling")
	}
}
