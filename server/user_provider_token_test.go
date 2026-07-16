package server

// Server-level behavior of the unified shared provider-token store
// (storage.UserProviderTokenStore, mcp-oauth#512 — rotation-race slice 1).
//
// Slice 1 unifies the per-user provider token: token keys reference the ONE
// shared entry and every rotation writes back to it, so a user's sessions no
// longer hold divergent copies of dex's single-use refresh token. The full
// rotation-race repro (rotation_race_repro_test.go) additionally asserts
// single-flight coordination ("dex called exactly once"), which lands in
// slices 2-4 — these tests pin down what slice 1 alone must already deliver.

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestUnifiedStore_RotationWritesBackToSharedEntry verifies that a refresh
// grant writes the rotated dex token back to the user's ONE shared entry, and
// that a sibling session's next refresh therefore uses the FRESH refresh
// token instead of a stale login-time copy — the structural cause of the
// reuse-detection nukes in giantswarm/giantswarm#37164 root cause 2.
func TestUnifiedStore_RotationWritesBackToSharedEntry(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)

	rtA := loginRaceSession(t, srv, store, dex, clientID) // session A
	rtB := loginRaceSession(t, srv, store, dex, clientID) // session B — same user, same dex RT

	// Session A refreshes: dex rotates its RT.
	tokA2, err := srv.RefreshAccessToken(ctx, rtA, clientID)
	if err != nil {
		t.Fatalf("session A refresh failed: %v", err)
	}

	// The rotated dex token must be visible in the shared entry.
	shared, err := store.GetUserProviderToken(ctx, "mock-user-123")
	if err != nil {
		t.Fatalf("GetUserProviderToken() error = %v", err)
	}
	if shared.RefreshToken != "dex-rt-1" {
		t.Fatalf("shared entry RefreshToken = %q, want %q (rotation must write back to the shared entry)",
			shared.RefreshToken, "dex-rt-1")
	}

	// Session B refreshes AFTER A: with per-session copies this died with
	// "already been claimed" and escalated to a full token nuke. With the
	// shared entry, B reads the fresh dex RT and survives. (Without slice
	// 2-4 coordination B still calls dex itself — hence 2 calls, not 1.)
	tokB2, err := srv.RefreshAccessToken(ctx, rtB, clientID)
	if err != nil {
		t.Fatalf("session B refresh failed — stale provider-token copy still in play: %v", err)
	}
	if got := dex.callCount(); got != 2 {
		t.Fatalf("dex RefreshToken calls = %d, want 2 (uncoordinated but each against the current RT)", got)
	}

	// Both sessions keep working.
	if _, err := srv.RefreshAccessToken(ctx, tokA2.RefreshToken, clientID); err != nil {
		t.Fatalf("session A follow-up refresh failed: %v", err)
	}
	if _, err := srv.RefreshAccessToken(ctx, tokB2.RefreshToken, clientID); err != nil {
		t.Fatalf("session B follow-up refresh failed: %v", err)
	}
}

// TestUnifiedStore_NoPerTokenCopies verifies the acceptance criterion that
// issued access/refresh tokens hold references to the shared entry rather
// than private provider-token copies.
func TestUnifiedStore_NoPerTokenCopies(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)

	rt := loginRaceSession(t, srv, store, dex, clientID)

	// The refresh token resolves to the user via a reference …
	userID, err := store.GetProviderTokenRef(ctx, rt)
	if err != nil {
		t.Fatalf("GetProviderTokenRef(refresh token) error = %v", err)
	}
	if userID != "mock-user-123" {
		t.Fatalf("provider token ref user = %q, want %q", userID, "mock-user-123")
	}

	// … and holds NO private provider-token copy under its own key.
	if _, err := store.GetToken(ctx, rt); err == nil {
		t.Fatal("refresh-token key holds a provider-token copy; want reference-only (unified layout)")
	}
}

// TestUnifiedStore_ReuseDetectionStillFires verifies that unifying the
// provider token does not weaken OAuth 2.1 reuse protection: presenting a
// rotated-away (genuinely reused) mcp refresh token still trips family +
// user/client revocation.
func TestUnifiedStore_ReuseDetectionStillFires(t *testing.T) {
	ctx := context.Background()
	srv, store, dex, clientID := setupRaceServer(t)

	rt := loginRaceSession(t, srv, store, dex, clientID)

	tok2, err := srv.RefreshAccessToken(ctx, rt, clientID)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// Re-present the consumed (rotated-away) refresh token: genuine reuse.
	if _, err := srv.RefreshAccessToken(ctx, rt, clientID); err == nil {
		t.Fatal("reused refresh token accepted; reuse detection must still fire")
	}

	// The nuke must have revoked the successor token too.
	if _, err := srv.RefreshAccessToken(ctx, tok2.RefreshToken, clientID); err == nil {
		t.Fatal("successor refresh token still valid after reuse detection; family revocation must cover it")
	}
}

// TestUnifiedStore_ValidationReadsSharedEntry verifies that opaque access
// token validation resolves token → user → shared entry, and that a
// validation-time provider refresh is visible to the whole user (write-back
// to the shared entry, not to a private copy).
func TestUnifiedStore_ValidationReadsSharedEntry(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.TokenRefreshThreshold = 300

	provider.ValidateTokenFunc = setupValidTokenProvider()
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "provider-at-fresh",
			RefreshToken: "provider-rt-fresh",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	const userID = "shared-entry-user"
	accessToken := "opaque-at-shared-entry" // #nosec G101 -- test data, not credentials
	seedProviderToken(t, store, accessToken, userID, &oauth2.Token{
		AccessToken:  "provider-at-stale",
		RefreshToken: "provider-rt-stale",
		Expiry:       time.Now().Add(-time.Minute), // expired → reactive refresh
	})

	if _, err := srv.ValidateToken(ctx, accessToken); err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	shared, err := store.GetUserProviderToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserProviderToken() error = %v", err)
	}
	if shared.RefreshToken != "provider-rt-fresh" {
		t.Errorf("shared entry RefreshToken = %q, want %q (validation refresh must write back to the shared entry)",
			shared.RefreshToken, "provider-rt-fresh")
	}
}
