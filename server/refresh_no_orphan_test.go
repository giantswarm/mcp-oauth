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
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
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

// ---------------------------------------------------------------------------
// Benign storage failures on the refresh path must not be classified as theft.
//
// Sibling findings to the L2 reorder above: a missing/expired shared provider
// entry for a refresh token that GetRefreshTokenInfo just proved VALID is a
// storage miss (evicted providertoken:<user> key, TTL collapse, deploy without
// a token flush) — never reuse — and must map to invalid_grant/re-login
// without RevokeRefreshTokenFamily, RevokeAllTokensForUserClient, or a theft
// audit event. Transient storage failures (shared-entry read, token-metadata
// read) must surface as retryable server errors, never as invalid_grant with
// a theft audit.
// ---------------------------------------------------------------------------

// faultInjectingStore wraps memory.Store and injects errors into the two reads
// the refresh path classifies: the user's shared provider entry and the
// refresh token's metadata. When the configured error is nil the call passes
// through to the real store.
type faultInjectingStore struct {
	*memory.Store
	mu               sync.Mutex
	providerTokenErr error
	tokenMetadataErr error
}

func (f *faultInjectingStore) setProviderTokenErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.providerTokenErr = err
}

func (f *faultInjectingStore) setTokenMetadataErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenMetadataErr = err
}

func (f *faultInjectingStore) GetUserProviderToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	f.mu.Lock()
	err := f.providerTokenErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.Store.GetUserProviderToken(ctx, userID)
}

func (f *faultInjectingStore) GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error) {
	f.mu.Lock()
	err := f.tokenMetadataErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.Store.GetTokenMetadata(tokenID)
}

// setupFaultInjectionServer builds a unified-layout server whose tokenStore is
// a faultInjectingStore, with server logs AND audit events captured in one
// buffer so tests can assert which security events did (not) fire.
func setupFaultInjectionServer(t *testing.T) (*Server, *faultInjectingStore, *bytes.Buffer) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	faults := &faultInjectingStore{Store: store}

	logger, logBuf := captureLogger()

	srv, err := New(mock.NewProvider(), faults, store, store, &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenTTL:              3600,
		DisableNonceEchoRequirement: true,
	}, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400
	srv.Auditor = security.NewAuditor(logger, true)

	return srv, faults, logBuf
}

// seedBoundSession stores a client-bound refresh token with family tracking,
// the way a real login leaves it (SaveRefreshTokenWithFamily also writes the
// token metadata carrying the client binding).
func seedBoundSession(t *testing.T, store *faultInjectingStore, refreshToken, userID, clientID, familyID string) {
	t.Helper()
	if err := store.SaveRefreshTokenWithFamily(context.Background(),
		refreshToken, userID, clientID, familyID, 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily(%s) error = %v", refreshToken, err)
	}
}

// assertNoReuseNuke asserts none of the reuse-detection machinery fired: the
// presented token's family is not revoked, the user's sibling session (same
// user+client) is untouched, and no theft audit event was emitted.
func assertNoReuseNuke(t *testing.T, store *faultInjectingStore, logOutput, rt, siblingRT, userID string) {
	t.Helper()
	ctx := context.Background()

	if fam, err := store.GetRefreshTokenFamily(ctx, rt); err != nil {
		t.Errorf("family of presented token should survive, got error: %v", err)
	} else if fam.Revoked {
		t.Error("family of presented token must NOT be revoked on a benign storage failure")
	}

	if got, err := store.GetRefreshTokenInfo(ctx, siblingRT); err != nil {
		t.Errorf("sibling session was revoked (RevokeAllTokensForUserClient fired?): %v", err)
	} else if got != userID {
		t.Errorf("sibling refresh token user = %q, want %q", got, userID)
	}
	if fam, err := store.GetRefreshTokenFamily(ctx, siblingRT); err != nil {
		t.Errorf("sibling family should survive, got error: %v", err)
	} else if fam.Revoked {
		t.Error("sibling family must NOT be revoked on a benign storage failure")
	}

	for _, theft := range []string{
		security.EventRefreshTokenReuseDetected,
		security.EventTokenReuseDetected,
		security.EventRevokedTokenFamilyReuseAttempt,
		"reuse detected",
	} {
		if strings.Contains(logOutput, theft) {
			t.Errorf("benign storage failure must not emit theft signal %q; log:\n%s", theft, logOutput)
		}
	}
}

// TestRefreshAccessToken_SharedProviderEntryErrors covers the classification
// of GetUserProviderToken failures for a refresh token that was just proven
// valid: missing/expired shared entry → invalid_grant (re-login); any other
// error → retryable server error. Never the reuse nuke, and in EVERY case the
// presented token stays un-consumed: "record deleted + family alive" is the
// fresh-reuse signature, so consuming it here would send a client that
// retries the same token straight into the reuse nuke — instead a retry
// idempotently re-enters the same benign path.
func TestRefreshAccessToken_SharedProviderEntryErrors(t *testing.T) {
	const (
		userID   = "user-shared-entry"
		clientID = "client-shared-entry"
	)

	tests := []struct {
		name string
		// sharedToken, when non-nil, is written as the user's shared entry.
		sharedToken *oauth2.Token
		// readErr, when non-nil, is injected into GetUserProviderToken.
		readErr          error
		wantInvalidGrant bool
	}{
		{
			name:             "missing shared entry maps to re-login, not reuse",
			sharedToken:      nil,
			wantInvalidGrant: true,
		},
		{
			name: "expired shared entry without provider refresh token maps to re-login, not reuse",
			sharedToken: &oauth2.Token{
				AccessToken: "provider-at-expired",
				Expiry:      time.Now().Add(-time.Hour),
			},
			wantInvalidGrant: true,
		},
		{
			name: "transient shared-entry read failure is a retryable server error",
			sharedToken: &oauth2.Token{
				AccessToken:  "provider-at",
				RefreshToken: "provider-rt",
				Expiry:       time.Now().Add(30 * time.Minute),
			},
			readErr:          fmt.Errorf("valkey: connection refused"),
			wantInvalidGrant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			srv, store, logBuf := setupFaultInjectionServer(t)

			const rt = "rt-shared-entry-case"
			const siblingRT = "rt-shared-entry-sibling"
			seedBoundSession(t, store, rt, userID, clientID, "family-presented")
			seedBoundSession(t, store, siblingRT, userID, clientID, "family-sibling")
			if tt.sharedToken != nil {
				if err := store.SaveUserProviderToken(ctx, userID, tt.sharedToken); err != nil {
					t.Fatalf("SaveUserProviderToken() error = %v", err)
				}
			}
			store.setProviderTokenErr(tt.readErr)

			checkGrantError := func(err error, attempt string) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s: expected the refresh grant to fail", attempt)
				}
				isInvalidGrant := strings.Contains(err.Error(), ErrorCodeInvalidGrant)
				if tt.wantInvalidGrant && !isInvalidGrant {
					t.Errorf("%s: want invalid_grant (re-login), got: %v", attempt, err)
				}
				if !tt.wantInvalidGrant && isInvalidGrant {
					t.Errorf("%s: transient storage failure must surface as a server error, not invalid_grant, got: %v", attempt, err)
				}
			}

			_, err := srv.RefreshAccessToken(ctx, rt, clientID)
			checkGrantError(err, "first attempt")

			logOutput := logBuf.String()
			assertNoReuseNuke(t, store, logOutput, rt, siblingRT, userID)

			if tt.wantInvalidGrant {
				// Non-theft audit trail: a warn-level auth failure naming the
				// benign cause, so operators can tell re-login storms from theft.
				if !containsAuthFailure(logOutput, "shared_provider_token_missing") {
					t.Errorf("expected non-theft auth_failure audit event, log:\n%s", logOutput)
				}
			}

			// The presented token must stay un-consumed in every case:
			// deleting it would turn a client retry into the fresh-reuse
			// signature (record gone, family live) and fire the nuke.
			if got, infoErr := store.GetRefreshTokenInfo(ctx, rt); infoErr != nil {
				t.Errorf("presented refresh token must stay un-consumed, got: %v", infoErr)
			} else if got != userID {
				t.Errorf("presented refresh token user = %q, want %q", got, userID)
			}

			// RETRY: a client re-presenting the SAME token lands on the same
			// benign classification — idempotent, still no reuse nuke, no
			// theft audit, and the token remains intact for the next attempt.
			_, retryErr := srv.RefreshAccessToken(ctx, rt, clientID)
			checkGrantError(retryErr, "retry")
			assertNoReuseNuke(t, store, logBuf.String(), rt, siblingRT, userID)
			if _, infoErr := store.GetRefreshTokenInfo(ctx, rt); infoErr != nil {
				t.Errorf("presented refresh token must survive the retry too, got: %v", infoErr)
			}
		})
	}
}

// TestRefreshAccessToken_TokenMetadataReadErrors covers the classification of
// GetTokenMetadata failures at the top of RefreshAccessToken: a transient
// storage failure must be a retryable server error (the old legacy layout
// read ClientID atomically inside the consume, where a transient error was
// retryable), NOT an empty client binding that downstream misclassifies as a
// legacy unbound token with a cross_client_token_theft_prevented audit event.
// Genuinely absent metadata keeps the legacy rejection.
func TestRefreshAccessToken_TokenMetadataReadErrors(t *testing.T) {
	const (
		userID   = "user-meta"
		clientID = "client-meta"
	)

	freshShared := func() *oauth2.Token {
		return &oauth2.Token{
			AccessToken:  "provider-at",
			RefreshToken: "provider-rt",
			Expiry:       time.Now().Add(30 * time.Minute),
		}
	}

	tests := []struct {
		name             string
		seedBound        bool // client-bound session (family + metadata) vs bare legacy token
		metaErr          error
		wantInvalidGrant bool
		wantLegacyAudit  bool
		wantRetryWorks   bool
	}{
		{
			name:             "transient metadata read failure is a retryable server error",
			seedBound:        true,
			metaErr:          fmt.Errorf("failed to get token metadata: dial tcp 10.0.0.1:6379: connect: connection refused"),
			wantInvalidGrant: false,
			wantLegacyAudit:  false,
			wantRetryWorks:   true,
		},
		{
			name:             "genuinely absent metadata keeps legacy unbound-token rejection",
			seedBound:        false,
			metaErr:          nil,
			wantInvalidGrant: true,
			wantLegacyAudit:  true,
			wantRetryWorks:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			srv, store, logBuf := setupFaultInjectionServer(t)

			const rt = "rt-meta-case"
			if tt.seedBound {
				seedBoundSession(t, store, rt, userID, clientID, "family-meta")
			} else {
				// Legacy shape: refresh token record without metadata/binding.
				if err := store.SaveRefreshToken(ctx, rt, userID, time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("SaveRefreshToken() error = %v", err)
				}
			}
			if err := store.SaveUserProviderToken(ctx, userID, freshShared()); err != nil {
				t.Fatalf("SaveUserProviderToken() error = %v", err)
			}
			store.setTokenMetadataErr(tt.metaErr)

			_, err := srv.RefreshAccessToken(ctx, rt, clientID)
			if err == nil {
				t.Fatal("expected the refresh grant to fail")
			}

			isInvalidGrant := strings.Contains(err.Error(), ErrorCodeInvalidGrant)
			if tt.wantInvalidGrant && !isInvalidGrant {
				t.Errorf("want invalid_grant, got: %v", err)
			}
			if !tt.wantInvalidGrant && isInvalidGrant {
				t.Errorf("transient metadata failure must surface as a server error, not invalid_grant, got: %v", err)
			}

			logOutput := logBuf.String()
			hasLegacyAudit := containsAuditEvent(logOutput, security.EventRefreshTokenMissingClientBinding)
			if tt.wantLegacyAudit && !hasLegacyAudit {
				t.Errorf("expected legacy missing-client-binding audit event, log:\n%s", logOutput)
			}
			if !tt.wantLegacyAudit {
				if hasLegacyAudit || strings.Contains(logOutput, "cross_client_token_theft_prevented") {
					t.Errorf("transient metadata failure must not be classified as a legacy/theft rejection, log:\n%s", logOutput)
				}
			}

			if tt.wantRetryWorks {
				// The token was never consumed, so once storage recovers the
				// SAME token succeeds — retryable, no re-login, no reuse nuke.
				if _, infoErr := store.GetRefreshTokenInfo(ctx, rt); infoErr != nil {
					t.Fatalf("refresh token must stay intact for retry, got: %v", infoErr)
				}
				store.setTokenMetadataErr(nil)
				tok, retryErr := srv.RefreshAccessToken(ctx, rt, clientID)
				if retryErr != nil {
					t.Fatalf("retry after storage recovery should succeed, got: %v", retryErr)
				}
				if tok.RefreshToken == "" || tok.RefreshToken == rt {
					t.Fatalf("retry should have rotated the refresh token, got %q", tok.RefreshToken)
				}
			}
		})
	}
}
