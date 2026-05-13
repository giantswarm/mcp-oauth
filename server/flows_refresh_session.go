package server

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// RefreshSession refreshes the upstream provider token for the session
// identified by familyID. Equivalent to the public /oauth/token
// refresh-token grant, but callable in-process from any goroutine — useful
// for integrations that need to force a refresh from a request thread
// (e.g. when a cached ID token has expired and the caller is about to
// forward it).
//
// Returns the new provider token. The caller can extract the id_token
// from the Extra field via [ExtractIDToken] for SSO-forwarding flows.
//
// Overlapping in-process calls for the same familyID are coalesced —
// only one refresh hits the upstream provider; the rest wait for and
// share the result. Calls that arrive sequentially (after the previous
// one returns) each run their own refresh, as expected. This matches
// the proactive-refresh path's coalescing behavior.
//
// Returns an error if:
//   - the storage backend does not implement
//     [storage.ActiveRefreshTokenByFamilyStore]
//   - no entry for the family exists at all (wrapped
//     [storage.ErrRefreshTokenFamilyNotFound])
//   - the family exists but every member is revoked (wrapped
//     [storage.ErrRefreshTokenFamilyRevoked])
//   - the upstream provider's refresh call fails
//
// The same lifecycle hooks fire as for the public refresh-token-grant
// path: TokenRefreshHandler is called with the userID + familyID + new
// token, refresh-token rotation produces a new family generation, and
// the new tokens are saved to the TokenStore.
//
// Failure semantics: if the call fails after the active refresh token
// has been atomically deleted (e.g. the upstream provider's refresh
// errors out), the family is left without a usable refresh token. The
// caller should treat that as session-loss and propagate a 401 / force
// re-authentication. This matches RefreshAccessToken behavior — it is
// the standard OAuth 2.1 rotation contract, not a regression from this
// API.
//
// Cross-process race: when the storage backend is shared across
// instances and another instance rotates the family between this call's
// lookup and its atomic delete, the atomic delete returns "not found"
// and is surfaced to the caller as an invalid-grant error.
// RefreshSession does not retry across this race because the underlying
// error is indistinguishable from a genuine reuse-detection event, and
// a naive retry would falsely trigger family revocation on the rotated
// state. Callers in distributed deployments that observe this should
// re-read the cached entry — another instance has produced a fresh
// token.
func (s *Server) RefreshSession(ctx context.Context, familyID string) (*oauth2.Token, error) {
	if familyID == "" {
		return nil, fmt.Errorf("familyID is required")
	}

	// Detach the leader's ctx from caller cancellation so one cancelled caller
	// does not fail all coalesced waiters; the shared refresh survives the
	// leader giving up.
	result, err, _ := s.refreshSessionGroup.Do(familyID, func() (any, error) {
		return s.refreshSessionImpl(context.WithoutCancel(ctx), familyID)
	})
	if err != nil {
		return nil, err
	}
	return result.(*oauth2.Token), nil
}

// refreshSessionImpl is the un-coalesced body of RefreshSession. Looks up
// the active refresh token + owning client ID with a single storage call,
// then delegates to the existing RefreshAccessToken path so rotation,
// reuse detection, audit logging, and TokenRefreshHandler dispatch all
// behave identically to the public token-endpoint flow.
//
// The clientID returned from storage is passed back into
// RefreshAccessToken so its OAuth 2.1 client-binding validation runs.
// In this in-process flow that check trivially passes (the value comes
// from storage and goes straight back into a check against itself); the
// useful path is the public refresh-token-grant flow where storage's
// clientID is compared against an untrusted value supplied by the
// caller. Calling RefreshAccessToken with the storage clientID keeps
// the audit log and reuse-detection paths uniform across both flows.
func (s *Server) refreshSessionImpl(ctx context.Context, familyID string) (*oauth2.Token, error) {
	activeStore, ok := s.tokenStore.(storage.ActiveRefreshTokenByFamilyStore)
	if !ok {
		return nil, fmt.Errorf("storage backend does not implement storage.ActiveRefreshTokenByFamilyStore — RefreshSession requires it")
	}

	refreshToken, clientID, err := activeStore.GetActiveRefreshTokenByFamily(ctx, familyID)
	switch {
	case err == nil:
		return s.RefreshAccessToken(ctx, refreshToken, clientID)
	case errors.Is(err, storage.ErrRefreshTokenFamilyNotFound),
		errors.Is(err, storage.ErrRefreshTokenFamilyRevoked):
		// Both sentinels are the caller's actionable signal — wrap with
		// the familyID for log readability, preserve the sentinel for
		// errors.Is at the call site.
		return nil, fmt.Errorf("family %q: %w", familyID, err)
	default:
		return nil, fmt.Errorf("lookup active refresh token: %w", err)
	}
}
