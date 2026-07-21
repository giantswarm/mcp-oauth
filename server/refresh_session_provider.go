package server

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

// RefreshSessionProvider refreshes ONLY the upstream provider (IdP) token for
// the session identified by familyID (the provider token is shared per-user,
// so familyID resolves the owning user and scopes the callback) and fires TokenRefreshHandler with the
// result — WITHOUT rotating the client-facing mcp refresh token, minting a new
// family generation, or issuing a new mcp access token. It is the
// background-safe sibling of [Server.RefreshSession].
//
// RefreshSession delegates to RefreshAccessToken, i.e. the full OAuth 2.1
// refresh-token grant, which rotates the client's mcp refresh token as a side
// effect. A background integration that must keep a fresh upstream id_token on
// hand — e.g. an SSO re-exchange/forwarding loop — cannot use it: on a tight
// retry it rotates the client's refresh token out from under the client, and
// once the client later presents its now-superseded token OAuth 2.1 reuse
// detection revokes the whole family (the user is deauthed). See
// giantswarm/giantswarm#37164.
//
// RefreshSessionProvider performs the same upstream refresh and the same
// TokenRefreshHandler dispatch the validation-time proactive/reactive refresh
// already performs (see attemptProactiveRefresh / validateStoredToken), but
// keyed by familyID and leaving the client's refresh chain completely
// untouched. The refresh is coordinated through the per-user single-flight
// provider-refresh lock, so concurrent sessions of the same user — and a tight
// retry loop — collapse into at most one provider round-trip per rotation
// window; a shared entry that is already fresh is adopted without calling the
// provider at all.
//
// The owning user is resolved from the refresh-token FAMILY record
// (GetRefreshTokenFamilyByID), which survives rotation, rather than from any
// individual issued token: resolving via a consumable token would race a
// concurrent genuine client refresh that atomically deletes it and surface a
// spurious failure exactly when the session is healthiest.
//
// The handler is fired only when the refreshed token actually carries an
// id_token. A provider refresh may legitimately return no id_token (RFC 6749
// §5.1: the response may omit it, and preserveRefreshToken carries only the
// refresh token forward), which would write an id_token-less shared entry;
// firing the handler with it would let a background refresh drive an
// SSO-teardown branch in handlers that treat a missing id_token as a broken
// chain. A genuinely broken upstream chain is still caught by the caller's own
// stale-token accounting.
//
// Returns the fresh provider token; extract the id_token via [ExtractIDToken].
// Returns an error if:
//   - familyID is empty
//   - the storage backend does not implement storage.RefreshTokenFamilyByIDStore
//   - no family record exists (wrapped storage.ErrRefreshTokenFamilyNotFound)
//   - the family is revoked (wrapped storage.ErrRefreshTokenFamilyRevoked)
//   - the upstream provider refresh fails
func (s *Server) RefreshSessionProvider(ctx context.Context, familyID string) (*oauth2.Token, error) {
	if familyID == "" {
		return nil, fmt.Errorf("familyID is required")
	}

	familyStore, ok := s.tokenStore.(storage.RefreshTokenFamilyByIDStore)
	if !ok {
		return nil, fmt.Errorf("storage backend does not implement storage.RefreshTokenFamilyByIDStore — RefreshSessionProvider requires it")
	}

	family, err := familyStore.GetRefreshTokenFamilyByID(ctx, familyID)
	if err != nil {
		// Preserve the sentinel (wrapped ErrRefreshTokenFamilyNotFound) for
		// errors.Is at the call site; add the familyID for log readability.
		return nil, fmt.Errorf("family %q: %w", familyID, err)
	}
	if family.Revoked {
		// GetRefreshTokenFamilyByID returns a retained-but-revoked family as
		// metadata with Revoked set, not as an error — surface it as the
		// revoked sentinel so callers can distinguish "session was revoked"
		// from "no such session" and stop retrying.
		return nil, fmt.Errorf("family %q: %w", familyID, storage.ErrRefreshTokenFamilyRevoked)
	}

	// Provider-only refresh through the per-user single-flight coordinator.
	// observed=nil: this path holds no prior snapshot of the shared entry, so
	// freshness is judged on the entry's own expiry — refresh when due, adopt a
	// sibling's fresh entry otherwise. The client refresh token is never read
	// or rotated here.
	newToken, err := s.refreshUserProviderToken(ctx, family.UserID, nil)
	if err != nil {
		return nil, fmt.Errorf("provider refresh for family %q: %w", familyID, err)
	}

	if s.tokenRefreshHandler != nil && ExtractIDToken(newToken) != "" {
		s.tokenRefreshHandler(ctx, family.UserID, familyID, newToken)
	}

	return newToken, nil
}
