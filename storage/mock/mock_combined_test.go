package mock_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/mock"
)

// TestCombinedStore_RoundTrip exercises one method from each of the three
// embedded interfaces against a single CombinedStore value, proving the
// interface is satisfied by the embedded mocks and that the underlying state
// is per-mock (not shared).
func TestCombinedStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := mock.NewCombined()

	// TokenStore leg.
	if err := store.SaveToken(ctx, "user-1", &oauth2.Token{AccessToken: "at-1"}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if tok, err := store.GetToken(ctx, "user-1"); err != nil {
		t.Fatalf("GetToken: %v", err)
	} else if tok.AccessToken != "at-1" {
		t.Errorf("GetToken.AccessToken = %q, want at-1", tok.AccessToken)
	}

	// ClientStore leg.
	client := &storage.Client{
		ClientID:   "client-1",
		ClientType: "public",
		CreatedAt:  time.Now(),
	}
	if err := store.SaveClient(ctx, client); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if c, err := store.GetClient(ctx, "client-1"); err != nil {
		t.Fatalf("GetClient: %v", err)
	} else if c.ClientID != "client-1" {
		t.Errorf("GetClient.ClientID = %q, want client-1", c.ClientID)
	}

	// FlowStore leg.
	if err := store.SaveAuthorizationState(ctx, &storage.AuthorizationState{
		StateID:       "state-1",
		ProviderState: "provider-state-1",
		ClientID:      "client-1",
		ExpiresAt:     time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveAuthorizationState: %v", err)
	}
	if s, err := store.GetAuthorizationState(ctx, "state-1"); err != nil {
		t.Fatalf("GetAuthorizationState: %v", err)
	} else if s.StateID != "state-1" {
		t.Errorf("GetAuthorizationState.StateID = %q, want state-1", s.StateID)
	}
}

// TestCombinedStore_ResetAllCallCounts verifies the disambiguation helper
// calls through to each embedded mock. The bare ResetCallCounts method is
// ambiguous by design on CombinedStore because all three embedded types
// expose one; the helper exists so callers don't need to remember that.
func TestCombinedStore_ResetAllCallCounts(t *testing.T) {
	ctx := context.Background()
	store := mock.NewCombined()

	_ = store.SaveToken(ctx, "u", &oauth2.Token{AccessToken: "at"})
	_ = store.SaveClient(ctx, &storage.Client{ClientID: "c", ClientType: "public"})
	_ = store.SaveAuthorizationState(ctx, &storage.AuthorizationState{
		StateID:       "s",
		ProviderState: "ps",
		ExpiresAt:     time.Now().Add(time.Hour),
	})

	// Sanity: each mock recorded its call.
	if store.TokenStore.CallCounts["SaveToken"] != 1 {
		t.Errorf("TokenStore.CallCounts[SaveToken] = %d, want 1", store.TokenStore.CallCounts["SaveToken"])
	}
	if store.ClientStore.CallCounts["SaveClient"] != 1 {
		t.Errorf("ClientStore.CallCounts[SaveClient] = %d, want 1", store.ClientStore.CallCounts["SaveClient"])
	}
	if store.FlowStore.CallCounts["SaveAuthorizationState"] != 1 {
		t.Errorf("FlowStore.CallCounts[SaveAuthorizationState] = %d, want 1", store.FlowStore.CallCounts["SaveAuthorizationState"])
	}

	store.ResetAllCallCounts()

	if store.TokenStore.CallCounts["SaveToken"] != 0 {
		t.Errorf("after Reset: TokenStore.CallCounts[SaveToken] = %d, want 0", store.TokenStore.CallCounts["SaveToken"])
	}
	if store.ClientStore.CallCounts["SaveClient"] != 0 {
		t.Errorf("after Reset: ClientStore.CallCounts[SaveClient] = %d, want 0", store.ClientStore.CallCounts["SaveClient"])
	}
	if store.FlowStore.CallCounts["SaveAuthorizationState"] != 0 {
		t.Errorf("after Reset: FlowStore.CallCounts[SaveAuthorizationState] = %d, want 0", store.FlowStore.CallCounts["SaveAuthorizationState"])
	}
}

// TestCombinedStore_SatisfiesInterface is a compile+runtime assertion
// companion to the package-level var — keeps the contract visible in test
// output when someone intentionally or accidentally breaks embedding.
func TestCombinedStore_SatisfiesInterface(t *testing.T) {
	var _ storage.Combined = mock.NewCombined()
}
