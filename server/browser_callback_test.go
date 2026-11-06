package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type callbackConsumptionStore struct {
	*memory.Store
	failure error
}

func (s *callbackConsumptionStore) ConsumeAuthorizationState(ctx context.Context, state string) (*storage.AuthorizationState, error) {
	if s.failure != nil {
		return nil, s.failure
	}
	return s.Store.ConsumeAuthorizationState(ctx, state)
}

func TestBrowserCallback_ConsumptionFailurePreservesFlow(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancel"}[cancel], func(t *testing.T) {
			authorizationServer, store, provider := setupFlowTestServer(t)
			failure := errors.New("storage unavailable")
			flowStore := &callbackConsumptionStore{Store: store, failure: failure}
			authorizationServer.flowStore = flowStore
			state := &storage.AuthorizationState{
				StateID:        testutil.GenerateRandomString(43),
				ProviderState:  testutil.GenerateRandomString(43),
				BrowserBinding: hashBrowserBinding("browser-binding"),
				ExpiresAt:      time.Now().Add(time.Minute),
			}
			require.NoError(t, store.SaveAuthorizationState(t.Context(), state))
			if cancel {
				require.ErrorIs(t, authorizationServer.CancelBrowserAuthorization(t.Context(), state.ProviderState, "browser-binding"), failure)
			} else {
				result, err := authorizationServer.CompleteBrowserAuthorization(t.Context(), state.ProviderState, "provider-code", "browser-binding")
				require.ErrorIs(t, err, failure)
				require.Nil(t, result)
			}
			_, err := store.GetAuthorizationStateByProviderState(t.Context(), state.ProviderState)
			require.NoError(t, err)
			require.Zero(t, provider.CallCounts["ExchangeCode"])
			flowStore.failure = nil
			if cancel {
				require.NoError(t, authorizationServer.CancelBrowserAuthorization(t.Context(), state.ProviderState, "browser-binding"))
				require.Zero(t, provider.CallCounts["ExchangeCode"])
			} else {
				result, err := authorizationServer.CompleteBrowserAuthorization(t.Context(), state.ProviderState, "provider-code", "browser-binding")
				require.NoError(t, err)
				require.Equal(t, state, result.State)
				require.Equal(t, 1, provider.CallCounts["ExchangeCode"])
			}
			_, err = store.GetAuthorizationStateByProviderState(t.Context(), state.ProviderState)
			require.ErrorIs(t, err, storage.ErrAuthorizationStateNotFound)
		})
	}
}
