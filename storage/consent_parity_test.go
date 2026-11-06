package storage_test

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestConsentStoreBackendParity(t *testing.T) {
	for name, factory := range map[string]func(*testing.T) storage.Combined{"memory": newMemoryBackend, "valkey": newValkeyBackend} {
		t.Run(name, func(t *testing.T) {
			store := factory(t)
			consents := store.(storage.ConsentStore)
			t.Run("issuer keys", func(t *testing.T) {
				first, err := consents.ConsentCookieKey(t.Context(), "https://auth.example.com/a")
				require.NoError(t, err)
				second, err := consents.ConsentCookieKey(t.Context(), "https://auth.example.com/a")
				require.NoError(t, err)
				require.Equal(t, first, second)
				require.Len(t, first, 32)
				other, err := consents.ConsentCookieKey(t.Context(), "https://auth.example.com/b")
				require.NoError(t, err)
				require.NotEqual(t, first, other)
			})
			t.Run("browser binding and atomic consume", func(t *testing.T) {
				data := bytes.Repeat([]byte("pending-request"), 1024)
				require.NoError(t, consents.SavePendingConsent(t.Context(), "browser-a", "id", data, time.Now().Add(time.Minute)))
				_, err := consents.ConsumePendingConsent(t.Context(), "browser-b", "id")
				require.ErrorIs(t, err, storage.ErrPendingConsentNotFound)
				var successes atomic.Int32
				var group sync.WaitGroup
				for range 32 {
					group.Go(func() {
						value, err := consents.ConsumePendingConsent(t.Context(), "browser-a", "id")
						if err == nil {
							require.Equal(t, data, value)
							successes.Add(1)
						} else {
							require.ErrorIs(t, err, storage.ErrPendingConsentNotFound)
						}
					})
				}
				group.Wait()
				require.Equal(t, int32(1), successes.Load())
			})
			t.Run("pending bound", func(t *testing.T) {
				for index := range storage.MaxPendingConsentsPerBrowser {
					require.NoError(t, consents.SavePendingConsent(t.Context(), "bounded", fmt.Sprint(index), []byte("request"), time.Now().Add(time.Minute)))
				}
				require.ErrorIs(t, consents.SavePendingConsent(t.Context(), "bounded", "overflow", []byte("request"), time.Now().Add(time.Minute)), storage.ErrPendingConsentLimit)
				_, err := consents.ConsumePendingConsent(t.Context(), "bounded", "0")
				require.NoError(t, err)
				require.NoError(t, consents.SavePendingConsent(t.Context(), "bounded", "replacement", []byte("request"), time.Now().Add(time.Minute)))
			})
			t.Run("expired pending", func(t *testing.T) {
				require.NoError(t, consents.SavePendingConsent(t.Context(), "expiry", "id", []byte("request"), time.Now().Add(100*time.Millisecond)))
				time.Sleep(150 * time.Millisecond)
				_, err := consents.ConsumePendingConsent(t.Context(), "expiry", "id")
				require.ErrorIs(t, err, storage.ErrPendingConsentNotFound)
			})
			t.Run("atomic provider state", func(t *testing.T) {
				state := &storage.AuthorizationState{StateID: "client-state", ProviderState: "provider-state", BrowserBinding: "browser-binding", UpstreamScopes: []string{"openid", "groups"}, ConsentApproved: true, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
				require.NoError(t, store.SaveAuthorizationState(t.Context(), state))
				var successes atomic.Int32
				var group sync.WaitGroup
				for range 32 {
					group.Go(func() {
						value, err := store.(storage.AuthorizationStateConsumer).ConsumeAuthorizationState(t.Context(), state.ProviderState)
						if err == nil {
							require.Equal(t, state.BrowserBinding, value.BrowserBinding)
							require.Equal(t, state.UpstreamScopes, value.UpstreamScopes)
							require.True(t, value.ConsentApproved)
							successes.Add(1)
						} else {
							require.ErrorIs(t, err, storage.ErrAuthorizationStateNotFound)
						}
					})
				}
				group.Wait()
				require.Equal(t, int32(1), successes.Load())
				_, err := store.GetAuthorizationState(t.Context(), state.StateID)
				require.ErrorIs(t, err, storage.ErrAuthorizationStateNotFound)
			})
		})
	}
}
