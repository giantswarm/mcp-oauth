package server_test

// Cross-pod single-flight test for the per-user provider refresh — slice 2 of
// the rotation-race fix (giantswarm/giantswarm#37164 root cause 2,
// mcp-oauth#513): two Server instances, each with its OWN valkey.Store,
// sharing one Valkey — the supported replicaCount:2 topology. N concurrent
// refreshes for one user split across the two "pods" must produce EXACTLY ONE
// provider call, with every caller adopting the same fresh token.
//
// This file is an external test package (server_test): the valkey backend
// imports package server for the DPoP replay cache, so an in-package test
// importing valkey would cycle. The in-process (memory backend) single-flight
// tests live in provider_refresh_test.go.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// crossPodDex emulates dex's refresh-token rotation: a refresh token is valid
// exactly once; reusing a rotated-away token fails like dex does. Shared by
// both "pods" so the call count is global.
type crossPodDex struct {
	mu        sync.Mutex
	currentRT string
	gen       int
	calls     int
}

func (d *crossPodDex) refresh(_ context.Context, rt string) (*oauth2.Token, error) {
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

func (d *crossPodDex) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// newCrossPodValkeyStore returns a valkey-backed store over the shared test
// Valkey, namespaced by prefix. Skips when no Valkey is reachable.
func newCrossPodValkeyStore(t *testing.T, prefix string) *valkey.Store {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	s, err := valkey.New(valkey.Config{Address: addr, KeyPrefix: prefix})
	if err != nil {
		t.Skipf("skipping valkey cross-pod test: could not connect to %s: %v", addr, err)
	}
	t.Cleanup(func() {
		flushValkeyPrefix(t, addr, prefix)
		s.Close()
	})
	return s
}

// flushValkeyPrefix SCAN+DELs every key matching prefix+"*", mirroring the
// storage parity tests' cleanup ritual.
func flushValkeyPrefix(t *testing.T, addr, prefix string) {
	t.Helper()

	client, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	var cursor uint64
	for {
		entry, err := client.Do(ctx, client.B().Scan().Cursor(cursor).Match(prefix+"*").Count(100).Build()).AsScanEntry()
		if err != nil {
			t.Logf("warning: failed to scan for cleanup: %v", err)
			return
		}
		for _, key := range entry.Elements {
			_ = client.Do(ctx, client.B().Del().Key(key).Build())
		}
		cursor = entry.Cursor
		if cursor == 0 {
			return
		}
	}
}

// newCrossPodServer builds one "pod": a Server on the given store with a mock
// provider whose RefreshToken is the shared single-use dex emulation.
func newCrossPodServer(t *testing.T, store *valkey.Store, dex *crossPodDex) *server.Server {
	t.Helper()

	provider := mock.NewProvider()
	provider.RefreshTokenFunc = dex.refresh

	config := &server.Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		ClockSkewGracePeriod:        5,
		TokenRefreshThreshold:       300, // 5m proactive threshold (production default)
		DisableNonceEchoRequirement: true,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	require.NoError(t, err)
	return srv
}

// TestProviderRefresh_SingleFlight_CrossPod_Valkey: the lock coordinates
// across store instances, not just goroutines — one provider call for the
// whole fleet, every caller ends with the winner's fresh token, and the
// write-back is visible through the other pod's store.
func TestProviderRefresh_SingleFlight_CrossPod_Valkey(t *testing.T) {
	const userID = "cross-pod-user"
	prefix := fmt.Sprintf("mcptest-refreshlock:%s:", t.Name())
	dex := &crossPodDex{currentRT: "dex-rt-0"}

	storeA := newCrossPodValkeyStore(t, prefix)
	storeB := newCrossPodValkeyStore(t, prefix)
	podA := newCrossPodServer(t, storeA, dex)
	podB := newCrossPodServer(t, storeB, dex)

	ctx := context.Background()

	// The shared entry every session observed before the collision: dex's
	// current RT, expiry inside the 5m proactive threshold → refresh needed.
	observed := &oauth2.Token{
		AccessToken:  "dex-at-login",
		TokenType:    "Bearer",
		RefreshToken: "dex-rt-0",
		Expiry:       time.Now().Add(2 * time.Minute),
	}
	require.NoError(t, storeA.SaveUserProviderToken(ctx, userID, observed))

	// 8 concurrent sessions, alternating between the two pods.
	pods := []*server.Server{podA, podB, podA, podB, podA, podB, podA, podB}
	start := make(chan struct{})
	tokens := make([]*oauth2.Token, len(pods))
	errs := make([]error, len(pods))
	var wg sync.WaitGroup
	for i, pod := range pods {
		wg.Add(1)
		go func(i int, pod *server.Server) {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = pod.RefreshUserProviderTokenForTest(ctx, userID, observed)
		}(i, pod)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "caller %d: a lost cross-pod race must yield a valid token, not an error", i)
	}
	require.Equal(t, 1, dex.callCount(), "one provider call across BOTH pods (cross-pod single-flight)")
	for i, tok := range tokens {
		require.Equalf(t, "dex-rt-1", tok.RefreshToken, "caller %d must end with the winner's fresh token", i)
	}

	// The write-back is visible through the OTHER pod's store instance.
	shared, err := storeB.GetUserProviderToken(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, "dex-rt-1", shared.RefreshToken)
}
