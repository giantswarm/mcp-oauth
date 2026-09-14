package valkey

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

// tcpProxy sits between the store and the Valkey test server so a test can
// turn the backend unresponsive (accept, never answer) or dead (nothing
// listening) and back, without touching the shared server.
type tcpProxy struct {
	upstream  string
	addr      string
	blackhole atomic.Bool

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

func newTCPProxy(t *testing.T, upstream string) *tcpProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &tcpProxy{upstream: upstream, addr: ln.Addr().String(), conns: make(map[net.Conn]struct{})}
	p.ln = ln
	go p.serve(ln)
	t.Cleanup(p.closeAll)
	return p
}

func (p *tcpProxy) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns[c] = struct{}{}
		p.mu.Unlock()
		go p.handle(c)
	}
}

// handle forwards bytes in both directions; while black-holed it drops them,
// so the client sees an open connection that never answers.
func (p *tcpProxy) handle(c net.Conn) {
	defer func() {
		_ = c.Close()
		p.mu.Lock()
		delete(p.conns, c)
		p.mu.Unlock()
	}()
	u, err := net.Dial("tcp", p.upstream)
	if err != nil {
		return
	}
	defer func() { _ = u.Close() }()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			if p.blackhole.Load() {
				continue
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(u, c)
	go pipe(c, u)
	<-done
}

// unresponsive makes the backend accept connections but never answer.
func (p *tcpProxy) unresponsive() { p.blackhole.Store(true) }

// closeAll stops listening and drops every connection: from now on a dial to
// the proxy's address is refused, as with a Valkey pod that is gone.
func (p *tcpProxy) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		_ = c.Close()
	}
}

// restore brings the backend back on the same address.
func (p *tcpProxy) restore(t *testing.T) {
	t.Helper()
	p.blackhole.Store(false)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		return
	}
	ln, err := net.Listen("tcp", p.addr)
	require.NoError(t, err)
	p.ln = ln
	go p.serve(ln)
}

// proxiedStore builds a store that reaches the test server through a fresh
// proxy, with a short operation deadline so the tests stay fast.
func proxiedStore(t *testing.T, operationTimeout time.Duration) (*Store, *tcpProxy) {
	t.Helper()
	upstream := os.Getenv("VALKEY_TEST_ADDR")
	if upstream == "" {
		upstream = "localhost:6379"
	}
	proxy := newTCPProxy(t, upstream)
	store, err := New(Config{
		Address:          proxy.addr,
		KeyPrefix:        fmt.Sprintf("mcptest:%s:", t.Name()),
		OperationTimeout: operationTimeout,
	})
	if err != nil {
		t.Skipf("skipping: no server at VALKEY_TEST_ADDR=%s: %v", upstream, err)
	}
	t.Cleanup(func() {
		proxy.restore(t)
		cleanupTestKeys(t, store)
		store.Close()
	})
	return store, proxy
}

// requireRecovers asserts the store answers again once the backend is back.
func requireRecovers(t *testing.T, store *Store, refreshToken, wantUser string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		user, err := store.GetRefreshTokenInfo(context.Background(), refreshToken)
		if err == nil {
			require.Equal(t, wantUser, user)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("store did not recover after the backend came back: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestOperationTimeout_UnresponsiveBackend: a Valkey that accepts connections
// but never answers fails every operation within the operation deadline,
// instead of holding the caller for as long as the outage lasts (valkey-go
// otherwise retries read commands until the caller's context ends).
func TestOperationTimeout_UnresponsiveBackend(t *testing.T) {
	const opTimeout = 300 * time.Millisecond
	store, proxy := proxiedStore(t, opTimeout)
	ctx := context.Background()

	require.NoError(t, store.SaveRefreshToken(ctx, "rt-unresponsive", "user-1", time.Now().Add(time.Hour)))
	require.NoError(t, store.SaveTokenMetadata(ctx, "rt-unresponsive", storage.TokenMetadata{UserID: "user-1", ClientID: "c1"}))

	proxy.unresponsive()

	start := time.Now()
	_, err := store.GetRefreshTokenInfo(ctx, "rt-unresponsive")
	elapsed := time.Since(start)
	require.Error(t, err)
	require.True(t, storage.IsTransientError(err), "an unanswered read is a transient failure, got %v", err)
	require.Less(t, elapsed, opTimeout+time.Second, "operation must fail within its deadline (took %v): %v", elapsed, err)
	t.Logf("unanswered GetRefreshTokenInfo failed after %v: %v", elapsed, err)

	// The context-less metadata read runs under the deadline alone.
	start = time.Now()
	_, err = store.GetTokenMetadata("rt-unresponsive")
	elapsed = time.Since(start)
	require.Error(t, err)
	require.True(t, storage.IsTransientError(err), "got %v", err)
	require.Less(t, elapsed, opTimeout+time.Second, "GetTokenMetadata must fail within the deadline (took %v)", elapsed)

	// A caller's shorter deadline still wins.
	shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = store.GetRefreshTokenInfo(shortCtx, "rt-unresponsive")
	require.Error(t, err)
	require.Less(t, time.Since(start), opTimeout, "the caller's shorter deadline must be honoured")

	proxy.restore(t)
	requireRecovers(t, store, "rt-unresponsive", "user-1")
}

// TestOperationTimeout_DeadBackend: nothing listening at the endpoint fails
// reads and writes within the operation deadline; valkey-go's reconnect and
// read-retry loop is cut off by the deadline.
func TestOperationTimeout_DeadBackend(t *testing.T) {
	const opTimeout = 300 * time.Millisecond
	store, proxy := proxiedStore(t, opTimeout)
	ctx := context.Background()

	require.NoError(t, store.SaveRefreshToken(ctx, "rt-dead", "user-2", time.Now().Add(time.Hour)))

	proxy.closeAll()

	start := time.Now()
	_, err := store.GetRefreshTokenInfo(ctx, "rt-dead")
	elapsed := time.Since(start)
	require.Error(t, err)
	require.True(t, storage.IsTransientError(err), "got %v", err)
	require.Less(t, elapsed, opTimeout+time.Second, "read against a dead endpoint must fail within the deadline (took %v): %v", elapsed, err)
	t.Logf("GetRefreshTokenInfo against a dead endpoint failed after %v: %v", elapsed, err)

	start = time.Now()
	err = store.SaveRefreshToken(ctx, "rt-dead-2", "user-2", time.Now().Add(time.Hour))
	elapsed = time.Since(start)
	require.Error(t, err)
	require.True(t, storage.IsTransientError(err), "got %v", err)
	require.Less(t, elapsed, opTimeout+time.Second, "write against a dead endpoint must fail within the deadline (took %v)", elapsed)

	proxy.restore(t)
	requireRecovers(t, store, "rt-dead", "user-2")
}

// TestOperationTimeout_ClientSecretValidationSurfacesOutage: a client lookup
// that failed because Valkey did not answer is reported as that failure, not
// as rejected credentials — a client must not be told its secret is wrong
// because the store is down.
func TestOperationTimeout_ClientSecretValidationSurfacesOutage(t *testing.T) {
	const opTimeout = 300 * time.Millisecond
	store, proxy := proxiedStore(t, opTimeout)
	ctx := context.Background()

	require.NoError(t, store.SaveClient(ctx, &storage.Client{
		ClientID: "confidential-1", ClientType: storage.ClientTypeConfidential,
		ClientSecretHash: storage.DummyBcryptHash, CreatedAt: time.Now(),
	}))
	err := store.ValidateClientSecret(ctx, "confidential-1", "wrong")
	require.ErrorIs(t, err, storage.ErrInvalidClientCredentials)
	require.False(t, storage.IsTransientError(err), "a wrong secret is a rejection, not an outage")

	proxy.closeAll()
	start := time.Now()
	err = store.ValidateClientSecret(ctx, "confidential-1", "wrong")
	require.Error(t, err)
	require.NotErrorIs(t, err, storage.ErrInvalidClientCredentials)
	require.True(t, storage.IsTransientError(err), "got %v", err)
	require.Less(t, time.Since(start), opTimeout+time.Second)
}

func TestNew_OperationTimeoutValidation(t *testing.T) {
	_, err := New(Config{Address: "127.0.0.1:1", OperationTimeout: -time.Second})
	require.Error(t, err)
	require.Contains(t, err.Error(), "OperationTimeout")
}

func TestStore_DefaultOperationTimeout(t *testing.T) {
	store := testStore(t)
	require.Equal(t, storage.DefaultOperationTimeout, store.operationTimeout)
}
