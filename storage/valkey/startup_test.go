package valkey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"
)

// deadAddress returns a loopback address nothing listens on: a dial is refused,
// as with a Valkey pod that has not started yet.
func deadAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// requireTestServer skips unless the Valkey test server answers.
func requireTestServer(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	store, err := New(Config{Address: addr, StartupTimeout: testStartupTimeout})
	if err != nil {
		t.Skipf("skipping: no server at VALKEY_TEST_ADDR=%s: %v", addr, err)
	}
	store.Close()
	return addr
}

// TestNew_WaitsForValkeyToStart: a server that starts before its Valkey waits
// for it and comes up without an error once Valkey accepts connections.
func TestNew_WaitsForValkeyToStart(t *testing.T) {
	upstream := requireTestServer(t)
	proxy := newTCPProxy(t, upstream)
	proxy.closeAll() // Valkey not started yet: connections are refused.

	type result struct {
		store   *Store
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		store, err := New(Config{
			Address:        proxy.addr,
			KeyPrefix:      fmt.Sprintf("mcptest:%s:", t.Name()),
			StartupTimeout: 10 * time.Second,
		})
		done <- result{store, err, time.Since(start)}
	}()

	const startsAfter = time.Second
	time.Sleep(startsAfter)
	proxy.restore(t) // Valkey is up.

	res := <-done
	require.NoError(t, res.err)
	store := res.store
	t.Cleanup(store.Close)
	require.GreaterOrEqual(t, res.elapsed, startsAfter, "New must have waited for Valkey")
	require.Less(t, res.elapsed, startsAfter+startupBackoffMax, "New must connect soon after Valkey is up (took %v)", res.elapsed)

	require.NoError(t, store.SaveRefreshToken(context.Background(), "rt-startup", "user-1", time.Now().Add(time.Hour)))
	t.Logf("connected %v after start, Valkey came up after %v", res.elapsed, startsAfter)
}

// TestNew_FailsAfterStartupTimeout: a Valkey that never comes up fails
// start-up with a clear error once the startup timeout has passed.
func TestNew_FailsAfterStartupTimeout(t *testing.T) {
	const timeout = 600 * time.Millisecond
	start := time.Now()
	_, err := New(Config{Address: deadAddress(t), StartupTimeout: timeout})
	elapsed := time.Since(start)
	require.Error(t, err)
	require.ErrorContains(t, err, "valkey not reachable within the startup timeout of 600ms")
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	require.GreaterOrEqual(t, elapsed, timeout)
	require.Less(t, elapsed, timeout+time.Second, "New must give up at the timeout (took %v)", elapsed)
}

// TestNew_InvalidAddressFailsAtOnce: an address that cannot be dialled at all
// is not retried.
func TestNew_InvalidAddressFailsAtOnce(t *testing.T) {
	start := time.Now()
	_, err := New(Config{Address: "invalid:99999", StartupTimeout: time.Minute})
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second, "got %v", err)
}

func TestNew_NegativeStartupTimeout(t *testing.T) {
	_, err := New(Config{Address: "127.0.0.1:1", StartupTimeout: -time.Second})
	require.ErrorContains(t, err, "StartupTimeout")
}

func TestIsStartupRetryable(t *testing.T) {
	dialRefused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", fmt.Errorf("failed to create valkey client: %w", dialRefused), true},
		{"connection reset", fmt.Errorf("wrap: %w", syscall.ECONNRESET), true},
		{"DNS not resolvable yet", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "valkey", IsNotFound: true}}, true},
		{"EOF during handshake", fmt.Errorf("wrap: %w", io.EOF), true},
		{"deadline", fmt.Errorf("wrap: %w", context.DeadlineExceeded), true},
		{"invalid port", &net.OpError{Op: "dial", Err: &net.AddrError{Err: "invalid port", Addr: "invalid:99999"}}, false},
		{"TLS certificate", &net.OpError{Op: "remote error", Err: &tls.CertificateVerificationError{Err: errors.New("unknown authority")}}, false},
		{"TLS to a plaintext server", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, false},
		{"other error", errors.New("something else"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isStartupRetryable(tc.err), "%v", tc.err)
		})
	}
}

// TestIsStartupRetryable_WrongCredentials: the server's reply to wrong
// credentials is final, however long the startup timeout. (The test server's
// default user accepts any password, so the reply comes from an AUTH as a user
// that does not exist, which Valkey answers with the same WRONGPASS.)
func TestIsStartupRetryable_WrongCredentials(t *testing.T) {
	addr := requireTestServer(t)
	client, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	require.NoError(t, err)
	t.Cleanup(client.Close)

	authErr := client.Do(context.Background(), client.B().Auth().Username("no-such-user").Password("x").Build()).Error()
	require.ErrorContains(t, authErr, "WRONGPASS")
	require.False(t, isStartupRetryable(fmt.Errorf("failed to connect to valkey: %w", authErr)), "%v", authErr)
}
