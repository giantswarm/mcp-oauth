package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHMACNonceProvider_CurrentWindowAccepted(t *testing.T) {
	now := time.Unix(1000, 0)
	provider := NewHMACNonceProvider([]byte("secret"), time.Minute, func() time.Time { return now })

	nonce := provider.Nonce(t.Context())
	require.NotEmpty(t, nonce)
	require.True(t, provider.Valid(t.Context(), nonce))
}

func TestHMACNonceProvider_PreviousWindowAccepted(t *testing.T) {
	secret := []byte("secret")
	window := time.Minute

	// Provider at time T returns a nonce.
	tPrev := time.Unix(1000, 0)
	prevProvider := NewHMACNonceProvider(secret, window, func() time.Time { return tPrev })
	prevNonce := prevProvider.Nonce(t.Context())

	// One window later the previous nonce is still valid (boundary grace).
	tCur := tPrev.Add(window)
	curProvider := NewHMACNonceProvider(secret, window, func() time.Time { return tCur })
	require.True(t, curProvider.Valid(t.Context(), prevNonce))
}

func TestHMACNonceProvider_TwoWindowsAgoRejected(t *testing.T) {
	secret := []byte("secret")
	window := time.Minute

	tOld := time.Unix(1000, 0)
	oldProvider := NewHMACNonceProvider(secret, window, func() time.Time { return tOld })
	oldNonce := oldProvider.Nonce(t.Context())

	tCur := tOld.Add(2 * window)
	curProvider := NewHMACNonceProvider(secret, window, func() time.Time { return tCur })
	require.False(t, curProvider.Valid(t.Context(), oldNonce))
}

func TestHMACNonceProvider_WrongSecretRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	p1 := NewHMACNonceProvider([]byte("secret-A"), time.Minute, func() time.Time { return now })
	p2 := NewHMACNonceProvider([]byte("secret-B"), time.Minute, func() time.Time { return now })

	nonce := p1.Nonce(t.Context())
	require.False(t, p2.Valid(t.Context(), nonce))
}

func TestHMACNonceProvider_EmptyNonceRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	provider := NewHMACNonceProvider([]byte("secret"), time.Minute, func() time.Time { return now })
	require.False(t, provider.Valid(t.Context(), ""))
}

func TestHMACNonceProvider_NilNowDefaultsToTimeNow(t *testing.T) {
	provider := NewHMACNonceProvider([]byte("secret"), time.Minute, nil)
	nonce := provider.Nonce(t.Context())
	require.NotEmpty(t, nonce)
	require.True(t, provider.Valid(t.Context(), nonce))
}

func TestHMACNonceProvider_ZeroWindowDefaultsTenMinutes(t *testing.T) {
	now := time.Unix(1000, 0)
	provider := NewHMACNonceProvider([]byte("secret"), 0, func() time.Time { return now })
	nonce := provider.Nonce(t.Context())
	require.NotEmpty(t, nonce)
	require.True(t, provider.Valid(t.Context(), nonce))
}
