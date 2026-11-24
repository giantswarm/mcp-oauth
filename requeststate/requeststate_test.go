package requeststate

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T, id byte) Key {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7) + id
	}
	return Key{ID: id, Secret: secret}
}

const dex = "https://dex.example"

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := s.Seal(dex, "alice", "call_tool:abc", []byte("inner state"), time.Minute)
	require.NoError(t, err)
	require.NotContains(t, sealed, "inner")
	got, err := s.Open(dex, "alice", "call_tool:abc", sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("inner state"), got)
}

func TestOpenRefuses(t *testing.T) {
	s, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := s.Seal(dex, "alice", "call", []byte("x"), time.Minute)
	require.NoError(t, err)
	other, err := New(testKey(t, 2))
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	require.NoError(t, err)
	flipped := bytes.Clone(raw)
	flipped[len(flipped)-1] ^= 1
	relabelled := bytes.Clone(raw)
	relabelled[1] = 2

	for name, tc := range map[string]struct {
		sealer  *Sealer
		issuer  string
		subject string
		call    string
		value   string
	}{
		"another user":       {s, dex, "bob", "call", sealed},
		"another issuer":     {s, "https://other.example", "alice", "call", sealed},
		"another call":       {s, dex, "alice", "other", sealed},
		"changed ciphertext": {s, dex, "alice", "call", base64.RawURLEncoding.EncodeToString(flipped)},
		"changed key ID":     {s, dex, "alice", "call", base64.RawURLEncoding.EncodeToString(relabelled)},
		"key not held":       {other, dex, "alice", "call", sealed},
		"not base64":         {s, dex, "alice", "call", "!!"},
		"too short":          {s, dex, "alice", "call", "AQE"},
		"oversized":          {s, dex, "alice", "call", strings.Repeat("A", MaxSealedLength+1)},
		"empty":              {s, dex, "alice", "call", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.sealer.Open(tc.issuer, tc.subject, tc.call, tc.value)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestOpenExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New(testKey(t, 1))
		require.NoError(t, err)
		sealed, err := s.Seal(dex, "alice", "call", nil, 10*time.Second)
		require.NoError(t, err)
		time.Sleep(9 * time.Second)
		_, err = s.Open(dex, "alice", "call", sealed)
		require.NoError(t, err)
		time.Sleep(time.Second)
		_, err = s.Open(dex, "alice", "call", sealed)
		require.ErrorIs(t, err, ErrExpired)
	})
}

func TestRotation(t *testing.T) {
	before, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := before.Seal(dex, "alice", "call", []byte("x"), time.Minute)
	require.NoError(t, err)

	after, err := New(testKey(t, 2), testKey(t, 1))
	require.NoError(t, err)
	got, err := after.Open(dex, "alice", "call", sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("x"), got)

	resealed, err := after.Seal(dex, "alice", "call", []byte("y"), time.Minute)
	require.NoError(t, err)
	_, err = before.Open(dex, "alice", "call", resealed)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestNewRefusesBadKeys(t *testing.T) {
	for name, keys := range map[string][]Key{
		"short":        {{ID: 1, Secret: make([]byte, 16)}},
		"low entropy":  {{ID: 1, Secret: make([]byte, 32)}},
		"duplicate ID": {testKey(t, 1), testKey(t, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(keys[0], keys[1:]...)
			require.Error(t, err)
		})
	}
}

func TestSealRefuses(t *testing.T) {
	s, err := New(testKey(t, 1))
	require.NoError(t, err)
	_, err = s.Seal("", "alice", "call", nil, time.Minute)
	require.Error(t, err)
	_, err = s.Seal(dex, "", "call", nil, time.Minute)
	require.Error(t, err)
	_, err = s.Seal(dex, "alice", "call", nil, 0)
	require.Error(t, err)
	_, err = s.Seal(dex, "alice", "call", make([]byte, MaxSealedLength), time.Minute)
	require.Error(t, err)
}
