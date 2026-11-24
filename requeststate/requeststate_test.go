package requeststate

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
)

func testKey(t *testing.T, id byte) Key {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7) + id
	}
	return Key{ID: id, Secret: secret}
}

var (
	alice = &providers.UserInfo{Issuer: "https://dex.example", ID: "alice"}
	bob   = &providers.UserInfo{Issuer: "https://dex.example", ID: "bob"}
)

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := s.Seal(alice, "call_tool:abc", []byte("inner state"), time.Minute)
	require.NoError(t, err)
	require.NotContains(t, sealed, "inner")
	got, err := s.Open(alice, "call_tool:abc", sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("inner state"), got)
}

func TestOpenRefuses(t *testing.T) {
	s, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := s.Seal(alice, "call", []byte("x"), time.Minute)
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
		sealer *Sealer
		user   *providers.UserInfo
		call   string
		value  string
	}{
		"another user":       {s, bob, "call", sealed},
		"another issuer":     {s, &providers.UserInfo{Issuer: "https://other.example", ID: "alice"}, "call", sealed},
		"another call":       {s, alice, "other", sealed},
		"changed ciphertext": {s, alice, "call", base64.RawURLEncoding.EncodeToString(flipped)},
		"changed key ID":     {s, alice, "call", base64.RawURLEncoding.EncodeToString(relabelled)},
		"key not held":       {other, alice, "call", sealed},
		"not base64":         {s, alice, "call", "!!"},
		"too short":          {s, alice, "call", "AQE"},
		"oversized":          {s, alice, "call", strings.Repeat("A", MaxSealedLength+1)},
		"empty":              {s, alice, "call", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.sealer.Open(tc.user, tc.call, tc.value)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestOpenExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New(testKey(t, 1))
		require.NoError(t, err)
		sealed, err := s.Seal(alice, "call", nil, 10*time.Second)
		require.NoError(t, err)
		time.Sleep(9 * time.Second)
		_, err = s.Open(alice, "call", sealed)
		require.NoError(t, err)
		time.Sleep(time.Second)
		_, err = s.Open(alice, "call", sealed)
		require.ErrorIs(t, err, ErrExpired)
	})
}

func TestRotation(t *testing.T) {
	before, err := New(testKey(t, 1))
	require.NoError(t, err)
	sealed, err := before.Seal(alice, "call", []byte("x"), time.Minute)
	require.NoError(t, err)

	after, err := New(testKey(t, 2), testKey(t, 1))
	require.NoError(t, err)
	got, err := after.Open(alice, "call", sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("x"), got)

	resealed, err := after.Seal(alice, "call", []byte("y"), time.Minute)
	require.NoError(t, err)
	_, err = before.Open(alice, "call", resealed)
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
	_, err = s.Seal(nil, "call", nil, time.Minute)
	require.Error(t, err)
	_, err = s.Seal(&providers.UserInfo{ID: "alice"}, "call", nil, time.Minute)
	require.Error(t, err)
	_, err = s.Seal(alice, "call", nil, 0)
	require.Error(t, err)
	_, err = s.Seal(alice, "call", make([]byte, MaxSealedLength), time.Minute)
	require.Error(t, err)
}
