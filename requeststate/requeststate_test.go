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
	"github.com/giantswarm/mcp-oauth/security"
)

func testKey(id byte) security.Key {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7) + id
	}
	return security.Key{ID: id, Secret: secret}
}

func testSealer(t *testing.T, active security.Key, previous ...security.Key) *Sealer {
	t.Helper()
	ring, err := security.NewKeyRing(active, previous...)
	require.NoError(t, err)
	s, err := New(ring)
	require.NoError(t, err)
	return s
}

const request = "tools/call:deploy:abc"

func alice() *providers.UserInfo {
	return &providers.UserInfo{Issuer: "https://dex.example", ID: "alice", ClientID: "cursor"}
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := testSealer(t, testKey(1))
	sealed, err := s.Seal(alice(), request, []byte("inner state"), time.Minute)
	require.NoError(t, err)
	require.NotContains(t, sealed, "inner")
	got, err := s.Open(alice(), request, sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("inner state"), got)
}

func TestOpenRefuses(t *testing.T) {
	s := testSealer(t, testKey(1))
	delegated := alice()
	delegated.ActorIssuer, delegated.ActorSubject = "https://dex.example", "agent-a"
	sealed, err := s.Seal(alice(), request, []byte("x"), time.Minute)
	require.NoError(t, err)
	sealedForAgent, err := s.Seal(delegated, request, []byte("x"), time.Minute)
	require.NoError(t, err)
	other := testSealer(t, testKey(2))
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	require.NoError(t, err)
	flipped := bytes.Clone(raw)
	flipped[len(flipped)-1] ^= 1
	relabelled := bytes.Clone(raw)
	relabelled[1] = 2

	with := func(change func(*providers.UserInfo)) *providers.UserInfo {
		u := alice()
		change(u)
		return u
	}
	for name, tc := range map[string]struct {
		sealer  *Sealer
		user    *providers.UserInfo
		request string
		value   string
	}{
		"another user":       {s, with(func(u *providers.UserInfo) { u.ID = "bob" }), request, sealed},
		"another issuer":     {s, with(func(u *providers.UserInfo) { u.Issuer = "https://other.example" }), request, sealed},
		"another client":     {s, with(func(u *providers.UserInfo) { u.ClientID = "claude" }), request, sealed},
		"no actor":           {s, alice(), request, sealedForAgent},
		"another actor":      {s, with(func(u *providers.UserInfo) { u.ActorIssuer, u.ActorSubject = "https://dex.example", "agent-b" }), request, sealedForAgent},
		"another request":    {s, alice(), "tools/call:deploy:def", sealed},
		"changed ciphertext": {s, alice(), request, base64.RawURLEncoding.EncodeToString(flipped)},
		"changed key ID":     {s, alice(), request, base64.RawURLEncoding.EncodeToString(relabelled)},
		"key not held":       {other, alice(), request, sealed},
		"not base64":         {s, alice(), request, "!!"},
		"too short":          {s, alice(), request, "AQE"},
		"oversized":          {s, alice(), request, strings.Repeat("A", MaxSealedLength+1)},
		"empty":              {s, alice(), request, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.sealer.Open(tc.user, tc.request, tc.value)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestOpenExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := testSealer(t, testKey(1))
		sealed, err := s.Seal(alice(), request, nil, 10*time.Second)
		require.NoError(t, err)
		time.Sleep(9 * time.Second)
		_, err = s.Open(alice(), request, sealed)
		require.NoError(t, err)
		time.Sleep(time.Second)
		_, err = s.Open(alice(), request, sealed)
		require.ErrorIs(t, err, ErrExpired)
	})
}

func TestRotation(t *testing.T) {
	before := testSealer(t, testKey(1))
	sealed, err := before.Seal(alice(), request, []byte("x"), time.Minute)
	require.NoError(t, err)

	after := testSealer(t, testKey(2), testKey(1))
	got, err := after.Open(alice(), request, sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("x"), got)

	resealed, err := after.Seal(alice(), request, []byte("y"), time.Minute)
	require.NoError(t, err)
	_, err = before.Open(alice(), request, resealed)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestNewRefusesRingWithoutActiveKey(t *testing.T) {
	_, err := New(nil)
	require.Error(t, err)
	ring, err := security.NewKeyRing(testKey(1))
	require.NoError(t, err)
	_, err = New(ringWithoutActive{ring})
	require.Error(t, err)
}

// ringWithoutActive names an active kid its ring does not resolve.
type ringWithoutActive struct{ security.KeyRing }

func (ringWithoutActive) ActiveKID() byte { return 9 }

func TestSealRefuses(t *testing.T) {
	s := testSealer(t, testKey(1))
	for name, tc := range map[string]struct {
		user    *providers.UserInfo
		request string
		payload []byte
		ttl     time.Duration
	}{
		"no user":    {nil, request, nil, time.Minute},
		"no issuer":  {&providers.UserInfo{ID: "alice"}, request, nil, time.Minute},
		"no subject": {&providers.UserInfo{Issuer: "https://dex.example"}, request, nil, time.Minute},
		"no client":  {&providers.UserInfo{Issuer: "https://dex.example", ID: "alice"}, request, nil, time.Minute},
		"no request": {alice(), "", nil, time.Minute},
		"no ttl":     {alice(), request, nil, 0},
		"oversized":  {alice(), request, make([]byte, MaxSealedLength), time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Seal(tc.user, tc.request, tc.payload, tc.ttl)
			require.Error(t, err)
		})
	}
}

func TestOpenRefusesUserWithoutClient(t *testing.T) {
	s := testSealer(t, testKey(1))
	sealed, err := s.Seal(alice(), request, nil, time.Minute)
	require.NoError(t, err)
	_, err = s.Open(&providers.UserInfo{Issuer: "https://dex.example", ID: "alice"}, request, sealed)
	require.Error(t, err)
}
