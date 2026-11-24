package security

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func ringKey(id byte) Key {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7) + id
	}
	return Key{ID: id, Secret: secret}
}

func TestNewKeyRing(t *testing.T) {
	ring, err := NewKeyRing(ringKey(2), ringKey(1))
	require.NoError(t, err)
	require.Equal(t, byte(2), ring.ActiveKID())

	active, err := ring.AEAD(2)
	require.NoError(t, err)
	previous, err := ring.AEAD(1)
	require.NoError(t, err)
	require.NotSame(t, active, previous)

	_, err = ring.AEAD(3)
	require.ErrorContains(t, err, "unknown key id 3")
}

func TestNewKeyRingRefusesBadKeys(t *testing.T) {
	for name, keys := range map[string][]Key{
		"short":        {{ID: 1, Secret: make([]byte, 16)}},
		"empty":        {{ID: 1}},
		"low entropy":  {{ID: 1, Secret: make([]byte, 32)}},
		"duplicate ID": {ringKey(1), ringKey(1)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewKeyRing(keys[0], keys[1:]...)
			require.Error(t, err)
		})
	}
}

func TestKeyID(t *testing.T) {
	require.Equal(t, KeyID(ringKey(1).Secret), KeyID(ringKey(1).Secret))
	require.NotEqual(t, KeyID(ringKey(1).Secret), KeyID(ringKey(2).Secret))
}
