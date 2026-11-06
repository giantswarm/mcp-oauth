package security

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsentCookieKeyDerivation(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	first, err := NewEncryptor(key)
	require.NoError(t, err)
	second, err := NewEncryptor(key)
	require.NoError(t, err)
	left, err := first.ConsentCookieKey("https://auth.example.com/a")
	require.NoError(t, err)
	right, err := second.ConsentCookieKey("https://auth.example.com/a")
	require.NoError(t, err)
	require.Equal(t, left, right)
	require.Len(t, left, 32)
	require.NotEqual(t, key, left)
	other, err := first.ConsentCookieKey("https://auth.example.com/b")
	require.NoError(t, err)
	require.NotEqual(t, left, other)
}
