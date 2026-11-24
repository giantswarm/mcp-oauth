package oauthconfig_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/providers"
)

var otherKeyB64 = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210FEDCBA9876543210"))

func TestNewRequestStateSealerFromEnv(t *testing.T) {
	user := &providers.UserInfo{Issuer: "https://dex.example", ID: "alice"}

	t.Run("unset returns nil", func(t *testing.T) {
		setRequired(t, "")
		sealer, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.NoError(t, err)
		require.Nil(t, sealer)
	})

	t.Run("file variant", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_REQUEST_STATE_KEY_FILE", writeSecretFile(t, validKeyHex+"\n"))
		sealer, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.NoError(t, err)
		require.NotNil(t, sealer)
	})

	t.Run("rotation opens values sealed with the previous key", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_REQUEST_STATE_KEY", validKeyB64)
		before, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.NoError(t, err)
		sealed, err := before.Seal(user, "call", []byte("x"), time.Minute)
		require.NoError(t, err)

		t.Setenv("OAUTH_REQUEST_STATE_KEY", otherKeyB64)
		t.Setenv("OAUTH_REQUEST_STATE_PREVIOUS_KEY", validKeyB64)
		after, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.NoError(t, err)
		got, err := after.Open(user, "call", sealed)
		require.NoError(t, err)
		require.Equal(t, []byte("x"), got)
	})

	t.Run("same key twice is refused", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_REQUEST_STATE_KEY", validKeyB64)
		t.Setenv("OAUTH_REQUEST_STATE_PREVIOUS_KEY", validKeyHex)
		_, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.Error(t, err)
	})

	t.Run("malformed key is refused", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_REQUEST_STATE_KEY", "not-a-key")
		_, err := oauthconfig.NewRequestStateSealerFromEnv()
		require.ErrorContains(t, err, "OAUTH_REQUEST_STATE_KEY")
	})
}
