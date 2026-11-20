package valkey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRevocationIndexesExtendFractionalRemainingLifetime(t *testing.T) {
	for _, index := range []string{"family", "user-client", "existing-key"} {
		t.Run(index, func(t *testing.T) {
			store := testStore(t)
			key := store.familyKey("family")
			switch index {
			case "family":
				require.NoError(t, store.saddExtendOnlyTTL(t.Context(), key, "existing", time.Hour))
			case "user-client":
				key = store.userClientKey("person", "client")
				store.addToUserClientSet(t.Context(), "person", "client", "existing", time.Hour)
			case "existing-key":
				require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(key).Value("existing").Build()).Error())
			}
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Pexpire().Key(key).Milliseconds(1500).Build()).Error())
			minimumExpiry := time.Now().Add(1800 * time.Millisecond)
			switch index {
			case "family":
				require.NoError(t, store.addTokenToFamilySet(t.Context(), "new", "family", 1800*time.Millisecond))
			case "user-client":
				store.addToUserClientSet(t.Context(), "person", "client", "new", 1800*time.Millisecond)
			case "existing-key":
				require.NoError(t, store.client.Do(t.Context(), store.client.B().Eval().Script(luaExtendOnlyTTL).Numkeys(1).Key(key).Arg("2").Build()).Error())
			}
			remaining, err := store.client.Do(t.Context(), store.client.B().Pttl().Key(key).Build()).AsInt64()
			require.NoError(t, err)
			require.GreaterOrEqual(t, time.Duration(remaining)*time.Millisecond, time.Until(minimumExpiry))
		})
	}
}
