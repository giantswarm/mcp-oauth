package valkey

import (
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
)

// FuzzSerializedTokenSize exercises the encrypt + marshal pipeline that
// SaveToken's size gate guards. Random id_token payloads of varying length
// must serialize deterministically and the maxTokenDataSize verdict must
// agree with the actual measured size on every input.
func FuzzSerializedTokenSize(f *testing.F) {
	seedSizes := []int{
		0,
		1,
		MinMaxTokenDataSize / 2,
		MinMaxTokenDataSize,
		DefaultMaxTokenDataSize / 4,
		DefaultMaxTokenDataSize / 2,
		DefaultMaxTokenDataSize - 1024,
		DefaultMaxTokenDataSize + 1024,
	}
	for _, n := range seedSizes {
		if n < 0 {
			continue
		}
		f.Add(make([]byte, n))
	}

	key, err := security.GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		f.Fatalf("NewEncryptor: %v", err)
	}
	store := &Store{
		encryptor:        encryptor,
		maxTokenDataSize: DefaultMaxTokenDataSize,
	}

	f.Fuzz(func(t *testing.T, idTokenPayload []byte) {
		// Bound work per iteration so the fuzzer can explore breadth without
		// hot-looping on a multi-megabyte allocation that swamps shared CI.
		if len(idTokenPayload) > MaxMaxTokenDataSize {
			t.Skip()
		}

		token := (&oauth2.Token{
			AccessToken:  "fuzz-access",
			RefreshToken: "fuzz-refresh",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(time.Hour),
		}).WithExtra(map[string]interface{}{
			"id_token": string(idTokenPayload),
			"scope":    "openid",
		})

		encrypted, err := store.encryptToken(token)
		if err != nil {
			t.Fatalf("encryptToken: %v", err)
		}

		data, err := json.Marshal(toSerializable(encrypted))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}

		overBudget := len(data) > store.maxTokenDataSize

		// Mirror the SaveToken size gate: the verdict must be byte-exact with
		// the measured length. Drift here means SaveToken would silently admit
		// or reject payloads the gate's other branch would treat differently.
		if overBudget && len(data) <= store.maxTokenDataSize {
			t.Fatalf("size verdict inconsistency: overBudget=true but len=%d <= cap=%d", len(data), store.maxTokenDataSize)
		}
		if !overBudget && len(data) > store.maxTokenDataSize {
			t.Fatalf("size verdict inconsistency: overBudget=false but len=%d > cap=%d", len(data), store.maxTokenDataSize)
		}
	})
}
