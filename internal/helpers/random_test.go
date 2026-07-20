package helpers

import (
	"encoding/hex"
	"testing"
)

func TestRandomHexToken(t *testing.T) {
	t.Run("length and hex encoding", func(t *testing.T) {
		for _, nBytes := range []int{1, 16, 32} {
			token, err := RandomHexToken(nBytes)
			if err != nil {
				t.Fatalf("RandomHexToken(%d) error = %v", nBytes, err)
			}
			if len(token) != 2*nBytes {
				t.Errorf("RandomHexToken(%d) length = %d, want %d", nBytes, len(token), 2*nBytes)
			}
			if _, err := hex.DecodeString(token); err != nil {
				t.Errorf("RandomHexToken(%d) = %q is not valid hex: %v", nBytes, token, err)
			}
		}
	})

	t.Run("zero bytes yields empty string", func(t *testing.T) {
		token, err := RandomHexToken(0)
		if err != nil {
			t.Fatalf("RandomHexToken(0) error = %v", err)
		}
		if token != "" {
			t.Errorf("RandomHexToken(0) = %q, want empty string", token)
		}
	})

	t.Run("negative bytes returns error", func(t *testing.T) {
		if _, err := RandomHexToken(-1); err == nil {
			t.Error("RandomHexToken(-1) expected error, got nil")
		}
	})

	t.Run("successive tokens differ", func(t *testing.T) {
		seen := make(map[string]bool)
		for range 32 {
			token, err := RandomHexToken(16)
			if err != nil {
				t.Fatalf("RandomHexToken(16) error = %v", err)
			}
			if seen[token] {
				t.Fatalf("RandomHexToken(16) produced duplicate token %q", token)
			}
			seen[token] = true
		}
	})
}
