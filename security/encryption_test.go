package security

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("GenerateKey() returned key of length %d, want 32", len(key))
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	equal := true
	for i := range key {
		if key[i] != key2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("GenerateKey() returned identical keys")
	}
}

func TestNewEncryptor(t *testing.T) {
	// Use a real random key for the valid case — 32 zero bytes now (correctly)
	// fails the entropy check, so we can't use make([]byte, 32) any more.
	randKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randKey); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	tests := []struct {
		name       string
		key        []byte
		wantErr    bool
		wantEnable bool
	}{
		{
			name:       "valid random 32-byte key",
			key:        randKey,
			wantErr:    false,
			wantEnable: true,
		},
		{
			name:       "nil key (disabled)",
			key:        nil,
			wantErr:    false,
			wantEnable: false,
		},
		{
			name:       "empty key (disabled)",
			key:        []byte{},
			wantErr:    false,
			wantEnable: false,
		},
		{
			name:       "invalid key length (16 bytes)",
			key:        make([]byte, 16),
			wantErr:    true,
			wantEnable: false,
		},
		{
			name:       "invalid key length (64 bytes)",
			key:        make([]byte, 64),
			wantErr:    true,
			wantEnable: false,
		},
		{
			// Catches copy-paste failure modes: all-zeros placeholder
			// written into a secret manager, accidentally-left-default.
			name:       "low-entropy key (32 zero bytes)",
			key:        make([]byte, 32),
			wantErr:    true,
			wantEnable: false,
		},
		{
			// ASCII placeholder like "aaaa…" — 0 entropy, passes length.
			name:       "low-entropy key (32 'a' bytes)",
			key:        bytes.Repeat([]byte{'a'}, 32),
			wantErr:    true,
			wantEnable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := NewEncryptor(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if enc.IsEnabled() != tt.wantEnable {
					t.Errorf("IsEnabled() = %v, want %v", enc.IsEnabled(), tt.wantEnable)
				}
			}
		})
	}
}

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple string",
			plaintext: "hello world",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "long string",
			plaintext: "this is a much longer string with special characters !@#$%^&*()_+-={}[]|:;<>?,./~`",
		},
		{
			name:      "unicode",
			plaintext: "Hello 世界 🌍",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext is different from plaintext
			if ciphertext == tt.plaintext && tt.plaintext != "" {
				t.Error("Encrypt() returned plaintext unchanged")
			}

			// Verify ciphertext is base64 encoded
			if _, err := base64.StdEncoding.DecodeString(ciphertext); err != nil {
				t.Errorf("Encrypt() did not return base64 encoded string: %v", err)
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify decrypted matches original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptor_EncryptDecrypt_Disabled(t *testing.T) {
	// Create disabled encryptor
	enc, err := NewEncryptor(nil)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "test data"

	// Encrypt should return plaintext unchanged
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if ciphertext != plaintext {
		t.Errorf("Encrypt() with disabled encryptor = %q, want %q", ciphertext, plaintext)
	}

	// Decrypt should also return plaintext unchanged
	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() with disabled encryptor = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptor_Decrypt_InvalidData(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!!!",
		},
		{
			name:       "too short",
			ciphertext: base64.StdEncoding.EncodeToString([]byte("short")),
		},
		{
			name:       "corrupted data",
			ciphertext: base64.StdEncoding.EncodeToString([]byte("this is corrupted data that won't decrypt properly")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("Decrypt() should return error for invalid data")
			}
		})
	}
}

func TestEncryptor_Decrypt_WrongKey(t *testing.T) {
	// Encrypt with one key
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc1, err := NewEncryptor(key1)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	ciphertext, err := enc1.Encrypt("secret data")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with different key
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enc2, err := NewEncryptor(key2)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	_, err = enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt() with wrong key should return error")
	}
}

func TestKeyFromBase64(t *testing.T) {
	// Generate a valid key and encode it
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encoded := KeyToBase64(key)

	// Decode it back
	decoded, err := KeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("KeyFromBase64() error = %v", err)
	}

	// Verify it matches
	if len(decoded) != len(key) {
		t.Errorf("KeyFromBase64() returned key of length %d, want %d", len(decoded), len(key))
	}

	for i := range key {
		if decoded[i] != key[i] {
			t.Errorf("KeyFromBase64() byte %d = %d, want %d", i, decoded[i], key[i])
		}
	}
}

func TestKeyFromBase64_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		wantErr bool
	}{
		{
			name:    "invalid base64",
			encoded: "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "wrong length",
			encoded: base64.StdEncoding.EncodeToString(make([]byte, 16)),
			wantErr: true,
		},
		{
			name:    "empty",
			encoded: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := KeyFromBase64(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyFromBase64() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyToBase64(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encoded := KeyToBase64(key)

	// Verify it's valid base64
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Errorf("KeyToBase64() returned invalid base64: %v", err)
	}
}

func TestKeyFromHex(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encoded := KeyToHex(key)
	if len(encoded) != 64 {
		t.Errorf("KeyToHex() returned %d chars, want 64", len(encoded))
	}

	decoded, err := KeyFromHex(encoded)
	if err != nil {
		t.Fatalf("KeyFromHex() error = %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Errorf("KeyFromHex() round-trip mismatch")
	}
}

func TestKeyFromHex_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"non-hex chars", "zz" + bytesToHex(make([]byte, 31))},
		{"wrong length (short)", hex.EncodeToString(make([]byte, 16))},
		{"wrong length (long)", hex.EncodeToString(make([]byte, 48))},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := KeyFromHex(tt.encoded); err == nil {
				t.Errorf("KeyFromHex(%q) succeeded, want error", tt.encoded)
			}
		})
	}
}

func bytesToHex(b []byte) string { return hex.EncodeToString(b) }

func TestDecodeKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	t.Run("base64", func(t *testing.T) {
		decoded, err := DecodeKey(KeyToBase64(key))
		if err != nil {
			t.Fatalf("DecodeKey(base64) error = %v", err)
		}
		if !bytes.Equal(decoded, key) {
			t.Error("DecodeKey(base64) round-trip mismatch")
		}
	})

	t.Run("hex", func(t *testing.T) {
		decoded, err := DecodeKey(KeyToHex(key))
		if err != nil {
			t.Fatalf("DecodeKey(hex) error = %v", err)
		}
		if !bytes.Equal(decoded, key) {
			t.Error("DecodeKey(hex) round-trip mismatch")
		}
	})
}

func TestDecodeKey_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"neither base64 nor hex", "!!!not-a-key!!!"},
		{"base64 wrong length", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"hex wrong length", hex.EncodeToString(make([]byte, 16))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeKey(tt.encoded); err == nil {
				t.Errorf("DecodeKey(%q) succeeded, want error", tt.encoded)
			}
		})
	}
}

func TestEncryptionFormat(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	encrypted, err := enc.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	// v1 envelope: 0x01 || kid || nonce || ct(plaintext + tag)
	const (
		envelopeHeaderSize = 2 // tag + kid
		expectedNonceSize  = 12
		gcmTagSize         = 16
	)
	// "test" = 4 bytes → 2 + 12 + 4 + 16 = 34 bytes
	const expectedTotalSize = envelopeHeaderSize + expectedNonceSize + 4 + gcmTagSize
	if len(decoded) != expectedTotalSize {
		t.Errorf("expected total size %d bytes, got %d", expectedTotalSize, len(decoded))
	}
	if decoded[0] != envelopeV1Tag {
		t.Errorf("expected envelope tag 0x%02x, got 0x%02x", envelopeV1Tag, decoded[0])
	}
	if decoded[1] != 0 {
		t.Errorf("expected single-key kid=0, got %d", decoded[1])
	}
}

// TestEncryptor_DecryptV0LegacyEnvelope verifies that ciphertexts produced
// by the pre-KeyRing release (raw `nonce || ct`, no version tag) remain
// readable. Rolling-upgrade safety: existing Valkey rows must not need
// re-encryption.
func TestEncryptor_DecryptV0LegacyEnvelope(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	// Hand-roll a v0 envelope using the same AEAD the Encryptor holds.
	aead, err := enc.ring.AEAD(0)
	if err != nil {
		t.Fatalf("AEAD(0) error = %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("failed to read nonce: %v", err)
	}
	const plaintext = "legacy-row-from-previous-release"
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	legacy := base64.StdEncoding.EncodeToString(append(nonce, ct...))

	got, err := enc.Decrypt(legacy)
	if err != nil {
		t.Fatalf("Decrypt(v0 envelope) error = %v", err)
	}
	if got != plaintext {
		t.Errorf("v0 envelope decrypted to %q, want %q", got, plaintext)
	}
}

func TestEncryptor_DecryptV1UnknownKID(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	// v1 envelope with a kid that the single-key ring does not recognise.
	envelope := []byte{envelopeV1Tag, 0x99}
	envelope = append(envelope, make([]byte, 12+16)...) // nonce + tag-shaped padding
	if _, err := enc.Decrypt(base64.StdEncoding.EncodeToString(envelope)); err == nil {
		t.Error("Decrypt should fail with unknown kid")
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "same plaintext"

	// Encrypt the same plaintext multiple times
	encrypted1, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted2, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertexts should be different due to unique nonces
	if encrypted1 == encrypted2 {
		t.Error("Encrypt() returned identical ciphertexts for same plaintext - nonce not unique")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := enc.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	decrypted2, err := enc.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Errorf("Decrypt() failed: got %q and %q, want %q", decrypted1, decrypted2, plaintext)
	}

	// Verify nonces are actually different
	decoded1, _ := base64.StdEncoding.DecodeString(encrypted1)
	decoded2, _ := base64.StdEncoding.DecodeString(encrypted2)

	nonce1 := decoded1[:12]
	nonce2 := decoded2[:12]

	nonceEqual := true
	for i := range nonce1 {
		if nonce1[i] != nonce2[i] {
			nonceEqual = false
			break
		}
	}

	if nonceEqual {
		t.Error("Encrypt() generated identical nonces - CRITICAL SECURITY ISSUE")
	}
}

func TestValidateKeyEntropy(t *testing.T) {
	// Use a real random key for the happy case (fixed — deterministic test).
	random32 := []byte{
		0x3f, 0xa9, 0x17, 0x4d, 0xe2, 0x0c, 0x5b, 0x71,
		0x8e, 0x24, 0xc7, 0x93, 0x06, 0xf8, 0xab, 0x62,
		0x19, 0x5d, 0x7e, 0xa0, 0x4b, 0xcf, 0x38, 0x82,
		0x1c, 0x65, 0xd4, 0x0f, 0x97, 0x2b, 0xe6, 0x51,
	}

	// 16 distinct bytes repeated to length 32 — sits exactly on the threshold.
	exactly16Distinct := make([]byte, 32)
	for i := range 16 {
		exactly16Distinct[i] = byte(i)
		exactly16Distinct[i+16] = byte(i)
	}

	// 15 distinct bytes — one short of the threshold.
	fifteenDistinct := make([]byte, 32)
	for i := range fifteenDistinct {
		fifteenDistinct[i] = byte(i % 15)
	}

	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"empty (opt-out of encryption)", nil, false},
		{"random 32 bytes", random32, false},
		{"32 zero bytes", make([]byte, 32), true},
		{"32 0xff bytes", bytes.Repeat([]byte{0xff}, 32), true},
		{"32 'a' bytes (ascii placeholder)", bytes.Repeat([]byte{'a'}, 32), true},
		{"alternating two bytes 0xAB/0xCD", bytes.Repeat([]byte{0xAB, 0xCD}, 16), true},
		{"15 distinct bytes (below threshold)", fifteenDistinct, true},
		{"exactly 16 distinct bytes (at threshold)", exactly16Distinct, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyEntropy(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyEntropy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDistinctBytes(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"single byte", []byte{0x42}, 1},
		{"all same byte", bytes.Repeat([]byte{0xab}, 100), 1},
		{"two values", append(bytes.Repeat([]byte{0}, 50), bytes.Repeat([]byte{1}, 50)...), 2},
		{"full alphabet once each", fullByteAlphabet(), 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := distinctBytes(tt.in); got != tt.want {
				t.Errorf("distinctBytes = %d, want %d", got, tt.want)
			}
		})
	}
}

func fullByteAlphabet() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
