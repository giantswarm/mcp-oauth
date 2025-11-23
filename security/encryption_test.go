package security

import (
	"encoding/base64"
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
	tests := []struct {
		name       string
		key        []byte
		wantErr    bool
		wantEnable bool
	}{
		{
			name:       "valid 32-byte key",
			key:        make([]byte, 32),
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
