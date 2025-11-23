package oauth

import (
	"encoding/base64"
	"testing"
)

func TestTokenEncryption_GenerateKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("GenerateEncryptionKey() key length = %d, want 32", len(key))
	}

	// Generate another key and ensure they're different
	key2, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	if string(key) == string(key2) {
		t.Error("GenerateEncryptionKey() generated identical keys (should be random)")
	}
}

func TestTokenEncryption_EncryptDecrypt(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	enc, err := NewTokenEncryption(key)
	if err != nil {
		t.Fatalf("NewTokenEncryption() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple token", "access_token_123456"},
		{"long token", "very_long_token_with_lots_of_characters_to_test_larger_plaintexts"},
		{"empty string", ""},
		{"special chars", "token!@#$%^&*()_+-={}[]|:;<>?,./"},
		{"unicode", "token_🔐_secure_🛡️"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Empty plaintext should return empty ciphertext
			if tt.plaintext == "" {
				if ciphertext != "" {
					t.Errorf("Encrypt('') = %q, want ''", ciphertext)
				}
				return
			}

			// Ciphertext should be different from plaintext
			if ciphertext == tt.plaintext {
				t.Error("Encrypt() returned plaintext unchanged")
			}

			// Ciphertext should be base64-encoded
			_, err = base64.StdEncoding.DecodeString(ciphertext)
			if err != nil {
				t.Errorf("Encrypt() did not return valid base64: %v", err)
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Decrypted should match original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestTokenEncryption_DisabledEncryption(t *testing.T) {
	// Create encryption with nil key (disabled)
	enc, err := NewTokenEncryption(nil)
	if err != nil {
		t.Fatalf("NewTokenEncryption(nil) error = %v", err)
	}

	if enc.enabled {
		t.Error("NewTokenEncryption(nil) should have encryption disabled")
	}

	plaintext := "access_token_123"

	// Encrypt should return plaintext
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() with disabled encryption error = %v", err)
	}

	if ciphertext != plaintext {
		t.Errorf("Encrypt() with disabled encryption = %q, want %q", ciphertext, plaintext)
	}

	// Decrypt should also return plaintext
	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() with disabled encryption error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() with disabled encryption = %q, want %q", decrypted, plaintext)
	}
}

func TestTokenEncryption_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"16 bytes (AES-128)", 16},
		{"24 bytes (AES-192)", 24},
		{"31 bytes (invalid)", 31},
		{"33 bytes (invalid)", 33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewTokenEncryption(key)
			if err == nil {
				t.Error("NewTokenEncryption() with invalid key size should return error")
			}
		})
	}
}

func TestTokenEncryption_DifferentCiphertexts(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	enc, err := NewTokenEncryption(key)
	if err != nil {
		t.Fatalf("NewTokenEncryption() error = %v", err)
	}

	plaintext := "same_token_encrypted_twice"

	// Encrypt same plaintext twice
	ciphertext1, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext2, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertexts should be different (due to random nonce)
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypt() produced same ciphertext for same plaintext (nonce reuse!)")
	}

	// But both should decrypt to same plaintext
	decrypted1, err := enc.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	decrypted2, err := enc.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Error("Decrypt() failed to decrypt both ciphertexts correctly")
	}
}

func TestTokenEncryption_TamperedCiphertext(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	enc, err := NewTokenEncryption(key)
	if err != nil {
		t.Fatalf("NewTokenEncryption() error = %v", err)
	}

	plaintext := "sensitive_token"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Tamper with ciphertext
	decoded, _ := base64.StdEncoding.DecodeString(ciphertext)
	if len(decoded) > 20 {
		decoded[20] ^= 0xFF // Flip bits in the middle
	}
	tamperedCiphertext := base64.StdEncoding.EncodeToString(decoded)

	// Decryption should fail due to authentication tag mismatch
	_, err = enc.Decrypt(tamperedCiphertext)
	if err == nil {
		t.Error("Decrypt() should fail for tampered ciphertext (GCM authentication failure)")
	}
}

func TestEncryptionKeyFromBase64(t *testing.T) {
	// Generate a key and encode it
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	encoded := EncryptionKeyToBase64(key)

	// Decode it back
	decoded, err := EncryptionKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("EncryptionKeyFromBase64() error = %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("EncryptionKeyFromBase64() key length = %d, want 32", len(decoded))
	}

	if string(decoded) != string(key) {
		t.Error("EncryptionKeyFromBase64() did not decode to original key")
	}
}

func TestEncryptionKeyFromBase64_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"invalid base64", "not@valid@base64!!!"},
		{"wrong size", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := EncryptionKeyFromBase64(tt.encoded)
			if tt.encoded == "" {
				// Empty string should return nil, nil
				if err != nil || key != nil {
					t.Errorf("EncryptionKeyFromBase64('') = %v, %v, want nil, nil", key, err)
				}
			} else {
				if err == nil {
					t.Error("EncryptionKeyFromBase64() should return error for invalid input")
				}
			}
		})
	}
}
