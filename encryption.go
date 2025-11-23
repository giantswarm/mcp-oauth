package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// TokenEncryption provides encryption/decryption for tokens at rest
// Uses AES-256-GCM for authenticated encryption
//
// Security Properties:
//   - AES-256 provides strong confidentiality
//   - GCM mode provides both encryption and authentication (AEAD)
//   - Random nonce for each encryption (never reused)
//   - Protects against tampering and replay attacks
//
// Key Management:
//   - Key should be 32 bytes (256 bits) for AES-256
//   - Key should be generated from a secure source (e.g., KMS, vault)
//   - Key rotation should be implemented in production
//   - Never hardcode keys in source code
type TokenEncryption struct {
	// key is the AES-256 encryption key (32 bytes)
	key []byte

	// enabled indicates if encryption is active
	enabled bool
}

// NewTokenEncryption creates a new token encryption instance
// If key is nil or empty, encryption is disabled and tokens pass through unencrypted
func NewTokenEncryption(key []byte) (*TokenEncryption, error) {
	if len(key) == 0 {
		// Encryption disabled - tokens stored in plaintext
		return &TokenEncryption{
			key:     nil,
			enabled: false,
		}, nil
	}

	// Validate key size
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes (256 bits), got %d bytes", len(key))
	}

	return &TokenEncryption{
		key:     key,
		enabled: true,
	}, nil
}

// Encrypt encrypts data using AES-256-GCM
// Returns base64-encoded: nonce || ciphertext || tag
// If encryption is disabled, returns data unchanged
func (e *TokenEncryption) Encrypt(plaintext string) (string, error) {
	if !e.enabled {
		// Encryption disabled - return plaintext
		return plaintext, nil
	}

	if plaintext == "" {
		return "", nil
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	// Security: Nonce must be unique for each encryption with the same key
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// GCM automatically appends authentication tag to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode as base64 for storage
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Decrypt decrypts data encrypted with Encrypt
// Expects base64-encoded: nonce || ciphertext || tag
// If encryption is disabled, returns data unchanged
func (e *TokenEncryption) Decrypt(encoded string) (string, error) {
	if !e.enabled {
		// Encryption disabled - return as-is
		return encoded, nil
	}

	if encoded == "" {
		return "", nil
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce from ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateEncryptionKey generates a secure 32-byte encryption key
// This should be called once and the key stored securely (e.g., in a vault)
// DO NOT call this on every server start - the key must be persistent
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}

// EncryptionKeyFromBase64 converts a base64-encoded key to bytes
// Useful for loading keys from environment variables or config files
func EncryptionKeyFromBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil // No key - encryption disabled
	}

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d bytes", len(key))
	}

	return key, nil
}

// EncryptionKeyToBase64 converts a key to base64 for storage
func EncryptionKeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
