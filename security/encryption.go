package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// MinKeyDistinctBytes is the minimum number of distinct byte values an
// AES-256 key must contain. 16 bounds the effective keyspace from a key
// drawn over this many symbols at ≥ 2^128 (the NIST minimum for AES). A
// uniformly random 32-byte key averages ~30 distinct bytes (σ ≈ 1.5), so
// the false-positive rate on genuine keys is negligible.
const MinKeyDistinctBytes = 16

// ValidateKeyEntropy returns an error when key is too predictable to be
// safe as an AES-256 key. Empty input is accepted (caller has opted out of
// encryption entirely — see NewEncryptor).
//
// Defense in depth: callers using GenerateKey never trip this, but
// operators who paste a placeholder (`000…000`, `0xff…`, `aaaa…`,
// `0xAB 0xCD` repeated) into a secret manager still pass length checks
// and would otherwise encrypt all tokens under a trivially-known key.
//
// This check cannot detect every weak key — e.g. SHA-256 of a dictionary
// word produces a high-distinct-byte output that still trivially leaks.
// Operators must generate keys via crypto/rand (GenerateKey) or
// `openssl rand`; this gate is only a backstop against obvious mistakes.
func ValidateKeyEntropy(key []byte) error {
	if len(key) == 0 {
		return nil
	}
	if n := distinctBytes(key); n < MinKeyDistinctBytes {
		return fmt.Errorf("encryption key has only %d distinct byte values (want >= %d) — check that the key is not all zeros, a repeated byte, or a placeholder; generate with crypto/rand or `openssl rand -hex 32`", n, MinKeyDistinctBytes)
	}
	return nil
}

func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// Encryptor handles token encryption at rest using AES-256-GCM.
type Encryptor struct {
	key     []byte
	enabled bool
}

// NewEncryptor creates a new encryptor.
// If key is nil or empty, encryption is disabled.
// The key must be exactly 32 bytes for AES-256 and must pass
// ValidateKeyEntropy — a low-entropy key is rejected rather than silently
// encrypting all tokens under a trivially-known secret.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) == 0 {
		return &Encryptor{enabled: false}, nil
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes for AES-256, got %d", len(key))
	}
	if err := ValidateKeyEntropy(key); err != nil {
		return nil, err
	}

	return &Encryptor{
		key:     key,
		enabled: true,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext.
func (e *Encryptor) Encrypt(plaintext string) (out string, err error) {
	if !e.enabled {
		return plaintext, nil
	}
	start := time.Now()
	defer func() { recordEncryption("encrypt", err, start) }()

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Prepend nonce to ciphertext for storage
	// Format: [nonce][ciphertext]
	nonce = append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(nonce), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM.
func (e *Encryptor) Decrypt(encoded string) (out string, err error) {
	if !e.enabled {
		return encoded, nil
	}
	start := time.Now()
	defer func() { recordEncryption("decrypt", err, start) }()

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// IsEnabled returns true if encryption is enabled
func (e *Encryptor) IsEnabled() bool {
	return e.enabled
}

// GenerateKey generates a new 32-byte encryption key for AES-256
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// KeyFromBase64 decodes a base64-encoded encryption key
func KeyFromBase64(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// KeyToBase64 encodes an encryption key to base64
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyFromHex decodes a hex-encoded 32-byte encryption key. 64-char input is
// the canonical form produced by `openssl rand -hex 32`. Paired with
// KeyFromBase64 for operators who prefer one encoding over the other.
func KeyFromHex(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// KeyToHex encodes an encryption key to lowercase hex.
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}
