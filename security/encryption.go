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

// ValidateKeyEntropy rejects obvious placeholder keys (all-zero, repeated
// bytes, low-distinct-symbol patterns) that pass length checks but leave
// encrypted tokens trivially recoverable. Empty input is accepted — the
// caller has opted out of encryption entirely (see NewEncryptor).
//
// This is a backstop against operator mistakes only. It cannot detect
// derived-but-weak keys (e.g. SHA-256 of a dictionary word averages ~27
// distinct bytes). Generate real keys via [GenerateKey] or
// `openssl rand -hex 32`.
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

// Ciphertext envelope versions.
//
//	v0: base64( nonce || ciphertext )                 — produced by previous releases.
//	v1: base64( 0x01 || kid || nonce || ciphertext )  — produced by this and later releases.
//
// Decrypt accepts both. v0 rows remain readable so a rolling upgrade across
// a multi-replica deployment does not require operator action; v0 rows
// decay naturally as tokens expire and rotate.
const (
	envelopeV1Tag byte = 0x01
)

// KeyRing resolves AES-256 keys keyed by a 1-byte `kid`. `ActiveKID` returns
// the id stamped into every new ciphertext; `AEAD(kid)` resolves any
// historical id present in stored rows. The built-in [NewEncryptor] wires a
// [singleKeyRing] with kid = 0 because in-tree consumers need exactly one
// key today.
//
// Multi-key consumers (external KMS, scheduled rotation, dual-write windows)
// supply their own implementation. Notes for those implementations:
//
//   - `ActiveKID` is invoked on every Encrypt; implementations that want
//     to change the active id at runtime MUST make this call goroutine-safe.
//     The built-in `singleKeyRing` returns a constant and is trivially safe.
//   - The Encryptor does not yet expose which kid authenticated a given
//     decrypted row, so re-encrypt-on-read rotation is not implementable
//     against today's [Encryptor.Decrypt]. Tracked in #335.
type KeyRing interface {
	// ActiveKID returns the kid byte stamped into newly-emitted ciphertexts.
	ActiveKID() byte

	// AEAD returns the AEAD primitive bound to the given kid. The returned
	// AEAD's NonceSize() and Overhead() must be stable across calls.
	AEAD(kid byte) (cipher.AEAD, error)
}

// singleKeyRing implements [KeyRing] with one key, kid = 0. The built-in
// behind [NewEncryptor]; consumers needing rotation provide their own.
type singleKeyRing struct {
	aead cipher.AEAD
}

func newSingleKeyRing(key []byte) (*singleKeyRing, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &singleKeyRing{aead: aead}, nil
}

func (r *singleKeyRing) ActiveKID() byte { return 0 }

func (r *singleKeyRing) AEAD(kid byte) (cipher.AEAD, error) {
	if kid != 0 {
		return nil, fmt.Errorf("unknown key id %d", kid)
	}
	return r.aead, nil
}

// Encryptor handles token encryption at rest using AES-256-GCM. Emits v1
// envelopes; decrypts v0 (legacy) and v1.
type Encryptor struct {
	ring    KeyRing
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

	ring, err := newSingleKeyRing(key)
	if err != nil {
		return nil, err
	}
	return &Encryptor{ring: ring, enabled: true}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM. The output is a base64-encoded
// v1 envelope: 0x01 || kid || nonce || ciphertext.
func (e *Encryptor) Encrypt(plaintext string) (out string, err error) {
	if !e.enabled {
		return plaintext, nil
	}
	start := time.Now()
	defer func() { recordEncryption("encrypt", err, start) }()

	kid := e.ring.ActiveKID()
	aead, err := e.ring.AEAD(kid)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// envelope: 0x01 || kid || nonce || ct
	envelope := make([]byte, 0, 2+aead.NonceSize()+len(plaintext)+aead.Overhead())
	envelope = append(envelope, envelopeV1Tag, kid)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(envelope), nil
}

// Decrypt decrypts a base64-encoded envelope. Accepts both v1
// (0x01 || kid || nonce || ct) and legacy v0 (nonce || ct).
func (e *Encryptor) Decrypt(encoded string) (out string, err error) {
	if !e.enabled {
		return encoded, nil
	}
	start := time.Now()
	defer func() { recordEncryption("decrypt", err, start) }()

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	aead, err := e.ring.AEAD(e.ring.ActiveKID())
	if err != nil {
		return "", err
	}
	nonceSize := aead.NonceSize()

	// v1 envelope is identified by a leading 0x01 byte. The tag alone is
	// ambiguous: any v0 ciphertext whose first nonce byte happens to be
	// 0x01 (~1/256 of legacy rows) looks structurally identical. Treat
	// AEAD verification as the disambiguator — on v1 Open failure fall
	// through to v0 instead of returning an error. The cost is one extra
	// AEAD Open on the colliding fraction; the alternative would silently
	// break ~0.4% of legacy ciphertexts on first decrypt after upgrade.
	if len(raw) >= 2+nonceSize+aead.Overhead() && raw[0] == envelopeV1Tag {
		kid := raw[1]
		if kidAEAD, kidErr := e.ring.AEAD(kid); kidErr == nil {
			nonce := raw[2 : 2+nonceSize]
			ct := raw[2+nonceSize:]
			if pt, openErr := kidAEAD.Open(nil, nonce, ct, nil); openErr == nil {
				return string(pt), nil
			}
		}
		// fall through to v0 — leading 0x01 collided with a v0 nonce byte.
	}

	// v0 fallback for ciphertexts written by previous releases.
	if len(raw) < nonceSize+aead.Overhead() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(pt), nil
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

// DecodeKey decodes an AES-256 token-encryption key from either base64
// (what `openssl rand -base64 32` produces) or hex (`openssl rand -hex 32`).
// Detection tries base64 first and falls back to hex. The returned key
// is guaranteed to be 32 bytes.
//
// DecodeKey is a convenience over [KeyFromBase64] and [KeyFromHex] for
// operators who configure the same secret across tools that emit different
// encodings.
func DecodeKey(s string) ([]byte, error) {
	if key, err := KeyFromBase64(s); err == nil {
		return key, nil
	}
	key, err := KeyFromHex(s)
	if err != nil {
		return nil, fmt.Errorf("encryption key is neither valid base64 nor hex: %w", err)
	}
	return key, nil
}
