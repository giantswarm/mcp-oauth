package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
)

// Key is one AES-256 secret and the kid stamped into what it seals.
type Key struct {
	ID     byte
	Secret []byte
}

// KeyID returns a kid computed from secret: the first byte of its SHA-256
// digest. An operator then rotates by moving the current secret to the
// previous slot, without naming IDs. Two secrets share a kid with probability
// 1/256; [NewKeyRing] refuses such a pair.
func KeyID(secret []byte) byte {
	digest := sha256.Sum256(secret)
	return digest[0]
}

// NewKeyRing returns a [KeyRing] whose active kid is active.ID and which
// resolves active and every previous key, so values sealed before a rotation
// still open. Every secret must be 32 bytes and pass [ValidateKeyEntropy];
// IDs must be distinct.
func NewKeyRing(active Key, previous ...Key) (KeyRing, error) {
	ring := &staticKeyRing{active: active.ID, aeads: make(map[byte]cipher.AEAD, 1+len(previous))}
	for _, key := range append([]Key{active}, previous...) {
		if _, dup := ring.aeads[key.ID]; dup {
			return nil, fmt.Errorf("key ID %d given twice", key.ID)
		}
		if len(key.Secret) != 32 {
			return nil, fmt.Errorf("key %d must be 32 bytes for AES-256, got %d", key.ID, len(key.Secret))
		}
		if err := ValidateKeyEntropy(key.Secret); err != nil {
			return nil, fmt.Errorf("key %d: %w", key.ID, err)
		}
		block, err := aes.NewCipher(key.Secret)
		if err != nil {
			return nil, fmt.Errorf("key %d: failed to create cipher: %w", key.ID, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("key %d: failed to create GCM: %w", key.ID, err)
		}
		ring.aeads[key.ID] = aead
	}
	return ring, nil
}

// staticKeyRing is a [KeyRing] over keys fixed at construction; it is
// read-only after NewKeyRing and so safe for concurrent use.
type staticKeyRing struct {
	active byte
	aeads  map[byte]cipher.AEAD
}

func (r *staticKeyRing) ActiveKID() byte { return r.active }

func (r *staticKeyRing) AEAD(kid byte) (cipher.AEAD, error) {
	aead, ok := r.aeads[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key id %d", kid)
	}
	return aead, nil
}
