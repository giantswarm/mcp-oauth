// Package requeststate seals the state an MCP server hands a client to echo
// back: the requestState of an InputRequiredResult (MCP 2026-07-28) and the
// elicitationId of a URL mode elicitation (MCP 2025-11-25).
//
// The client controls what it echoes, and MCP requires a server to bind an
// elicitation to the user who started it. A sealed value is encrypted and
// authenticated with AES-256-GCM. The user's issuer and subject, the call it
// was issued for and the key ID are authenticated with it, and it carries an
// expiry. Open refuses a value that was changed, issued for another user or
// another call, expired, or sealed with a key the [Sealer] does not hold.
//
// Each server seals with its own key. A value is only ever opened by the
// server that sealed it.
package requeststate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
)

const formatVersion byte = 1

const (
	headerSize = 2 // format version, key ID
	nonceSize  = 12

	// MaxSealedLength bounds what Open decodes, so a client cannot make the
	// server decode an arbitrarily large value.
	MaxSealedLength = 16 << 10
)

var (
	// ErrInvalid is a value that is malformed, was changed, or was sealed
	// for another user or call or with a key this Sealer does not hold.
	ErrInvalid = errors.New("requeststate: invalid state")
	// ErrExpired is an authentic value past its expiry.
	ErrExpired = errors.New("requeststate: expired state")
)

// Key is one AES-256 key and the ID stamped into the values it seals.
type Key struct {
	ID     byte
	Secret []byte
}

// Sealer seals with its active key and opens with any key it holds.
type Sealer struct {
	active byte
	keys   map[byte]cipher.AEAD
	now    func() time.Time
}

// New returns a Sealer that seals with active and opens values sealed with
// active or any of previous, so a key can be rotated without refusing values
// already handed out. Every secret must be 32 bytes and pass
// [security.ValidateKeyEntropy]; key IDs must be distinct.
func New(active Key, previous ...Key) (*Sealer, error) {
	s := &Sealer{active: active.ID, keys: map[byte]cipher.AEAD{}, now: time.Now}
	for _, k := range append([]Key{active}, previous...) {
		if _, dup := s.keys[k.ID]; dup {
			return nil, fmt.Errorf("requeststate: key ID %d given twice", k.ID)
		}
		if len(k.Secret) != 32 {
			return nil, fmt.Errorf("requeststate: key %d must be 32 bytes, got %d", k.ID, len(k.Secret))
		}
		if err := security.ValidateKeyEntropy(k.Secret); err != nil {
			return nil, fmt.Errorf("requeststate: key %d: %w", k.ID, err)
		}
		block, err := aes.NewCipher(k.Secret)
		if err != nil {
			return nil, fmt.Errorf("requeststate: key %d: %w", k.ID, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("requeststate: key %d: %w", k.ID, err)
		}
		s.keys[k.ID] = aead
	}
	return s, nil
}

// Seal returns payload sealed for user and call, valid for ttl. call names
// what the value may be echoed to, such as the tool name and a digest of its
// arguments; Open must be given the same. user must be the validated caller,
// with Issuer and ID set.
func (s *Sealer) Seal(user *providers.UserInfo, call string, payload []byte, ttl time.Duration) (string, error) {
	if err := checkUser(user); err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", errors.New("requeststate: ttl must be positive")
	}
	header := []byte{formatVersion, s.active}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("requeststate: nonce: %w", err)
	}
	plaintext := binary.AppendVarint(nil, s.now().Add(ttl).Unix())
	plaintext = append(plaintext, payload...)
	out := append(header, nonce...)
	out = s.keys[s.active].Seal(out, nonce, plaintext, additionalData(header, user, call))
	sealed := base64.RawURLEncoding.EncodeToString(out)
	if len(sealed) > MaxSealedLength {
		return "", fmt.Errorf("requeststate: sealed state is %d bytes, over %d", len(sealed), MaxSealedLength)
	}
	return sealed, nil
}

// Open returns the payload of a value Seal returned for the same user and
// call. It answers ErrInvalid or ErrExpired otherwise.
func (s *Sealer) Open(user *providers.UserInfo, call, sealed string) ([]byte, error) {
	if err := checkUser(user); err != nil {
		return nil, err
	}
	if len(sealed) > MaxSealedLength {
		return nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < headerSize+nonceSize || raw[0] != formatVersion {
		return nil, ErrInvalid
	}
	aead, ok := s.keys[raw[1]]
	if !ok {
		return nil, ErrInvalid
	}
	header, nonce, ciphertext := raw[:headerSize], raw[headerSize:headerSize+nonceSize], raw[headerSize+nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData(header, user, call))
	if err != nil {
		return nil, ErrInvalid
	}
	expiry, n := binary.Varint(plaintext)
	if n <= 0 {
		return nil, ErrInvalid
	}
	if !s.now().Before(time.Unix(expiry, 0)) {
		return nil, ErrExpired
	}
	return plaintext[n:], nil
}

func checkUser(user *providers.UserInfo) error {
	if user == nil || user.Issuer == "" || user.ID == "" {
		return errors.New("requeststate: a validated user with issuer and subject is required")
	}
	return nil
}

// additionalData authenticates the header, the user and the call with the
// ciphertext. Each field is length-prefixed so no two inputs encode alike.
func additionalData(header []byte, user *providers.UserInfo, call string) []byte {
	ad := append([]byte{}, header...)
	for _, field := range []string{user.Issuer, user.ID, call} {
		ad = binary.AppendUvarint(ad, uint64(len(field)))
		ad = append(ad, field...)
	}
	return ad
}
