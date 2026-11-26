// Package requeststate seals the requestState an MCP server returns in an
// InputRequiredResult and the client echoes back on its retry (MCP
// 2026-07-28, multi round-trip requests).
//
// MCP treats an echoed requestState as attacker-controlled input: the server
// must protect its integrity and should bind it to the authenticated
// principal, a short expiry and the originating request. A server must also
// bind an elicitation to the client and user identity. A sealed value is
// encrypted and authenticated with AES-256-GCM under a [security.KeyRing],
// and bound to:
//
//   - the user and OAuth client of the validated token: the Issuer, ID and
//     ClientID of its [providers.UserInfo], and its current actor
//     (ActorIssuer, ActorSubject) when the token is delegated;
//   - the originating request, such as the method, the tool name and a
//     digest of its arguments;
//   - an expiry.
//
// Seal and Open return [ErrIncompleteIdentity] for a missing user, issuer or
// subject, and [ErrMissingClientID] for a user without a ClientID. These are
// local validation errors, not OAuth error codes. Both mean the caller cannot
// be bound to, so the request fails: a server does not answer such a caller
// without requestState instead.
//
// Open refuses a value that was changed, sealed for another user, client,
// actor or request, expired, or sealed with a key the ring does not hold.
// A value can be opened more than once until it expires; a server whose
// state must be consumed at most once records that itself.
//
// Each server seals with its own key ring, and a value is only ever opened
// by the server that sealed it.
package requeststate

import (
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

	// MaxSealedLength bounds what Open decodes, so a client cannot make the
	// server decode an arbitrarily large value.
	MaxSealedLength = 16 << 10
)

var (
	// ErrInvalid is a value that is malformed, was changed, or was sealed
	// for another user, client, actor or request or with a key the ring
	// does not hold.
	ErrInvalid = errors.New("requeststate: invalid state")
	// ErrExpired is an authentic value past its expiry.
	ErrExpired = errors.New("requeststate: expired state")
	// ErrIncompleteIdentity means the validated user is absent or lacks an
	// Issuer or ID. Client identity is checked separately.
	ErrIncompleteIdentity = errors.New("requeststate: a validated user with Issuer and ID is required")
	// ErrMissingClientID means the user has an Issuer and ID but no ClientID.
	ErrMissingClientID = errors.New("requeststate: the validated user's ClientID is required")
)

// Sealer seals with its ring's active key and opens with any key the ring
// resolves.
type Sealer struct {
	ring security.KeyRing
}

// New returns a Sealer over ring. ring must resolve its active key.
func New(ring security.KeyRing) (*Sealer, error) {
	if ring == nil {
		return nil, errors.New("requeststate: a key ring is required")
	}
	if _, err := ring.AEAD(ring.ActiveKID()); err != nil {
		return nil, fmt.Errorf("requeststate: active key: %w", err)
	}
	return &Sealer{ring: ring}, nil
}

// Seal returns payload sealed for user and request, valid for ttl. user is
// the validated caller; request identifies the originating request. Open
// must be given the same user and request. Missing identity fields return
// ErrIncompleteIdentity or ErrMissingClientID.
func (s *Sealer) Seal(user *providers.UserInfo, request string, payload []byte, ttl time.Duration) (string, error) {
	if err := checkBinding(user, request); err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", errors.New("requeststate: ttl must be positive")
	}
	kid := s.ring.ActiveKID()
	aead, err := s.ring.AEAD(kid)
	if err != nil {
		return "", fmt.Errorf("requeststate: active key: %w", err)
	}
	header := []byte{formatVersion, kid}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("requeststate: nonce: %w", err)
	}
	plaintext := binary.AppendVarint(nil, time.Now().Add(ttl).Unix())
	plaintext = append(plaintext, payload...)
	out := append(header, nonce...)
	out = aead.Seal(out, nonce, plaintext, additionalData(header, user, request))
	sealed := base64.RawURLEncoding.EncodeToString(out)
	if len(sealed) > MaxSealedLength {
		return "", fmt.Errorf("requeststate: sealed state is %d bytes, over %d", len(sealed), MaxSealedLength)
	}
	return sealed, nil
}

// Open returns the payload of a value Seal returned for the same user and
// request. Missing identity fields return ErrIncompleteIdentity or
// ErrMissingClientID. A value that fails verification returns ErrInvalid;
// an authentic value past its expiry returns ErrExpired.
func (s *Sealer) Open(user *providers.UserInfo, request, sealed string) ([]byte, error) {
	if err := checkBinding(user, request); err != nil {
		return nil, err
	}
	if len(sealed) > MaxSealedLength {
		return nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < headerSize || raw[0] != formatVersion {
		return nil, ErrInvalid
	}
	aead, err := s.ring.AEAD(raw[1])
	if err != nil {
		return nil, ErrInvalid
	}
	nonceEnd := headerSize + aead.NonceSize()
	if len(raw) < nonceEnd {
		return nil, ErrInvalid
	}
	header, nonce, ciphertext := raw[:headerSize], raw[headerSize:nonceEnd], raw[nonceEnd:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData(header, user, request))
	if err != nil {
		return nil, ErrInvalid
	}
	expiry, n := binary.Varint(plaintext)
	if n <= 0 {
		return nil, ErrInvalid
	}
	if !time.Now().Before(time.Unix(expiry, 0)) {
		return nil, ErrExpired
	}
	return plaintext[n:], nil
}

func checkBinding(user *providers.UserInfo, request string) error {
	if user == nil || user.Issuer == "" || user.ID == "" {
		return ErrIncompleteIdentity
	}
	if request == "" {
		return errors.New("requeststate: the originating request is required")
	}
	if user.ClientID == "" {
		return ErrMissingClientID
	}
	return nil
}

// additionalData authenticates the header, the user, client and actor, and
// the request with the ciphertext. Each field is length-prefixed so no two
// bindings encode alike.
func additionalData(header []byte, user *providers.UserInfo, request string) []byte {
	ad := append([]byte{}, header...)
	for _, field := range []string{user.Issuer, user.ID, user.ClientID, user.ActorIssuer, user.ActorSubject, request} {
		ad = binary.AppendUvarint(ad, uint64(len(field)))
		ad = append(ad, field...)
	}
	return ad
}
