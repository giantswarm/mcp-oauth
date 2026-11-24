package oauthconfig

import (
	"fmt"

	"github.com/giantswarm/mcp-oauth/requeststate"
	"github.com/giantswarm/mcp-oauth/security"
)

// NewRequestStateSealerFromEnv reads OAUTH_REQUEST_STATE_KEY and, during a
// rotation, OAUTH_REQUEST_STATE_PREVIOUS_KEY (each also as _FILE), 32-byte
// keys in base64 or hex, and returns a *requeststate.Sealer that seals with
// the first and opens with both. Each key's ID is [security.KeyID] of it, so
// an operator rotates by moving the current key to the previous variable.
// Returns (nil, nil) when no key is configured: a server that returns no
// requestState needs none. Each server has its own key.
func NewRequestStateSealerFromEnv() (*requeststate.Sealer, error) {
	return NewRequestStateSealerFromEnvWithPrefix("OAUTH_")
}

// NewRequestStateSealerFromEnvWithPrefix is [NewRequestStateSealerFromEnv]
// with a caller-supplied prefix. See [FromEnvWithPrefix] for the convention.
func NewRequestStateSealerFromEnvWithPrefix(prefix string) (*requeststate.Sealer, error) {
	activeName, previousName := prefix+"REQUEST_STATE_KEY", prefix+"REQUEST_STATE_PREVIOUS_KEY"
	active, err := requestStateKey(activeName)
	if err != nil || active == nil {
		return nil, err
	}
	previous, err := requestStateKey(previousName)
	if err != nil {
		return nil, err
	}
	var previousKeys []security.Key
	if previous != nil {
		if previous.ID == active.ID {
			return nil, fmt.Errorf("%s: has the same key ID as %s; generate a new key", previousName, activeName)
		}
		previousKeys = append(previousKeys, *previous)
	}
	ring, err := security.NewKeyRing(*active, previousKeys...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", activeName, err)
	}
	return requeststate.New(ring)
}

func requestStateKey(name string) (*security.Key, error) {
	raw, err := optionalSecret(name)
	if err != nil || raw == "" {
		return nil, err
	}
	secret, err := decodeSymmetricKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &security.Key{ID: security.KeyID(secret), Secret: secret}, nil
}
