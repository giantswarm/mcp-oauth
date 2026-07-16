package helpers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandomHexToken returns a hex-encoded token built from nBytes of
// cryptographically secure random data (the result is 2*nBytes characters
// long). It is used for unguessable one-shot values such as per-acquisition
// lock ownership tokens, where 16 bytes (128 bits) is the conventional size.
//
// nBytes must be non-negative; a negative value returns an error rather than
// panicking.
func RandomHexToken(nBytes int) (string, error) {
	if nBytes < 0 {
		return "", fmt.Errorf("nBytes must be non-negative, got %d", nBytes)
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
