package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// ErrDPoPNonceInvalid is returned by ValidateDPoPProof when the server requires
// a nonce and the proof's nonce claim is absent or does not match a currently
// accepted value (RFC 9449 §8). Callers must respond with
// error=use_dpop_nonce and a DPoP-Nonce response header carrying a fresh nonce.
var ErrDPoPNonceInvalid = errors.New("dpop: nonce required or stale")

// DPoPNonceProvider generates and validates server-issued DPoP nonces (RFC 9449 §8).
// Implementations must be safe for concurrent use.
//
// Set a provider via [WithDPoPNonceProvider]. When nil, [ValidateDPoPProof]
// accepts proofs that omit the nonce claim entirely.
type DPoPNonceProvider interface {
	// Nonce returns the current server-issued nonce value to include in a
	// DPoP-Nonce response header. Callers return this value to the client
	// whenever a use_dpop_nonce error is issued.
	Nonce(ctx context.Context) string

	// Valid reports whether nonce is currently accepted. Implementations SHOULD
	// accept at least the current and one previous time window so that clients
	// transitioning at a window boundary are not spuriously rejected.
	Valid(ctx context.Context, nonce string) bool
}

// hmacNonceProvider issues and validates HMAC-SHA256 nonces bound to fixed
// time windows. Nonces for the current and the immediately preceding window
// are both accepted so clients are never rejected at a boundary transition.
type hmacNonceProvider struct {
	secret []byte
	window time.Duration
	now    func() time.Time
}

// NewHMACNonceProvider returns a [DPoPNonceProvider] that derives nonces with
// HMAC-SHA256 keyed on secret and rotated every window. Callers that do not
// need a testable clock should pass nil for now (time.Now is used).
//
// A window of 10 minutes is a reasonable default: short enough to limit the
// replay exposure on a stolen nonce, long enough to tolerate mobile clients
// with slow network round-trips.
func NewHMACNonceProvider(secret []byte, window time.Duration, now func() time.Time) DPoPNonceProvider {
	if now == nil {
		now = time.Now
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &hmacNonceProvider{secret: secret, window: window, now: now}
}

func (p *hmacNonceProvider) Nonce(_ context.Context) string {
	return p.nonceForBucket(p.bucket(p.now()))
}

func (p *hmacNonceProvider) Valid(_ context.Context, nonce string) bool {
	t := p.now()
	cur := p.bucket(t)
	return nonce == p.nonceForBucket(cur) || nonce == p.nonceForBucket(cur-1)
}

func (p *hmacNonceProvider) bucket(t time.Time) int64 {
	secs := int64(p.window.Seconds())
	if secs < 1 {
		secs = 1
	}
	return t.Unix() / secs
}

func (p *hmacNonceProvider) nonceForBucket(bucket int64) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = fmt.Fprintf(mac, "dpop-nonce:%d", bucket)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
