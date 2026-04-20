// Package valkeytls builds a *tls.Config for Valkey connections from a small
// set of feature-flag-shaped options. Kept under oauthconfig/internal so the
// env-loader can compose it without exporting Valkey-specific types on any
// public API surface — consumers that want Valkey directly construct
// storage/valkey.Config themselves.
package valkeytls

import "crypto/tls"

// Options controls the TLS posture used when oauthconfig.StorageFromEnv
// constructs a Valkey client. The zero value means "no TLS".
type Options struct {
	// Enabled switches TLS on. When false the other fields are ignored and
	// New returns nil (Valkey client interprets nil as plaintext).
	Enabled bool

	// InsecureSkipVerify disables TLS certificate verification. Intended for
	// local development and self-signed test fixtures only — production
	// deployments must leave this false.
	InsecureSkipVerify bool
}

// New returns a *tls.Config for the given options, or nil when TLS is not
// enabled. Keeping the construction here means the StorageFromEnv entry point
// doesn't pull Valkey-specific TLS parsing into every caller.
func New(opts Options) *tls.Config {
	if !opts.Enabled {
		return nil
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify, // #nosec G402 -- operator opt-in, documented
	}
}
