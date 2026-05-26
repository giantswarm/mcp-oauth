// Package valkey provides a Valkey-backed DPoPReplayCache for multi-instance deployments.
// It implements [server.DPoPReplayCache] using an atomic SET NX EX operation so
// proof JTI uniqueness is enforced across all server replicas sharing the same
// Valkey instance.
package valkey

import (
	"context"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/server"
)

type replayCache struct {
	client    vk.Client
	keyPrefix string
}

// New returns a [server.DPoPReplayCache] backed by Valkey.
// keyPrefix is prepended to every JTI key; use it to namespace across
// environments or tenants (e.g. "muster:dpop:").
func New(client vk.Client, keyPrefix string) server.DPoPReplayCache {
	return &replayCache{client: client, keyPrefix: keyPrefix}
}

// Seen records jti with the given TTL and returns true if the JTI was already
// present. The underlying SET NX EX is atomic: no separate GET + SET race exists.
// A Valkey error is returned as-is; callers (ValidateDPoPProof) treat cache
// errors as proof rejection.
func (c *replayCache) Seen(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	seconds := int64(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	err := c.client.Do(
		ctx,
		c.client.B().Set().Key(c.keyPrefix+jti).Value("1").Nx().ExSeconds(seconds).Build(),
	).Error()
	if err == nil {
		return false, nil // key was just set — JTI is new
	}
	if vk.IsValkeyNil(err) {
		return true, nil // SET NX returned nil — key already existed, proof replayed
	}
	return false, err
}
