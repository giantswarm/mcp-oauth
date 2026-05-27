package valkey

import (
	"context"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/server"
)

type dpopReplayCache struct {
	client    vk.Client
	keyPrefix string
}

// NewDPoPReplayCache returns a [server.DPoPReplayCache] backed by Valkey.
// keyPrefix is prepended to every JTI key; use it to namespace across
// environments or tenants (e.g. "muster:dpop:").
func NewDPoPReplayCache(client vk.Client, keyPrefix string) server.DPoPReplayCache {
	return &dpopReplayCache{client: client, keyPrefix: keyPrefix}
}

// Seen records jti with the given TTL and returns true if the JTI was already
// present. The underlying SET NX EX is atomic: no separate GET + SET race exists.
// A Valkey error is returned as-is; callers (ValidateDPoPProof) treat cache
// errors as proof rejection.
func (c *dpopReplayCache) Seen(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	seconds := max(int64(ttl.Seconds()), 1)
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
