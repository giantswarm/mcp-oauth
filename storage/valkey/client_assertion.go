package valkey

import (
	"context"
	"math"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/server"
)

type clientAssertionReplayStore struct {
	client    vk.Client
	keyPrefix string
}

// NewClientAssertionReplayStore returns a [server.ClientAssertionReplayStore] backed by Valkey.
// keyPrefix is prepended to every JTI key; use it to namespace across
// environments or tenants (e.g. "muster:client-assertion:").
func NewClientAssertionReplayStore(client vk.Client, keyPrefix string) server.ClientAssertionReplayStore {
	return &clientAssertionReplayStore{client: client, keyPrefix: keyPrefix}
}

// Seen records jti with the given TTL and returns true if the JTI was already
// present. The underlying SET NX EX is atomic: no separate GET + SET race exists.
// A Valkey error is returned as-is; callers (ValidateClientAssertion) treat cache
// errors as proof rejection.
func (c *clientAssertionReplayStore) Seen(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	seconds := max(int64(math.Ceil(ttl.Seconds())), 1)
	err := c.client.Do(
		ctx,
		c.client.B().Set().Key(c.keyPrefix+jti).Value("1").Nx().ExSeconds(seconds).Build(),
	).Error()
	if err == nil {
		return false, nil
	}
	if vk.IsValkeyNil(err) {
		return true, nil
	}
	return false, err
}
