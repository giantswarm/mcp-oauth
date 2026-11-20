package valkey

import (
	vk "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/server"
)

// NewClientAssertionReplayStore returns a shared replay store isolated by keyPrefix.
func NewClientAssertionReplayStore(client vk.Client, keyPrefix string) server.ClientAssertionReplayStore {
	return NewDPoPReplayCache(client, keyPrefix)
}
