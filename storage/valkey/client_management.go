package valkey

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/giantswarm/mcp-oauth/storage"
)

// UpdateClientRegistration atomically replaces the authenticated registration.
func (s *Store) UpdateClientRegistration(ctx context.Context, client *storage.Client, registrationTokenHash, clientSecretHash string) (err error) {
	op := s.startTracedOp(ctx, "update_client_registration")
	defer op.end(&err)
	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client")
	}
	data, err := json.Marshal(toClientJSON(client))
	if err != nil {
		return fmt.Errorf("marshal client registration: %w", err)
	}
	result, err := s.client.Do(op.ctx, s.client.B().Eval().Script(`
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
local current = cjson.decode(value)
if current.revoked or (current.registration_access_token_hash or '') ~= ARGV[2]
  or (current.client_secret_hash or '') ~= ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1])
return 1
`).Numkeys(1).Key(s.clientKey(client.ClientID)).Arg(string(data), registrationTokenHash, clientSecretHash).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("update client registration: %w", err)
	}
	if result != 1 {
		return storage.ErrInvalidClientCredentials
	}
	return nil
}
