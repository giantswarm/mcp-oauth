package valkey

import (
	"context"
	"encoding/json"
	"fmt"
)

func (s *Store) IsClientRevoked(ctx context.Context, clientID string) (bool, error) {
	data, err := s.client.Do(ctx, s.client.B().Get().Key(s.clientKey(clientID)).Build()).ToString()
	if isNilError(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read client revocation: %w", err)
	}
	var client clientJSON
	if err := json.Unmarshal([]byte(data), &client); err != nil {
		return false, fmt.Errorf("decode client revocation: %w", err)
	}
	return client.Revoked, nil
}
