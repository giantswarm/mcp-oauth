package valkey

import (
	"context"
	"fmt"
	"time"
)

// revokedJTIKey identifies a denylist entry by its jti.
func (s *Store) revokedJTIKey(jti string) string {
	return fmt.Sprintf("%srevoked:%s", s.prefix, jti)
}

// RevokeJTI retains a denylist entry through expiresAt, including the caller's clock-skew allowance.
func (s *Store) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) (err error) {
	if jti == "" {
		return fmt.Errorf("jti cannot be empty")
	}

	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return nil
	}

	op := s.startTracedOp(ctx, "revoke_jti")
	defer op.end(&err)

	key := s.revokedJTIKey(jti)
	cmd := s.client.B().Set().Key(key).Value("1").ExSeconds(ceilSeconds(ttl)).Build()
	if err = s.client.Do(op.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("revoke jti: %w", err)
	}
	return nil
}

// IsJTIRevoked implements storage.RevokedTokenStore via an EXISTS lookup.
// EXISTS returns 0 for the no-revocation case (including expired entries
// already evicted by Valkey TTL), so a missing key is safely interpreted
// as "not revoked".
func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (revoked bool, err error) {
	if jti == "" {
		return false, nil
	}

	op := s.startTracedOp(ctx, "is_jti_revoked")
	defer op.end(&err)

	key := s.revokedJTIKey(jti)
	cmd := s.client.B().Exists().Key(key).Build()
	count, err := s.client.Do(op.ctx, cmd).AsInt64()
	if err != nil {
		return false, fmt.Errorf("check revoked jti: %w", err)
	}
	return count > 0, nil
}
