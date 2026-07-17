package valkey

import (
	"context"
	"fmt"
	"time"
)

// revokedJTIKey returns the key under which a revoked jti is recorded:
// {prefix}revoked:{jti}. Auto-expires at the JWT's original exp time so
// the denylist stays bounded.
func (s *Store) revokedJTIKey(jti string) string {
	return fmt.Sprintf("%srevoked:%s", s.prefix, jti)
}

// RevokeJTI implements storage.RevokedTokenStore by writing a sentinel
// value at revokedJTIKey(jti) with a relative TTL derived from the JWT's
// expiresAt via calculateTTL (clamped to a >=1s floor), so the entry
// auto-expires at/just after the JWT's own exp. The value is intentionally
// minimal — presence is the signal; the JWT itself already carries every
// other claim. RFC 7009 treats revocation of an already-expired token as a
// no-op, so we drop those without a round-trip.
func (s *Store) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) (err error) {
	if jti == "" {
		return fmt.Errorf("jti cannot be empty")
	}
	if !expiresAt.After(time.Now()) {
		return nil
	}

	op := s.startTracedOp(ctx, "revoke_jti")
	defer op.end(&err)

	// calculateTTL clamps a positive sub-second TTL up to a 1s floor;
	// without it a JWT revoked in its final second before exp would build
	// "EX 0" (valkey-go's Ex() truncates to whole seconds) and Valkey would
	// reject the write, silently failing to denylist the JTI.
	ttl := calculateTTL(expiresAt)
	if ttl <= 0 {
		return nil
	}

	key := s.revokedJTIKey(jti)
	cmd := s.client.B().Set().Key(key).Value("1").Ex(ttl).Build()
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
