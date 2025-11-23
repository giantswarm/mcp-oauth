package security

import "time"

const (
	// DefaultClockSkewGracePeriod is the default grace period for token expiration checks
	// This prevents false expiration errors due to time synchronization issues
	// between different systems (client, server, provider).
	//
	// Security Rationale:
	//   - Prevents false expiration errors due to minor time differences
	//   - Balances security (minimize token lifetime extension) with usability
	//   - 5 seconds is a conservative value that handles typical NTP drift
	//
	// Trade-offs:
	//   - Allows tokens to be used up to 5 seconds beyond their true expiration
	//   - This is acceptable for most use cases and improves reliability
	//   - For high-security scenarios, this can be reduced or disabled
	DefaultClockSkewGracePeriod = 5 * time.Second
)

// IsTokenExpired checks if a token is expired with default clock skew grace period
func IsTokenExpired(expiresAt time.Time) bool {
	return IsTokenExpiredWithGracePeriod(expiresAt, DefaultClockSkewGracePeriod)
}

// IsTokenExpiredWithGracePeriod checks if a token is expired with custom clock skew grace period
func IsTokenExpiredWithGracePeriod(expiresAt time.Time, gracePeriod time.Duration) bool {
	if expiresAt.IsZero() {
		return false // No expiration
	}

	// Apply grace period: token is only expired if it's been expired for more than grace period
	return time.Now().After(expiresAt.Add(gracePeriod))
}

// IsTokenExpiringSoon checks if a token will expire within the given threshold
func IsTokenExpiringSoon(expiresAt time.Time, threshold time.Duration) bool {
	if expiresAt.IsZero() {
		return false
	}

	return time.Now().Add(threshold).After(expiresAt)
}
