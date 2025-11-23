package oauth

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashForLogging creates a SHA256 hash of sensitive data for safe logging.
// This prevents leaking tokens, emails, or other PII in log files.
// Returns the first 16 characters of the hex-encoded hash for brevity.
// Returns an empty string for empty input.
func hashForLogging(sensitive string) string {
	if sensitive == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(sensitive))
	return hex.EncodeToString(hash[:])[:16]
}

// HashForDisplay is similar to hashForLogging but returns "<empty>" for empty strings.
// Useful for display contexts where we want to show that a field is empty vs missing.
func HashForDisplay(sensitive string) string {
	if sensitive == "" {
		return "<empty>"
	}
	return hashForLogging(sensitive)
}

// minInt returns the smaller of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
