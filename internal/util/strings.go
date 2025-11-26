// Package util provides common utility functions used across the mcp-oauth library.
// These utilities handle string manipulation, formatting, and other shared operations
// that don't fit into domain-specific packages.
package util

// SafeTruncate safely truncates a string to maxLen characters without panicking.
// Returns the original string if it's shorter than maxLen, otherwise returns
// the first maxLen characters. This prevents index out of bounds errors when
// logging sensitive data like tokens, where only a prefix should be shown.
//
// If maxLen is negative, it's treated as 0 and returns an empty string.
//
// Example:
//
//	SafeTruncate("very-long-token-abc123", 8) // Returns: "very-lon"
//	SafeTruncate("short", 10)                  // Returns: "short"
//	SafeTruncate("test", -1)                   // Returns: ""
func SafeTruncate(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
