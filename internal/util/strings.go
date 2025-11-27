// Package util provides common utility functions used across the mcp-oauth library.
// These utilities handle string manipulation, formatting, and other shared operations
// that don't fit into domain-specific packages.
package util

import "strings"

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

// NormalizeURL normalizes a URL for comparison by removing trailing slashes.
// This is used for RFC 8707 resource identifier and audience comparison,
// where URLs with and without trailing slashes should be considered equivalent.
//
// Example:
//
//	NormalizeURL("https://example.com/")   // Returns: "https://example.com"
//	NormalizeURL("https://example.com")    // Returns: "https://example.com"
//	NormalizeURL("https://example.com///") // Returns: "https://example.com"
func NormalizeURL(url string) string {
	return strings.TrimRight(url, "/")
}
