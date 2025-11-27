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

// MaxMetadataPathLength is the maximum allowed length for custom metadata paths.
// This prevents DoS attacks through excessively long path registration.
const MaxMetadataPathLength = 256

// MaxPathSegments is the maximum number of path segments (slashes) allowed.
// This prevents DoS attacks through deeply nested paths.
const MaxPathSegments = 10

// ValidateMetadataPath validates a metadata path for security concerns.
// This is used by both the HTTP handler (for runtime requests) and config
// validation (for startup configuration).
//
// Security checks performed:
//   - Path traversal sequences (..)
//   - Null bytes (can cause issues in some HTTP implementations)
//   - Excessive path length (DoS prevention)
//   - Excessive path segments (DoS prevention)
//
// Returns nil if the path is valid, otherwise returns an error describing the issue.
func ValidateMetadataPath(path string) error {
	// SECURITY: Reject paths containing path traversal sequences
	// Defense in depth: path.Clean() would normalize these, but explicit check prevents confusion
	if strings.Contains(path, "..") {
		return &PathValidationError{
			Path:   path,
			Reason: "path contains '..' sequence (path traversal attempt)",
		}
	}

	// SECURITY: Prevent DoS through excessively long paths
	// Long paths consume memory and can cause issues with storage, logging, and HTTP headers
	if len(path) > MaxMetadataPathLength {
		return &PathValidationError{
			Path:   path,
			Reason: "path exceeds maximum length (DoS prevention)",
		}
	}

	// SECURITY: Reject paths with suspicious patterns
	// Null bytes can cause issues in some HTTP implementations
	if strings.Contains(path, "\x00") {
		return &PathValidationError{
			Path:   path,
			Reason: "path contains null byte",
		}
	}

	// SECURITY: Reject paths with excessive slashes (potential DoS or confusion)
	if strings.Count(path, "/") > MaxPathSegments {
		return &PathValidationError{
			Path:   path,
			Reason: "path contains too many segments (DoS prevention)",
		}
	}

	return nil
}

// PathValidationError represents a path validation failure.
type PathValidationError struct {
	Path   string
	Reason string
}

// Error implements the error interface.
func (e *PathValidationError) Error() string {
	return e.Reason
}

// PathMatchesPrefix checks if resourcePath matches or starts with prefix.
// Handles path boundaries correctly: /mcp/files matches /mcp but not /mc.
//
// This is a pure function used for longest-prefix matching in path configuration
// lookups. It ensures that path matching respects segment boundaries.
//
// Returns false if either resourcePath or prefix is empty (empty prefix should
// not match anything in the context of path configuration).
//
// Examples:
//
//	PathMatchesPrefix("/mcp/files", "/mcp")    // true - valid prefix match
//	PathMatchesPrefix("/mcp", "/mcp")          // true - exact match
//	PathMatchesPrefix("/mcpx", "/mcp")         // false - not a segment boundary
//	PathMatchesPrefix("/other/mcp", "/mcp")    // false - not a prefix
//	PathMatchesPrefix("/a", "")                // false - empty prefix
func PathMatchesPrefix(resourcePath, prefix string) bool {
	// Empty prefix should not match anything (makes no sense for path matching)
	if prefix == "" {
		return resourcePath == ""
	}

	// Exact match
	if resourcePath == prefix {
		return true
	}

	// Prefix match with path boundary
	if strings.HasPrefix(resourcePath, prefix) {
		// Ensure we're matching at a path boundary
		// /mcp/files should match /mcp but not /mc
		remaining := strings.TrimPrefix(resourcePath, prefix)
		return len(remaining) > 0 && remaining[0] == '/'
	}

	return false
}
