// Package helpers provides common utility functions used across the mcp-oauth library.
// These utilities handle string manipulation, formatting, and other shared operations
// that don't fit into domain-specific packages.
package helpers

import (
	"net/url"
	"strings"
)

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

// NormalizeURL normalizes a URL for comparison.
// This is used for RFC 8707 resource identifier and audience comparison,
// where semantically equivalent URLs should be considered equal.
//
// Normalization includes:
//   - Lowercase scheme and host (case-insensitive per RFC 3986)
//   - Remove default ports (:443 for https, :80 for http)
//   - Remove trailing slashes from path
//   - Preserve path case (paths are case-sensitive)
//
// If the input is not a valid URL, it returns the lowercase trimmed input
// for backwards compatibility with non-URL audience values.
//
// Example:
//
//	NormalizeURL("https://EXAMPLE.COM/")       // Returns: "https://example.com"
//	NormalizeURL("https://example.com:443/")  // Returns: "https://example.com"
//	NormalizeURL("https://example.com")        // Returns: "https://example.com"
//	NormalizeURL("https://example.com///")     // Returns: "https://example.com"
//	NormalizeURL("HTTPS://Example.COM/Path")   // Returns: "https://example.com/Path"
//	NormalizeURL("client-id")                  // Returns: "client-id" (non-URL)
func NormalizeURL(rawURL string) string {
	// Try to parse as URL for full normalization
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		// Not a valid URL, just trim trailing slashes
		return strings.TrimRight(rawURL, "/")
	}

	// Normalize scheme to lowercase
	scheme := strings.ToLower(parsed.Scheme)

	// Normalize host to lowercase and remove default ports
	host := strings.ToLower(parsed.Host)
	host = removeDefaultPort(host, scheme)

	// Normalize path by removing trailing slashes (preserve case)
	path := strings.TrimRight(parsed.Path, "/")

	// Reconstruct the normalized URL
	// Only include components that were present
	result := scheme + "://" + host
	if path != "" {
		result += path
	}

	// Preserve query and fragment if present
	if parsed.RawQuery != "" {
		result += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		result += "#" + parsed.Fragment
	}

	return result
}

// removeDefaultPort removes the default port from a host:port string.
// HTTPS default is 443, HTTP default is 80.
func removeDefaultPort(host, scheme string) string {
	switch scheme {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	default:
		return host
	}
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
