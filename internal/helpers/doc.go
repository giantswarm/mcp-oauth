// Package helpers provides common utility functions used across the mcp-oauth library.
//
// This package contains helper functions for string manipulation, formatting,
// IP classification, and other shared operations that don't fit into domain-specific
// packages. These utilities are used internally by multiple packages to avoid code
// duplication and maintain consistent behavior across the codebase.
//
// Key utilities:
//   - SafeTruncate: Safely truncates strings for logging sensitive data
//   - ClassifyIP: Classifies IP addresses for SSRF protection (public, private, loopback, etc.)
//   - IsLinkLocal: Checks if an IP is link-local (cloud metadata SSRF protection)
//   - IsLoopbackHostname: Checks if a hostname represents a loopback address
//   - ValidateMetadataPath: Validates paths for security concerns (path traversal, etc.)
package helpers
