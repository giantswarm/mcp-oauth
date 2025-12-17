package server

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Kubernetes service account identity constants
const (
	// kubernetesServiceAccountPrefix is the prefix for K8s SA identities
	kubernetesServiceAccountPrefix = "system:serviceaccount:"

	// DefaultMachineIdentityEmailDomain is the default domain for synthetic emails
	DefaultMachineIdentityEmailDomain = "serviceaccount.local"

	// kubernetesServiceAccountPattern matches system:serviceaccount:namespace:name
	// Namespace and name follow K8s naming conventions (lowercase alphanumeric, -, .)
	kubernetesServiceAccountPatternStr = `^system:serviceaccount:([a-z0-9][-a-z0-9.]*[a-z0-9]):([a-z0-9][-a-z0-9.]*[a-z0-9])$`
)

var kubernetesServiceAccountPattern = regexp.MustCompile(kubernetesServiceAccountPatternStr)

// ParseKubernetesServiceAccount parses a K8s SA identity from a sub claim.
// Returns namespace, name, and whether it's a valid K8s SA.
//
// Handles both formats:
//   - Raw format: "system:serviceaccount:namespace:name"
//   - Dex encoded format: base64-encoded protobuf containing the K8s identity
//
// Dex encodes federated identities as protobuf with:
//   - Field 1: upstream subject (the K8s SA identity)
//   - Field 2: connector ID (e.g., "kubernetes")
//
// Example:
//
//	sub := "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw"
//	namespace, name, ok := ParseKubernetesServiceAccount(sub)
//	// namespace = "org-giantswarm", name = "grizzly-shoot", ok = true
func ParseKubernetesServiceAccount(sub string) (namespace, name string, ok bool) {
	// First, try to parse as raw K8s SA identity
	if namespace, name, ok = parseRawKubernetesServiceAccount(sub); ok {
		return namespace, name, true
	}

	// Try to decode as Dex's base64-encoded protobuf format
	decoded, err := tryDecodeDexSubject(sub)
	if err != nil {
		return "", "", false
	}

	// Now parse the decoded string as raw K8s SA identity
	return parseRawKubernetesServiceAccount(decoded)
}

// parseRawKubernetesServiceAccount parses a raw K8s SA identity string.
// Format: system:serviceaccount:namespace:name
func parseRawKubernetesServiceAccount(identity string) (namespace, name string, ok bool) {
	matches := kubernetesServiceAccountPattern.FindStringSubmatch(identity)
	if len(matches) != 3 {
		return "", "", false
	}
	return matches[1], matches[2], true
}

// tryDecodeDexSubject attempts to decode a Dex-encoded subject claim.
// Dex encodes federated identities as protobuf with the upstream subject in field 1.
//
// The wire format is:
//   - 0x0a (field 1, wire type 2 = length-delimited)
//   - varint length
//   - subject bytes
//   - 0x12 (field 2, wire type 2)
//   - varint length
//   - connector_id bytes
//
// We extract field 1 (the upstream subject) which contains the K8s SA identity.
func tryDecodeDexSubject(encoded string) (string, error) {
	// Try standard base64 decoding
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			// Try raw (no padding) variants
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					return "", fmt.Errorf("not base64 encoded: %w", err)
				}
			}
		}
	}

	// Parse the protobuf-like format to extract field 1 (upstream subject)
	return extractProtobufField1(decoded)
}

// extractProtobufField1 extracts the first string field from a protobuf-encoded message.
// This is a minimal parser for Dex's federated identity format.
//
// Wire format for string field 1:
//   - Tag byte: 0x0a = (1 << 3) | 2 = field 1, wire type 2 (length-delimited)
//   - Length: varint
//   - Data: UTF-8 string bytes
func extractProtobufField1(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("data too short")
	}

	// Check for field 1, wire type 2 (length-delimited)
	// Tag = (field_number << 3) | wire_type = (1 << 3) | 2 = 0x0a
	if data[0] != 0x0a {
		return "", fmt.Errorf("unexpected tag byte: 0x%02x, expected 0x0a", data[0])
	}

	// Read varint length
	length, bytesRead := readVarint(data[1:])
	if bytesRead == 0 {
		return "", fmt.Errorf("invalid varint length")
	}

	// Extract the string data
	start := 1 + bytesRead
	end := start + int(length)
	if end > len(data) {
		return "", fmt.Errorf("string length exceeds data: need %d, have %d", end, len(data))
	}

	return string(data[start:end]), nil
}

// readVarint reads a varint from the byte slice and returns the value and bytes consumed.
// Returns 0 bytes consumed if the varint is invalid.
func readVarint(data []byte) (uint64, int) {
	var value uint64
	for i, b := range data {
		if i >= 10 { // Varints are at most 10 bytes
			return 0, 0
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, i + 1
		}
	}
	return 0, 0
}

// GenerateSyntheticEmail creates a synthetic email address from a K8s SA identity.
// Format: {name}@{namespace}.{domain}
//
// Example:
//
//	email := GenerateSyntheticEmail("org-giantswarm", "grizzly-shoot", "serviceaccount.local")
//	// email = "grizzly-shoot@org-giantswarm.serviceaccount.local"
func GenerateSyntheticEmail(namespace, name, domain string) string {
	if domain == "" {
		domain = DefaultMachineIdentityEmailDomain
	}
	return fmt.Sprintf("%s@%s.%s", name, namespace, domain)
}

// DeriveKubernetesGroups returns standard K8s groups for a service account.
// These are the same groups Kubernetes assigns to service accounts:
//   - system:serviceaccounts (all service accounts)
//   - system:serviceaccounts:{namespace} (service accounts in this namespace)
//   - system:authenticated (all authenticated identities)
//
// Example:
//
//	groups := DeriveKubernetesGroups("org-giantswarm")
//	// groups = ["system:serviceaccounts", "system:serviceaccounts:org-giantswarm", "system:authenticated"]
func DeriveKubernetesGroups(namespace string) []string {
	return []string{
		"system:serviceaccounts",
		fmt.Sprintf("system:serviceaccounts:%s", namespace),
		"system:authenticated",
	}
}

// IsKubernetesServiceAccount checks if the given sub claim represents a K8s service account.
// This is a convenience function that wraps ParseKubernetesServiceAccount.
func IsKubernetesServiceAccount(sub string) bool {
	_, _, ok := ParseKubernetesServiceAccount(sub)
	return ok
}

// sanitizeForEmail removes or replaces characters that are not valid in email local parts.
// This is used as a fallback for non-K8s machine identities.
func sanitizeForEmail(s string) string {
	// Replace common problematic characters
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, " ", "-")

	// Remove any remaining non-alphanumeric characters except - and .
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()
	// Ensure it doesn't start or end with a special character
	sanitized = strings.Trim(sanitized, "-._")

	// Limit length to reasonable email local part size
	if len(sanitized) > 64 {
		sanitized = sanitized[:64]
	}

	// If empty after sanitization, use a fallback
	if sanitized == "" {
		sanitized = "machine"
	}

	return sanitized
}

// GenerateFallbackEmail creates a synthetic email for non-K8s machine identities.
// Format: {sanitized-sub}@machine.local
func GenerateFallbackEmail(sub string) string {
	sanitized := sanitizeForEmail(sub)
	return fmt.Sprintf("%s@machine.local", sanitized)
}

