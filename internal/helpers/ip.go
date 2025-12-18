// Package helpers provides common utility functions used across the mcp-oauth library.
package helpers

import "net"

// IPClassification represents the security classification of an IP address.
// This is used for SSRF protection in redirect URI validation and client ID metadata fetching.
type IPClassification int

const (
	// IPClassificationPublic indicates a publicly routable IP address.
	IPClassificationPublic IPClassification = iota
	// IPClassificationLoopback indicates a loopback address (127.0.0.0/8, ::1).
	IPClassificationLoopback
	// IPClassificationPrivate indicates a private/internal address (RFC 1918, ULA).
	IPClassificationPrivate
	// IPClassificationLinkLocal indicates a link-local address (169.254.x.x, fe80::/10).
	IPClassificationLinkLocal
	// IPClassificationUnspecified indicates an unspecified address (0.0.0.0, ::).
	IPClassificationUnspecified
)

// String returns a human-readable name for the IP classification.
func (c IPClassification) String() string {
	switch c {
	case IPClassificationPublic:
		return "public"
	case IPClassificationLoopback:
		return "loopback"
	case IPClassificationPrivate:
		return "private"
	case IPClassificationLinkLocal:
		return "link_local"
	case IPClassificationUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// ClassifyIP returns the security classification of an IP address.
// This is the single source of truth for IP classification used across the library
// for SSRF protection in redirect URI validation and client metadata fetching.
//
// Classifications:
//   - Unspecified: 0.0.0.0, :: (always dangerous, undefined behavior)
//   - Loopback: 127.0.0.0/8, ::1 (allowed for native apps per RFC 8252)
//   - LinkLocal: 169.254.0.0/16, fe80::/10 (cloud metadata SSRF risk)
//   - Private: RFC 1918 (10/8, 172.16/12, 192.168/16), fc00::/7 (SSRF to internal networks)
//   - Public: All other addresses (generally safe)
func ClassifyIP(ip net.IP) IPClassification {
	if ip == nil {
		return IPClassificationUnspecified
	}

	// Check for unspecified addresses (0.0.0.0, ::)
	// These are always blocked as they can bind to all interfaces or have undefined behavior
	if ip.IsUnspecified() {
		return IPClassificationUnspecified
	}

	// Check for loopback addresses (127.0.0.0/8, ::1)
	// Allowed for native apps per RFC 8252 Section 7.3
	if ip.IsLoopback() {
		return IPClassificationLoopback
	}

	// Check for link-local addresses (169.254.0.0/16, fe80::/10, ff02::/16)
	// This is critical for cloud security - blocks access to metadata services (169.254.169.254)
	if IsLinkLocal(ip) {
		return IPClassificationLinkLocal
	}

	// Check for private addresses using Go's built-in IsPrivate
	// Covers RFC 1918 (IPv4) and fc00::/7 (IPv6 ULA)
	if ip.IsPrivate() {
		return IPClassificationPrivate
	}

	return IPClassificationPublic
}

// IsLinkLocal checks if an IP address is link-local (unicast or multicast).
// This includes:
//   - IPv4 link-local: 169.254.0.0/16 (also catches cloud metadata 169.254.169.254)
//   - IPv6 link-local unicast: fe80::/10
//   - IPv6 link-local multicast: ff02::/16
//
// Link-local addresses are a significant security concern in cloud environments
// as they can access instance metadata services (AWS, GCP, Azure).
func IsLinkLocal(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// IsPrivateOrInternal checks if an IP is private, loopback, link-local, or unspecified.
// This is a convenience function for SSRF protection that returns true for any
// non-public IP address.
//
// Used by client ID metadata document fetching for comprehensive SSRF protection.
func IsPrivateOrInternal(ip net.IP) bool {
	classification := ClassifyIP(ip)
	return classification != IPClassificationPublic
}

// IsLoopbackHostname checks if a hostname represents a loopback address.
// This includes the entire 127.0.0.0/8 range (RFC 1122) and IPv6 ::1.
// Expects hostname without port (as returned by url.URL.Hostname()).
//
// Note: This function does NOT consider 0.0.0.0 as loopback (it's "unspecified").
func IsLoopbackHostname(hostname string) bool {
	// Handle "localhost" hostname directly
	if hostname == "localhost" {
		return true
	}

	// Normalize hostname (strip brackets from IPv6 like [::1])
	cleanHostname := hostname
	if len(hostname) > 2 && hostname[0] == '[' && hostname[len(hostname)-1] == ']' {
		cleanHostname = hostname[1 : len(hostname)-1]
	}

	// Parse as IP and use stdlib's IsLoopback for correct handling of:
	// - 127.0.0.0/8 range (all 16M addresses)
	// - ::1 (IPv6 loopback)
	// - ::ffff:127.0.0.1 (IPv4-mapped IPv6 loopback)
	if ip := net.ParseIP(cleanHostname); ip != nil {
		return ip.IsLoopback()
	}

	return false
}
