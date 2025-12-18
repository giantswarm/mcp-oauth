package security

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP address from the request
// Supports X-Forwarded-For and X-Real-IP headers when behind a proxy
//
// SECURITY CONSIDERATIONS:
// - Only enable trustProxy when behind a trusted reverse proxy (nginx, haproxy, etc.)
// - X-Forwarded-For format: "client, proxy1, proxy2, ..."
// - trustedProxyCount specifies how many proxies to trust from the right
// - This prevents X-Forwarded-For spoofing in multi-proxy setups
func GetClientIP(r *http.Request, trustProxy bool, trustedProxyCount int) string {
	if trustProxy {
		if ip := extractIPFromXFF(r.Header.Get("X-Forwarded-For"), trustedProxyCount); ip != "" {
			return ip
		}
		if ip := extractIPFromXRealIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return extractIPFromRemoteAddr(r.RemoteAddr)
}

// extractIPFromXFF parses the X-Forwarded-For header and extracts the client IP.
// SECURITY: Format is "client-ip, untrusted-proxy, trusted-proxy2, trusted-proxy1"
// The rightmost IPs are the trusted proxies we control.
//
// Example with trustedProxyCount=2:
//
//	Client (1.2.3.4) -> UntrustedProxy -> TrustedProxy2 -> TrustedProxy1 (us)
//	X-Forwarded-For: "1.2.3.4, untrusted-ip, proxy2-ip"
//	We extract: ips[len(ips) - trustedProxyCount - 1] = ips[0] = "1.2.3.4"
func extractIPFromXFF(xff string, trustedProxyCount int) string {
	if xff == "" {
		return ""
	}

	ips := strings.Split(xff, ",")
	if len(ips) == 0 {
		return ""
	}

	clientIndex := calculateClientIPIndex(len(ips), trustedProxyCount)
	clientIP := strings.TrimSpace(ips[clientIndex])

	if net.ParseIP(clientIP) != nil {
		return clientIP
	}
	return ""
}

// calculateClientIPIndex determines the index of the client IP in the X-Forwarded-For list.
// If trustedProxyCount=0, defaults to 1 (assume 1 trusted proxy).
// Client IP is at: len(ips) - proxyCount - 1
// If we don't have enough IPs, returns 0 (leftmost IP).
func calculateClientIPIndex(numIPs, trustedProxyCount int) int {
	proxyCount := trustedProxyCount
	if proxyCount == 0 {
		proxyCount = 1
	}

	clientIndex := numIPs - proxyCount - 1
	if clientIndex < 0 {
		return 0
	}
	return clientIndex
}

// extractIPFromXRealIP parses the X-Real-IP header (set by some proxies).
func extractIPFromXRealIP(xri string) string {
	if xri == "" {
		return ""
	}
	if net.ParseIP(xri) != nil {
		return xri
	}
	return ""
}

// extractIPFromRemoteAddr extracts the IP from RemoteAddr for direct connections.
// This is the IP of the direct connection (could be a proxy if not trusted).
func extractIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
