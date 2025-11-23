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
		// SECURITY: Extract client IP accounting for trusted proxies
		// Format: "client-ip, untrusted-proxy, trusted-proxy2, trusted-proxy1"
		// The rightmost IPs are the trusted proxies we control
		//
		// Example with trustedProxyCount=2:
		//   Client (1.2.3.4) -> UntrustedProxy -> TrustedProxy2 -> TrustedProxy1 (us)
		//   X-Forwarded-For: "1.2.3.4, untrusted-ip, proxy2-ip"
		//   We extract: ips[len(ips) - trustedProxyCount - 1] = ips[0] = "1.2.3.4"
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				// Calculate client IP index accounting for trusted proxies
				// If trustedProxyCount=0, default to 1 (assume 1 trusted proxy)
				proxyCount := trustedProxyCount
				if proxyCount == 0 {
					proxyCount = 1
				}

				// Client IP is at: len(ips) - proxyCount - 1
				// But if we don't have enough IPs, take the first one
				clientIndex := len(ips) - proxyCount - 1
				if clientIndex < 0 {
					clientIndex = 0 // Not enough proxies, take leftmost IP
				}

				clientIP := strings.TrimSpace(ips[clientIndex])
				if ip := net.ParseIP(clientIP); ip != nil {
					return clientIP
				}
			}
		}

		// Fallback to X-Real-IP header (set by some proxies)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return xri
			}
		}
	}

	// Direct connection or untrusted proxy - use RemoteAddr
	// This is the IP of the direct connection (could be a proxy if not trusted)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Return as-is if splitting fails
	}
	return host
}
