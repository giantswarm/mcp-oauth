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
// - We take the FIRST IP (leftmost) as it's the original client IP
// - The rightmost IPs are added by proxies and could be spoofed if multiple proxies exist
// - For production with multiple proxies, configure the number of trusted proxies
func GetClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// SECURITY: Take FIRST IP from X-Forwarded-For (original client)
		// Format: "client-ip, proxy1-ip, proxy2-ip"
		// The leftmost IP is the original client, subsequent IPs are added by proxies
		// 
		// Example:
		//   Client (1.2.3.4) -> Proxy1 -> Proxy2 (trusted)
		//   X-Forwarded-For: "1.2.3.4, proxy1-ip"
		//   We want: 1.2.3.4
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				// Get the first IP (original client)
				clientIP := strings.TrimSpace(ips[0])
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

