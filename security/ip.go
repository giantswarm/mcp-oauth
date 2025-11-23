package security

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP address from the request
// Supports X-Forwarded-For and X-Real-IP headers when behind a proxy
func GetClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Security: Take LAST IP from X-Forwarded-For (from trusted proxy)
		// This prevents client spoofing by taking the IP added by our trusted proxy
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			// Get the last IP (added by our trusted proxy)
			clientIP := strings.TrimSpace(ips[len(ips)-1])
			if ip := net.ParseIP(clientIP); ip != nil {
				return clientIP
			}
		}

		// Fallback to X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return xri
			}
		}
	}

	// Direct connection or untrusted proxy - use RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Return as-is if splitting fails
	}
	return host
}

