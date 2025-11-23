package security

import (
	"net/http"
	"net/url"
)

// SetSecurityHeaders sets comprehensive security headers on HTTP responses
// These headers protect against various web vulnerabilities
func SetSecurityHeaders(w http.ResponseWriter, serverURL string) {
	// X-Frame-Options: Prevent clickjacking attacks
	w.Header().Set("X-Frame-Options", "DENY")

	// X-Content-Type-Options: Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// X-XSS-Protection: Enable browser XSS protection (legacy browsers)
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Content-Security-Policy: Restrict resource loading
	// Very strict policy for OAuth endpoints (no inline scripts, no external resources)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

	// Referrer-Policy: Don't leak referrer information
	w.Header().Set("Referrer-Policy", "no-referrer")

	// Strict-Transport-Security: Enforce HTTPS (only if server uses HTTPS)
	if parsed, err := url.Parse(serverURL); err == nil && parsed.Scheme == "https" {
		// HSTS: Force HTTPS for 1 year, including subdomains
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Cache-Control: Prevent caching of sensitive OAuth responses
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
}

