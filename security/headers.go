package security

import (
	"net/http"
	"net/url"
)

// InterstitialScriptHash is the SHA-256 hash of the static inline script used in the
// success interstitial page. This hash is computed from the minified script content
// and allows the script to execute under a strict Content-Security-Policy.
//
// The script reads the redirect URL from the button's href attribute (which is set
// by the template), so the script content is static and the hash is stable.
//
// To regenerate this hash if the script changes:
//
//	echo -n '<script content>' | openssl dgst -sha256 -binary | base64
const InterstitialScriptHash = "sha256-BSPDdcxaKPs2IRkTMWvH7KxMRr/MuFv1HaDJlxd1UTI="

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

// SetInterstitialSecurityHeaders sets security headers for the OAuth success interstitial page.
// This is similar to SetSecurityHeaders but includes a hash-based CSP exception for the
// inline redirect script.
//
// Security considerations:
//   - Uses hash-based script allowlisting (CSP Level 2) instead of 'unsafe-inline'
//   - The script hash is computed from a static script that reads the redirect URL
//     from the DOM, ensuring the hash remains stable across different redirect URLs
//   - style-src 'unsafe-inline' is required for the inline CSS animations
func SetInterstitialSecurityHeaders(w http.ResponseWriter, serverURL string) {
	// X-Frame-Options: Prevent clickjacking attacks
	w.Header().Set("X-Frame-Options", "DENY")

	// X-Content-Type-Options: Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// X-XSS-Protection: Enable browser XSS protection (legacy browsers)
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Content-Security-Policy: Allow only the specific inline script via hash
	// - default-src 'none': Block everything by default
	// - script-src with hash: Allow only the exact inline script we control
	// - style-src 'unsafe-inline': Required for inline CSS (animations, styling)
	// - frame-ancestors 'none': Prevent embedding in iframes
	csp := "default-src 'none'; script-src '" + InterstitialScriptHash + "'; style-src 'unsafe-inline'; frame-ancestors 'none'"
	w.Header().Set("Content-Security-Policy", csp)

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
