// Package server provides OAuth 2.1 authorization server implementation with MCP support
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
)

// Constants for localhost detection in redirect URIs
const (
	localhostHostname     = "localhost"
	localhostIPv4Loopback = "127.0.0.1"
	localhostIPv6Loopback = "::1"
)

// ClientMetadata represents OAuth client metadata fetched from a URL-based client_id
// Implements draft-ietf-oauth-client-id-metadata-document-00
type ClientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
}

// isURLClientID checks if a client_id is a URL-formatted identifier
// Per draft-ietf-oauth-client-id-metadata-document-00:
// - MUST be an HTTPS URL
// - MUST have a hostname
// - Path component is optional (spec says "typically" has one, but not required)
// - MUST NOT contain userinfo, query parameters, or fragments (security hardening)
func isURLClientID(clientID string) bool {
	// Empty strings are not URLs
	if clientID == "" {
		return false
	}

	// Parse as URL
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}

	// MUST be HTTPS (security requirement)
	if u.Scheme != SchemeHTTPS {
		return false
	}

	// MUST have a hostname
	if u.Host == "" {
		return false
	}

	// SECURITY: Reject URLs with userinfo (credentials in URL)
	// Prevents: https://user:pass@example.com/
	if u.User != nil {
		return false
	}

	// SECURITY: Reject URLs with query parameters
	// Prevents injection attacks like: https://example.com?redirect=http://evil.com
	if u.RawQuery != "" {
		return false
	}

	// SECURITY: Reject URLs with fragments
	// Prevents fragment-based attacks like: https://example.com#../../etc/passwd
	if u.Fragment != "" {
		return false
	}

	// SHOULD have a path component (but not strictly required)
	// We'll be lenient here - the spec says client IDs "typically" have paths
	return true
}

// isPrivateIP checks if an IP address is in a private/internal range
// Used for SSRF protection per draft-ietf-oauth-client-id-metadata-document-00 Section 6
// Covers IPv4, IPv6, and IPv4-mapped IPv6 addresses
func isPrivateIP(ip net.IP) bool {
	// Check for loopback addresses (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local addresses (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IPv4 ranges
	// 10.0.0.0/8
	if ipv4 := ip.To4(); ipv4 != nil {
		if ipv4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
	}

	// SECURITY: Check for IPv4-mapped IPv6 addresses (::ffff:0:0/96)
	// These can be used to bypass IPv4 private IP checks
	// Example: ::ffff:127.0.0.1, ::ffff:10.0.0.1
	if len(ip) == 16 && ip.To4() == nil {
		// Check if this is an IPv4-mapped IPv6 address
		// Format: 0000:0000:0000:0000:0000:ffff:xxxx:xxxx
		isIPv4Mapped := true
		for i := 0; i < 10; i++ {
			if ip[i] != 0 {
				isIPv4Mapped = false
				break
			}
		}
		if isIPv4Mapped && ip[10] == 0xff && ip[11] == 0xff {
			// Extract the IPv4 part and check recursively
			ipv4 := net.IPv4(ip[12], ip[13], ip[14], ip[15])
			return isPrivateIP(ipv4)
		}
	}

	// Check for private IPv6 ranges
	// Unique local addresses (fc00::/7) - includes both fc00::/8 and fd00::/8
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}

	// fd00::/8 is the most commonly used ULA range (subset of fc00::/7, but check explicitly)
	if len(ip) == 16 && ip[0] == 0xfd {
		return true
	}

	return false
}

// validateAndSanitizeMetadataURL performs SSRF protection checks and returns a sanitized URL
// Per draft-ietf-oauth-client-id-metadata-document-00 Section 6:
// "Authorization servers fetching metadata documents SHOULD consider
// Server-Side Request Forgery (SSRF) risks"
func validateAndSanitizeMetadataURL(clientID string) (string, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// CRITICAL SECURITY: MUST be HTTPS only (no HTTP)
	if u.Scheme != SchemeHTTPS {
		return "", fmt.Errorf("client_id metadata URL must use HTTPS, got: %s", u.Scheme)
	}

	// Extract hostname for IP validation
	hostname := u.Hostname()

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}

	// CRITICAL SECURITY: Block requests to private/internal IP ranges
	// This prevents SSRF attacks against internal services
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("client_id metadata URL resolves to private/internal IP address: %s -> %s (SSRF protection)",
				hostname, ip.String())
		}
	}

	// Reconstruct URL from validated components to break taint flow
	sanitized := &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}
	return sanitized.String(), nil
}

// createSSRFProtectedTransport creates an HTTP transport with SSRF protection at connection time
// This prevents DNS rebinding attacks by validating IPs when connecting, not just during initial validation
func createSSRFProtectedTransport(ctx context.Context) *http.Transport {
	return &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			// Parse host:port
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// CRITICAL SECURITY: Resolve and validate IPs at connection time
			// This prevents DNS rebinding attacks where DNS resolution changes between
			// initial validation and actual connection
			ips, err := net.DefaultResolver.LookupIPAddr(dialCtx, host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
			}

			// Check all resolved IPs for private ranges
			for _, ipAddr := range ips {
				if isPrivateIP(ipAddr.IP) {
					return nil, fmt.Errorf("SSRF protection: %s resolves to private/internal IP %s", host, ipAddr.IP)
				}
			}

			// All IPs are safe - use default dialer
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(dialCtx, network, addr)
		},
	}
}

// fetchClientMetadata fetches and validates OAuth client metadata from an HTTPS URL
// Implements draft-ietf-oauth-client-id-metadata-document-00
//
// Returns the metadata and a suggested cache TTL from HTTP Cache-Control header (0 if not specified)
//
// Security considerations per Section 6:
// - SSRF protection: blocks private/internal IP addresses at connection time (prevents DNS rebinding)
// - HTTPS only: rejects HTTP URLs
// - Timeout protection: enforces reasonable timeout
// - Size limit: prevents memory exhaustion and validates full document read
func (s *Server) fetchClientMetadata(ctx context.Context, clientID string) (*ClientMetadata, time.Duration, error) {
	sanitizedURL, err := validateAndSanitizeMetadataURL(clientID)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "client_metadata_fetch_blocked",
				ClientID: clientID,
				Details: map[string]any{
					"reason": err.Error(),
					"ssrf":   "protected",
				},
			})
		}
		return nil, 0, fmt.Errorf("metadata URL validation failed: %w", err)
	}

	timeout := 10 * time.Second
	if s.Config.ClientMetadataFetchTimeout > 0 {
		timeout = s.Config.ClientMetadataFetchTimeout
	}

	if deadline, ok := ctx.Deadline(); ok {
		timeUntilDeadline := time.Until(deadline)
		if timeUntilDeadline > 0 && timeUntilDeadline < timeout {
			timeout = timeUntilDeadline
			s.Logger.Debug("Using context deadline for metadata fetch",
				"original_timeout", s.Config.ClientMetadataFetchTimeout,
				"adjusted_timeout", timeout,
				"reason", "context deadline")
		}
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: createSSRFProtectedTransport(ctx),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sanitizedURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create metadata request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcp-oauth")

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "client_metadata_fetch_failed",
				ClientID: clientID,
				Details: map[string]any{
					"error": err.Error(),
				},
			})
		}
		return nil, 0, fmt.Errorf("failed to fetch metadata from %s: %w", clientID, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			s.Logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "client_metadata_fetch_failed",
				ClientID: clientID,
				Details: map[string]any{
					"status_code": resp.StatusCode,
					"status":      resp.Status,
				},
			})
		}
		return nil, 0, fmt.Errorf("metadata fetch returned HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// SECURITY: Strict Content-Type validation - must be exactly application/json
	// (with optional charset parameter)
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return nil, 0, fmt.Errorf("metadata response missing Content-Type header")
	}

	// Parse media type and parameters
	parts := strings.Split(contentType, ";")
	mediaType := strings.ToLower(strings.TrimSpace(parts[0]))
	if mediaType != "application/json" {
		return nil, 0, fmt.Errorf("metadata must be application/json, got: %s", contentType)
	}

	// SECURITY: Validate charset parameter if present (must be UTF-8)
	// JSON is defined as UTF-8 per RFC 8259, non-UTF-8 encodings can cause parsing issues
	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if kv := strings.SplitN(param, "=", 2); len(kv) == 2 {
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.Trim(strings.ToLower(strings.TrimSpace(kv[1])), "\" ")

			if key == "charset" {
				// Allow utf-8 and utf8 (both are valid)
				if value != "utf-8" && value != "utf8" {
					return nil, 0, fmt.Errorf("unsupported charset: %s (only UTF-8 is supported for JSON)", value)
				}
			}
		}
	}

	// SECURITY: Validate Content-Length header to prevent resource waste
	// Check declared size before reading body
	const maxMetadataSize = 1 * 1024 * 1024 // 1MB
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		size, parseErr := strconv.ParseInt(contentLength, 10, 64)
		if parseErr == nil && size > maxMetadataSize {
			return nil, 0, fmt.Errorf("metadata Content-Length (%d bytes) exceeds maximum size of %d bytes", size, maxMetadataSize)
		}
	}

	// SECURITY: Read entire response body with size limit to prevent:
	// 1. Memory exhaustion from large responses
	// 2. Partial JSON parsing from truncated responses
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if response was truncated (exceeded size limit)
	if len(bodyBytes) > maxMetadataSize {
		return nil, 0, fmt.Errorf("metadata document exceeds maximum size of %d bytes", maxMetadataSize)
	}

	// Parse JSON response
	var metadata ClientMetadata
	if err := json.Unmarshal(bodyBytes, &metadata); err != nil {
		return nil, 0, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	// CRITICAL SECURITY: Validate that client_id in document matches the URL
	// Per spec: "The client_id value in the metadata document MUST exactly match
	// the URL from which it was retrieved"
	if metadata.ClientID != clientID {
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     "client_metadata_id_mismatch",
				ClientID: clientID,
				Details: map[string]any{
					"document_client_id": metadata.ClientID,
					"url_client_id":      clientID,
					"severity":           "high",
				},
			})
		}
		return nil, 0, fmt.Errorf("client_id mismatch: document contains %q but was fetched from %q (security violation)",
			metadata.ClientID, clientID)
	}

	// Validate required fields
	if len(metadata.RedirectURIs) == 0 {
		return nil, 0, fmt.Errorf("metadata must contain at least one redirect_uri")
	}

	// SECURITY: Validate redirect URIs for safety (defense-in-depth)
	// OAuth 2.1 requires HTTPS for redirect URIs except localhost
	for _, uri := range metadata.RedirectURIs {
		u, parseErr := url.Parse(uri)
		if parseErr != nil {
			return nil, 0, fmt.Errorf("invalid redirect_uri %q: %w", uri, parseErr)
		}

		// Only allow http and https schemes
		if u.Scheme != SchemeHTTPS && u.Scheme != SchemeHTTP {
			return nil, 0, fmt.Errorf("redirect_uri must use http or https scheme, got %s: %s", u.Scheme, uri)
		}

		// OAuth 2.1: HTTP redirect URIs only allowed for localhost
		if u.Scheme == SchemeHTTP {
			hostname := u.Hostname()
			if hostname != localhostHostname && hostname != localhostIPv4Loopback && hostname != localhostIPv6Loopback {
				return nil, 0, fmt.Errorf("http redirect_uri only allowed for localhost, got %s: %s", hostname, uri)
			}
		}
	}

	// Set defaults per OAuth 2.0 spec if not specified
	if len(metadata.GrantTypes) == 0 {
		metadata.GrantTypes = []string{"authorization_code"}
	}
	if len(metadata.ResponseTypes) == 0 {
		metadata.ResponseTypes = []string{"code"}
	}
	if metadata.TokenEndpointAuthMethod == "" {
		metadata.TokenEndpointAuthMethod = "none" // Default for public clients
	}

	// Parse Cache-Control header for suggested TTL
	// Per HTTP caching spec, max-age directive suggests how long to cache the response
	var suggestedTTL time.Duration
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		if maxAge := parseCacheControlMaxAge(cacheControl); maxAge > 0 {
			suggestedTTL = time.Duration(maxAge) * time.Second
			s.Logger.Debug("Parsed Cache-Control max-age",
				"client_id", clientID,
				"max_age_seconds", maxAge,
				"suggested_ttl", suggestedTTL)
		}
	}

	// Log successful fetch
	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type:     "client_metadata_fetched",
			ClientID: clientID,
			Details: map[string]any{
				"client_name":     metadata.ClientName,
				"redirect_count":  len(metadata.RedirectURIs),
				"document_size":   len(bodyBytes),
				"cache_suggested": suggestedTTL > 0,
			},
		})
	}

	s.Logger.Info("Fetched client metadata from URL",
		"client_id", clientID,
		"client_name", metadata.ClientName,
		"redirect_uris", len(metadata.RedirectURIs),
		"size_bytes", len(bodyBytes),
		"cache_ttl", suggestedTTL)

	return &metadata, suggestedTTL, nil
}

// hasLocalhostRedirectURIsOnly checks if all redirect URIs point to localhost
// Used to display security warnings per draft-ietf-oauth-client-id-metadata-document-00 Section 6
func hasLocalhostRedirectURIsOnly(redirectURIs []string) bool {
	if len(redirectURIs) == 0 {
		return false
	}

	for _, uri := range redirectURIs {
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}

		hostname := u.Hostname() // Hostname() strips port and brackets from IPv6
		// Check if hostname is NOT localhost (including IPv6 loopback)
		if hostname != localhostHostname && hostname != localhostIPv4Loopback && hostname != localhostIPv6Loopback {
			return false
		}
	}

	return true
}

// parseCacheControlMaxAge extracts max-age directive from Cache-Control header
// Returns 0 if max-age is not present or invalid
// Caps the max-age at 1 hour to prevent excessive caching from malicious servers
// Example: "max-age=300, must-revalidate" -> 300 seconds
func parseCacheControlMaxAge(cacheControl string) int {
	const maxCacheControlAge = 3600 // 1 hour - prevents excessive caching

	// Split by comma to handle multiple directives
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		// Trim whitespace and convert to lowercase
		directive = strings.TrimSpace(strings.ToLower(directive))

		// Check for max-age directive
		if strings.HasPrefix(directive, "max-age=") {
			// Extract the value after "max-age="
			ageStr := strings.TrimPrefix(directive, "max-age=")
			ageStr = strings.TrimSpace(ageStr)

			// Parse as integer
			age, err := strconv.Atoi(ageStr)
			if err != nil || age < 0 {
				return 0
			}

			// SECURITY: Cap max-age to prevent malicious servers from forcing very long cache times
			// This prevents cache poisoning attacks where an attacker controls the metadata server
			if age > maxCacheControlAge {
				return maxCacheControlAge
			}

			return age
		}
	}
	return 0
}
