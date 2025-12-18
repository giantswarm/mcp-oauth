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

	"github.com/giantswarm/mcp-oauth/internal/util"
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
//
// This delegates to the shared util.IsPrivateOrInternal for DRY.
// The utility checks for loopback, link-local, private, and unspecified addresses.
func isPrivateIP(ip net.IP) bool {
	return util.IsPrivateOrInternal(ip)
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
func createSSRFProtectedTransport(_ context.Context) *http.Transport {
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
	fetchStart := time.Now()

	sanitizedURL, err := validateAndSanitizeMetadataURL(clientID)
	if err != nil {
		s.recordCIMDFetchMetric(ctx, "blocked", fetchStart)
		s.logMetadataFetchEvent("client_metadata_fetch_blocked", clientID, map[string]any{
			"reason": err.Error(),
			"ssrf":   "protected",
		})
		return nil, 0, fmt.Errorf("metadata URL validation failed: %w", err)
	}

	timeout := s.calculateFetchTimeout(ctx)
	client := s.createMetadataHTTPClient(ctx, timeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sanitizedURL, nil)
	if err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		return nil, 0, fmt.Errorf("failed to create metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcp-oauth")

	resp, err := client.Do(req)
	if err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		s.logMetadataFetchEvent("client_metadata_fetch_failed", clientID, map[string]any{
			"error": err.Error(),
		})
		return nil, 0, fmt.Errorf("failed to fetch metadata from %s: %w", clientID, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			s.Logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		s.logMetadataFetchEvent("client_metadata_fetch_failed", clientID, map[string]any{
			"status_code": resp.StatusCode,
			"status":      resp.Status,
		})
		return nil, 0, fmt.Errorf("metadata fetch returned HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// SECURITY: Strict Content-Type validation
	if err := validateResponseContentType(resp); err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		return nil, 0, err
	}

	// SECURITY: Read and validate response body with size limit
	const maxMetadataSize int64 = 1 * 1024 * 1024 // 1MB
	bodyBytes, err := readAndValidateResponseBody(resp, maxMetadataSize)
	if err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		return nil, 0, err
	}

	// Parse JSON response
	var metadata ClientMetadata
	if err := json.Unmarshal(bodyBytes, &metadata); err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		return nil, 0, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	// CRITICAL SECURITY: Validate that client_id in document matches the URL
	if metadata.ClientID != clientID {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		s.logMetadataFetchEvent("client_metadata_id_mismatch", clientID, map[string]any{
			"document_client_id": metadata.ClientID,
			"url_client_id":      clientID,
			"severity":           "high",
		})
		return nil, 0, fmt.Errorf("client_id mismatch: document contains %q but was fetched from %q (security violation)",
			metadata.ClientID, clientID)
	}

	// Validate redirect URIs
	if err := validateClientMetadataRedirectURIs(metadata.RedirectURIs); err != nil {
		s.recordCIMDFetchMetric(ctx, "error", fetchStart)
		return nil, 0, err
	}

	// Set defaults per OAuth 2.0 spec if not specified
	setClientMetadataDefaults(&metadata)

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
	s.logMetadataFetchEvent("client_metadata_fetched", clientID, map[string]any{
		"client_name":     metadata.ClientName,
		"redirect_count":  len(metadata.RedirectURIs),
		"document_size":   len(bodyBytes),
		"cache_suggested": suggestedTTL > 0,
	})
	s.recordCIMDFetchMetric(ctx, "success", fetchStart)

	s.Logger.Info("Fetched client metadata from URL",
		"client_id", clientID,
		"client_name", metadata.ClientName,
		"redirect_uris", len(metadata.RedirectURIs),
		"size_bytes", len(bodyBytes),
		"cache_ttl", suggestedTTL)

	return &metadata, suggestedTTL, nil
}

// validateResponseContentType validates the Content-Type header for JSON responses
// Returns an error if the content type is not application/json with valid charset
func validateResponseContentType(resp *http.Response) error {
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return fmt.Errorf("metadata response missing Content-Type header")
	}

	// Parse media type and parameters
	parts := strings.Split(contentType, ";")
	mediaType := strings.ToLower(strings.TrimSpace(parts[0]))
	if mediaType != "application/json" {
		return fmt.Errorf("metadata must be application/json, got: %s", contentType)
	}

	// Validate charset parameter if present (must be UTF-8)
	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if kv := strings.SplitN(param, "=", 2); len(kv) == 2 {
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.Trim(strings.ToLower(strings.TrimSpace(kv[1])), "\" ")

			if key == "charset" && value != "utf-8" && value != "utf8" {
				return fmt.Errorf("unsupported charset: %s (only UTF-8 is supported for JSON)", value)
			}
		}
	}

	return nil
}

// readAndValidateResponseBody reads the response body with size validation
// Returns the body bytes or an error if the body exceeds the size limit
func readAndValidateResponseBody(resp *http.Response, maxSize int64) ([]byte, error) {
	// Check declared size before reading body
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		size, parseErr := strconv.ParseInt(contentLength, 10, 64)
		if parseErr == nil && size > maxSize {
			return nil, fmt.Errorf("metadata Content-Length (%d bytes) exceeds maximum size of %d bytes", size, maxSize)
		}
	}

	// Read entire response body with size limit
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if response was truncated
	if int64(len(bodyBytes)) > maxSize {
		return nil, fmt.Errorf("metadata document exceeds maximum size of %d bytes", maxSize)
	}

	return bodyBytes, nil
}

// validateClientMetadataRedirectURIs validates redirect URIs in client metadata
// Ensures URIs use valid schemes and HTTP is only used for localhost
func validateClientMetadataRedirectURIs(redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return fmt.Errorf("metadata must contain at least one redirect_uri")
	}

	for _, uri := range redirectURIs {
		u, parseErr := url.Parse(uri)
		if parseErr != nil {
			return fmt.Errorf("invalid redirect_uri %q: %w", uri, parseErr)
		}

		// Only allow http and https schemes
		if u.Scheme != SchemeHTTPS && u.Scheme != SchemeHTTP {
			return fmt.Errorf("redirect_uri must use http or https scheme, got %s: %s", u.Scheme, uri)
		}

		// OAuth 2.1: HTTP redirect URIs only allowed for localhost
		if u.Scheme == SchemeHTTP {
			hostname := u.Hostname()
			if hostname != localhostHostname && hostname != localhostIPv4Loopback && hostname != localhostIPv6Loopback {
				return fmt.Errorf("http redirect_uri only allowed for localhost, got %s: %s", hostname, uri)
			}
		}
	}

	return nil
}

// setClientMetadataDefaults sets default values for optional metadata fields
func setClientMetadataDefaults(metadata *ClientMetadata) {
	if len(metadata.GrantTypes) == 0 {
		metadata.GrantTypes = []string{"authorization_code"}
	}
	if len(metadata.ResponseTypes) == 0 {
		metadata.ResponseTypes = []string{"code"}
	}
	if metadata.TokenEndpointAuthMethod == "" {
		metadata.TokenEndpointAuthMethod = "none" // Default for public clients
	}
}

// calculateFetchTimeout determines the timeout to use for metadata fetch
// Returns the configured timeout or a shorter one if context deadline is sooner
func (s *Server) calculateFetchTimeout(ctx context.Context) time.Duration {
	timeout := 10 * time.Second
	if s.Config.ClientMetadataFetchTimeout > 0 {
		timeout = s.Config.ClientMetadataFetchTimeout
	}

	if deadline, ok := ctx.Deadline(); ok {
		timeUntilDeadline := time.Until(deadline)
		if timeUntilDeadline > 0 && timeUntilDeadline < timeout {
			s.Logger.Debug("Using context deadline for metadata fetch",
				"original_timeout", s.Config.ClientMetadataFetchTimeout,
				"adjusted_timeout", timeUntilDeadline,
				"reason", "context deadline")
			return timeUntilDeadline
		}
	}

	return timeout
}

// logMetadataFetchEvent logs an audit event for metadata fetch operations
func (s *Server) logMetadataFetchEvent(eventType, clientID string, details map[string]any) {
	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type:     eventType,
			ClientID: clientID,
			Details:  details,
		})
	}
}

// createMetadataHTTPClient creates an HTTP client configured for metadata fetching
func (s *Server) createMetadataHTTPClient(ctx context.Context, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: createSSRFProtectedTransport(ctx),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// recordCIMDFetchMetric records CIMD fetch metrics if instrumentation is enabled
func (s *Server) recordCIMDFetchMetric(ctx context.Context, result string, fetchStart time.Time) {
	if s.Instrumentation != nil {
		// Use Seconds() * 1000 for sub-millisecond precision (consistent with handler.go)
		durationMs := time.Since(fetchStart).Seconds() * 1000
		s.Instrumentation.Metrics().RecordCIMDFetch(ctx, result, durationMs)
	}
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
