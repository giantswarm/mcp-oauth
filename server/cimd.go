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
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
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
// - MUST have a path component
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
	if u.Scheme != "https" {
		return false
	}

	// MUST have a hostname
	if u.Host == "" {
		return false
	}

	// SHOULD have a path component (but not strictly required)
	// We'll be lenient here - the spec says client IDs "typically" have paths
	return true
}

// isPrivateIP checks if an IP address is in a private/internal range
// Used for SSRF protection per draft-ietf-oauth-client-id-metadata-document-00 Section 6
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

	// Check for private IPv6 ranges
	// Unique local addresses (fc00::/7)
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}

	return false
}

// validateMetadataURL performs SSRF protection checks on a metadata URL
// Per draft-ietf-oauth-client-id-metadata-document-00 Section 6:
// "Authorization servers fetching metadata documents SHOULD consider
// Server-Side Request Forgery (SSRF) risks"
func validateMetadataURL(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// CRITICAL SECURITY: MUST be HTTPS only (no HTTP)
	if u.Scheme != "https" {
		return fmt.Errorf("client_id metadata URL must use HTTPS, got: %s", u.Scheme)
	}

	// Extract hostname for IP validation
	hostname := u.Hostname()

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}

	// CRITICAL SECURITY: Block requests to private/internal IP ranges
	// This prevents SSRF attacks against internal services
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("client_id metadata URL resolves to private/internal IP address: %s -> %s (SSRF protection)",
				hostname, ip.String())
		}
	}

	return nil
}

// fetchClientMetadata fetches and validates OAuth client metadata from an HTTPS URL
// Implements draft-ietf-oauth-client-id-metadata-document-00
//
// Security considerations per Section 6:
// - SSRF protection: blocks private/internal IP addresses
// - HTTPS only: rejects HTTP URLs
// - Timeout protection: enforces reasonable timeout
// - Size limit: prevents memory exhaustion
func (s *Server) fetchClientMetadata(ctx context.Context, clientID string) (*ClientMetadata, error) {
	// Validate URL and apply SSRF protections
	if err := validateMetadataURL(clientID); err != nil {
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
		return nil, fmt.Errorf("metadata URL validation failed: %w", err)
	}

	// Determine timeout from configuration or use default
	timeout := 10 * time.Second
	if s.Config.ClientMetadataFetchTimeout > 0 {
		timeout = s.Config.ClientMetadataFetchTimeout
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout,
		// Disable redirect following for security
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata request: %w", err)
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
		return nil, fmt.Errorf("failed to fetch metadata from %s: %w", clientID, err)
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
		return nil, fmt.Errorf("metadata fetch returned HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Check Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("metadata must be application/json, got: %s", contentType)
	}

	// Limit response size to prevent memory exhaustion (1MB max)
	limitedReader := io.LimitReader(resp.Body, 1*1024*1024)

	// Parse JSON response
	var metadata ClientMetadata
	if err := json.NewDecoder(limitedReader).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
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
		return nil, fmt.Errorf("client_id mismatch: document contains %q but was fetched from %q (security violation)",
			metadata.ClientID, clientID)
	}

	// Validate required fields
	if len(metadata.RedirectURIs) == 0 {
		return nil, fmt.Errorf("metadata must contain at least one redirect_uri")
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

	// Log successful fetch
	if s.Auditor != nil {
		s.Auditor.LogEvent(security.Event{
			Type:     "client_metadata_fetched",
			ClientID: clientID,
			Details: map[string]any{
				"client_name":    metadata.ClientName,
				"redirect_count": len(metadata.RedirectURIs),
			},
		})
	}

	s.Logger.Info("Fetched client metadata from URL",
		"client_id", clientID,
		"client_name", metadata.ClientName,
		"redirect_uris", len(metadata.RedirectURIs))

	return &metadata, nil
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
		if hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
			return false
		}
	}

	return true
}
