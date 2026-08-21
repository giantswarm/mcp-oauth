package server

import (
	"context"
	"strings"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// resolveScopes determines the final scopes to use for an authorization flow.
// If requestedScope is provided, it's used as-is.
// If empty, provider defaults are used, filtered by client's allowed scopes.
func (s *Server) resolveScopes(ctx context.Context, requestedScope string, client *storage.Client) string {
	// If client provided scopes, use them
	if requestedScope != "" {
		return requestedScope
	}

	// Get provider defaults
	defaultScopes := s.provider.DefaultScopes()
	if len(defaultScopes) == 0 {
		return ""
	}

	// SECURITY: Audit when default scopes are applied for forensics and compliance
	// This helps track which clients rely on provider defaults vs explicit scopes
	var resolvedScopes string
	if len(client.Scopes) == 0 {
		// Client has no restrictions, use all provider defaults
		resolvedScopes = strings.Join(defaultScopes, " ")
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventScopeDefaultsApplied,
			ClientID: client.ClientID,
			Details: map[string]any{
				logKeyProvider:      s.provider.Name(),
				"provider_defaults": defaultScopes,
				"resolved_scopes":   resolvedScopes,
				"client_restricted": false,
			},
		})
	} else {
		// Build intersection - only provider defaults that client is authorized for
		authorizedScopes := intersectScopes(defaultScopes, client.Scopes)
		resolvedScopes = strings.Join(authorizedScopes, " ")
		s.Auditor.LogEvent(ctx, security.Event{
			Type:     security.EventScopeDefaultsApplied,
			ClientID: client.ClientID,
			Details: map[string]any{
				logKeyProvider:       s.provider.Name(),
				"provider_defaults":  defaultScopes,
				"client_allowed":     client.Scopes,
				"resolved_scopes":    resolvedScopes,
				"client_restricted":  true,
				"intersection_count": len(authorizedScopes),
			},
		})
	}

	return resolvedScopes
}

// intersectScopes returns scopes that exist in both slices.
// The order is preserved from the first slice (a).
func intersectScopes(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}

	scopeSet := make(map[string]bool, len(b))
	for _, scope := range b {
		scopeSet[scope] = true
	}

	var result []string
	for _, scope := range a {
		if scopeSet[scope] {
			result = append(result, scope)
		}
	}
	return result
}
