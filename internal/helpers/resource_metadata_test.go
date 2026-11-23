package helpers

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtectedResourceMetadataURL(t *testing.T) {
	for _, testCase := range []struct {
		resource string
		metadata string
	}{
		{"https://example.com", "https://example.com/.well-known/oauth-protected-resource"},
		{"https://example.com/", "https://example.com/.well-known/oauth-protected-resource"},
		{"https://example.com/mcp/", "https://example.com/.well-known/oauth-protected-resource/mcp/"},
		{"https://example.com/mcp%2Ffiles", "https://example.com/.well-known/oauth-protected-resource/mcp%2Ffiles"},
		{"https://example.com/%7Bid%7D", "https://example.com/.well-known/oauth-protected-resource/%7Bid%7D"},
		{"https://example.com/mcp?tenant=one", "https://example.com/.well-known/oauth-protected-resource/mcp?tenant=one"},
		{"https://example.com/mcp?", "https://example.com/.well-known/oauth-protected-resource/mcp?"},
		{"https://example.com/%zz", ""},
	} {
		t.Run(testCase.resource, func(t *testing.T) {
			require.Equal(t, testCase.metadata, ProtectedResourceMetadataURL(testCase.resource))
		})
	}
}

func TestCanonicalEscapedPath(t *testing.T) {
	for _, testCase := range []struct {
		resource string
		path     string
	}{
		{"https://example.com/a%70i", "/api"},
		{"https://example.com/mcp%2ffiles", "/mcp%2Ffiles"},
		{"https://example.com/mcp/files", "/mcp/files"},
		{"https://example.com/%7bid%7d/", "/%7Bid%7D/"},
	} {
		t.Run(testCase.resource, func(t *testing.T) {
			resource, err := url.Parse(testCase.resource)
			require.NoError(t, err)
			require.Equal(t, testCase.path, CanonicalEscapedPath(resource))
		})
	}
}
