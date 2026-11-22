package helpers

import (
	"net/url"
	"strings"
)

// ProtectedResourceMetadataURL inserts the well-known suffix before the
// resource's path, as required by RFC 9728 section 3.1.
func ProtectedResourceMetadataURL(resource string) string {
	parsed, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	parsed.Path = "/.well-known/oauth-protected-resource" + strings.TrimRight(parsed.Path, "/")
	parsed.RawPath, parsed.RawQuery, parsed.Fragment = "", "", ""
	return parsed.String()
}
