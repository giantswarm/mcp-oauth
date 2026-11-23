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
	resourcePath := parsed.EscapedPath()
	if resourcePath == "/" {
		resourcePath = ""
	}
	metadataPath := "/.well-known/oauth-protected-resource" + resourcePath
	parsed.Path, err = url.PathUnescape(metadataPath)
	if err != nil {
		return ""
	}
	parsed.RawPath = metadataPath
	parsed.Fragment, parsed.RawFragment = "", ""
	return parsed.String()
}

// CanonicalEscapedPath normalizes percent-encoding within path segments without
// turning an encoded slash into a path separator. It is a routing key, not a
// replacement for the resource identifier.
func CanonicalEscapedPath(resource *url.URL) string {
	segments := strings.Split(resource.EscapedPath(), "/")
	for index, segment := range segments {
		// EscapedPath guarantees valid percent-encoding.
		decoded, _ := url.PathUnescape(segment)
		segments[index] = url.PathEscape(decoded)
	}
	return strings.Join(segments, "/")
}
