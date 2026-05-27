// Package constants defines values shared between the root package and
// server/ to break the circular import that would arise from server importing
// the root (which already imports server for its type aliases).
package constants

// OAuth 2.0 / 2.1 error codes (RFC 6749 §4.1.2.1, §5.2).
const (
	ErrorCodeInvalidClient      = "invalid_client"
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeInvalidRedirectURI = "invalid_redirect_uri"
	ErrorCodeInvalidScope       = "invalid_scope"
	ErrorCodeInvalidGrant       = "invalid_grant"
	OAuthSpecVersion            = "OAuth 2.1"
)

// PKCE validation bounds (RFC 7636 §4.1).
const (
	MinCodeVerifierLength = 43
	MaxCodeVerifierLength = 128
	PKCEMethodS256        = "S256"
	PKCEMethodPlain       = "plain"
)

// Resource parameter validation (RFC 8707).
const MaxResourceLength = 2048

// Redirect URI scheme lists. These are vars (not consts) because Go does not
// allow slice literals as constants.
var (
	// AllowedHTTPSchemes contains the only two schemes permitted for http(s) redirect URIs.
	AllowedHTTPSchemes = []string{"http", "https"}

	// DefaultBlockedRedirectSchemes is the canonical list of schemes that must
	// never appear in redirect URIs. Covers script-injection vectors, local
	// filesystem access, proprietary Windows app schemes, and legacy protocols.
	DefaultBlockedRedirectSchemes = []string{
		"javascript", "data", "file", "vbscript", "about", "ftp",
		"blob", "ms-appx", "ms-appx-web",
	}

	// DefaultRFC3986SchemePattern is the regex that validates custom URI schemes
	// (RFC 3986 §3.1).
	DefaultRFC3986SchemePattern = []string{"^[a-z][a-z0-9+.-]*$"}
)
