package handler

// OAuth 2.1 grant type identifiers (RFC 6749 Section 4.1 and Section 6).
const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
)

// OAuth error response fields (RFC 6749 Section 5.2). Also used as
// structured-logging keys so log lines mirror the wire format.
const (
	paramError            = "error"
	paramErrorDescription = "error_description"
)

// OIDC claim and client registration metadata field names (OpenID Connect
// Core 1.0, RFC 7591).
const (
	claimSub          = "sub"
	fieldClientType   = "client_type"
	fieldRedirectURIs = "redirect_uris"
)
