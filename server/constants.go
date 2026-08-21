package server

// Structured-logging and audit-detail keys used across the server package.
const (
	logKeyReason           = "reason"
	logKeyError            = "error"
	logKeySeverity         = "severity"
	logKeyAction           = "action"
	logKeyOAuthSpec        = "oauth_spec"
	logKeyValidationMethod = "validation_method"
	logKeySessionID        = "session_id"
	logKeyProvider         = "provider"
	logKeyFamilyID         = "family_id"
	logKeyExchange         = "exchange"
)

// Audit severity levels attached to security events.
const (
	severityHigh     = "high"
	severityCritical = "critical"
)

// exchangeBrokered marks audit events emitted by the brokered token-exchange
// path (details key "exchange").
const exchangeBrokered = "brokered"

// OAuth protocol parameters, JWT/OIDC claims, and token introspection fields
// (RFC 6749, RFC 7519, RFC 7662).
const (
	paramGrantType = "grant_type"
	paramClientID  = "client_id"
	paramScope     = "scope"
	paramAudience  = "audience"

	claimSub   = "sub"
	claimIss   = "iss"
	claimJTI   = "jti"
	claimEmail = "email"

	fieldActive     = "active"
	fieldTokenType  = "token_type"
	tokenTypeBearer = "Bearer"
)

// oauthSpecSection412 cites the OAuth 2.1 section that mandates revoking all
// tokens derived from a reused authorization code; attached to audit events.
const oauthSpecSection412 = "OAuth 2.1 Section 4.1.2"
