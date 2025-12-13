package security

// Event type constants for security audit logging.
// These constants ensure consistency across the codebase and prevent typos
// when logging security-relevant events.
const (
	// Token lifecycle events

	// EventTokenIssued is logged when a new access token is issued to a client
	EventTokenIssued = "token_issued"

	// EventTokenRefreshed is logged when an access token is refreshed using a refresh token
	EventTokenRefreshed = "token_refreshed"

	// EventTokenProactivelyRefreshed is logged when a token is proactively refreshed before expiry
	EventTokenProactivelyRefreshed = "token_proactively_refreshed"

	// EventTokenRevoked is logged when a token is revoked by the user or client
	EventTokenRevoked = "token_revoked"

	// EventAllTokensRevoked is logged when all tokens for a user are revoked
	EventAllTokensRevoked = "all_tokens_revoked" //nolint:gosec // G101: False positive - this is an event type name, not a credential

	// Authorization flow events

	// EventAuthorizationFlowStarted is logged when an authorization flow is initiated
	EventAuthorizationFlowStarted = "authorization_flow_started"

	// EventAuthorizationCodeIssued is logged when an authorization code is issued
	EventAuthorizationCodeIssued = "authorization_code_issued"

	// EventAuthorizationCodeReuseDetected is logged when an authorization code is reused (attack)
	EventAuthorizationCodeReuseDetected = "authorization_code_reuse_detected"

	// Client registration events

	// EventClientRegistered is logged when a new OAuth client is registered
	EventClientRegistered = "client_registered"

	// EventClientRegisteredViaTrustedScheme is logged when a client is registered without a token
	// because it uses only trusted custom URI schemes (e.g., cursor://, vscode://).
	// This enables compatibility with MCP clients that don't support registration tokens.
	EventClientRegisteredViaTrustedScheme = "client_registered_via_trusted_scheme"

	// EventClientRegistrationRejected is logged when client registration is rejected for security reasons
	EventClientRegistrationRejected = "client_registration_rejected"

	// EventClientRegistrationRateLimitExceeded is logged when client registration rate limit is exceeded
	EventClientRegistrationRateLimitExceeded = "client_registration_rate_limit_exceeded"

	// Security violation events

	// EventAuthFailure is logged when authentication fails (wrong credentials, etc.)
	EventAuthFailure = "auth_failure"

	// EventRateLimitExceeded is logged when a rate limit is exceeded
	EventRateLimitExceeded = "rate_limit_exceeded"

	// EventInvalidPKCE is logged when PKCE validation fails
	EventInvalidPKCE = "invalid_pkce"

	// EventPKCEValidationFailed is logged when PKCE code_verifier validation fails
	EventPKCEValidationFailed = "pkce_validation_failed"

	// EventPKCERequiredForPublicClient is logged when a public client attempts flow without PKCE
	EventPKCERequiredForPublicClient = "pkce_required_for_public_client"

	// EventInsecurePublicClientWithoutPKCE is logged when insecure flow is attempted
	EventInsecurePublicClientWithoutPKCE = "insecure_public_client_without_pkce"

	// EventTokenReuseDetected is logged when refresh token reuse is detected (theft)
	EventTokenReuseDetected = "token_reuse_detected" //nolint:gosec // G101: False positive - this is an event type name, not a credential

	// EventRefreshTokenReuseDetected is logged when a refresh token is reused in the same family
	EventRefreshTokenReuseDetected = "refresh_token_reuse_detected"

	// EventRevokedTokenFamilyReuseAttempt is logged when a revoked token family is accessed
	EventRevokedTokenFamilyReuseAttempt = "revoked_token_family_reuse_attempt"

	// EventSuspiciousActivity is logged for general suspicious behavior
	EventSuspiciousActivity = "suspicious_activity"

	// EventInvalidRedirect is logged when an invalid redirect URI is used
	EventInvalidRedirect = "invalid_redirect"

	// EventScopeEscalationAttempt is logged when a client tries to escalate scopes
	EventScopeEscalationAttempt = "scope_escalation_attempt"

	// EventScopeDefaultsApplied is logged when provider default scopes are used (forensics/compliance)
	EventScopeDefaultsApplied = "scope_defaults_applied"

	// EventResourceMismatch is logged when resource parameter doesn't match (RFC 8707)
	EventResourceMismatch = "resource_mismatch"

	// Provider-related events

	// EventInvalidProviderCallback is logged when provider callback validation fails
	EventInvalidProviderCallback = "invalid_provider_callback"

	// EventProviderStateMismatch is logged when provider state parameter doesn't match
	EventProviderStateMismatch = "provider_state_mismatch"

	// EventProviderCodeExchangeFailed is logged when code exchange with provider fails (PKCE, etc.)
	EventProviderCodeExchangeFailed = "provider_code_exchange_failed"

	// EventProviderRevocationThresholdExceeded is logged when provider revocation partial failure occurs
	EventProviderRevocationThresholdExceeded = "provider_revocation_threshold_exceeded"

	// EventProviderRevocationCompleteFailure is logged when all provider revocation attempts fail
	EventProviderRevocationCompleteFailure = "provider_revocation_complete_failure"

	// EventTokenRevocationNotSupported is logged when provider doesn't support token revocation
	EventTokenRevocationNotSupported = "token_revocation_not_supported"

	// Operational events

	// EventProactiveRefreshFailed is logged when proactive token refresh fails
	EventProactiveRefreshFailed = "proactive_refresh_failed"
)
