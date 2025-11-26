// Package security provides security features for OAuth including encryption,
// rate limiting, audit logging, and secure header management.
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"
)

// Auditor handles security event logging with PII protection.
type Auditor struct {
	logger  *slog.Logger
	enabled bool
}

// NewAuditor creates a new security auditor
func NewAuditor(logger *slog.Logger, enabled bool) *Auditor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Auditor{
		logger:  logger,
		enabled: enabled,
	}
}

// Event represents a security audit event
type Event struct {
	Type      string
	UserID    string
	ClientID  string
	IPAddress string
	UserAgent string // User-Agent header for detecting automated attacks
	RequestID string // Unique request ID for correlating log entries
	Details   map[string]any
	Timestamp time.Time
}

// LogEvent logs a security event with hashed PII
func (a *Auditor) LogEvent(event Event) {
	if !a.enabled {
		return
	}

	event.Timestamp = time.Now()

	a.logger.Info("security_audit",
		"event_type", event.Type,
		"user_id_hash", hashForLogging(event.UserID),
		"client_id", event.ClientID,
		"ip_address", event.IPAddress,
		"user_agent", event.UserAgent,
		"request_id", event.RequestID,
		"details", event.Details,
		"timestamp", event.Timestamp,
	)
}

// LogTokenIssued logs when a token is issued
func (a *Auditor) LogTokenIssued(userID, clientID, ipAddress, scope string) {
	a.LogEvent(Event{
		Type:      EventTokenIssued,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"scope": scope,
		},
	})
}

// LogTokenRefreshed logs when a token is refreshed
func (a *Auditor) LogTokenRefreshed(userID, clientID, ipAddress string, rotated bool) {
	a.LogEvent(Event{
		Type:      EventTokenRefreshed,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"rotated": rotated,
		},
	})
}

// LogTokenRevoked logs when a token is revoked
func (a *Auditor) LogTokenRevoked(userID, clientID, ipAddress, tokenType string) {
	a.LogEvent(Event{
		Type:      EventTokenRevoked,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"token_type": tokenType,
		},
	})
}

// LogAuthFailure logs an authentication failure
func (a *Auditor) LogAuthFailure(userID, clientID, ipAddress, reason string) {
	a.LogEvent(Event{
		Type:      EventAuthFailure,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"reason": reason,
		},
	})
}

// LogRateLimitExceeded logs a rate limit violation
func (a *Auditor) LogRateLimitExceeded(ipAddress, userID string) {
	a.LogEvent(Event{
		Type:      EventRateLimitExceeded,
		UserID:    userID,
		IPAddress: ipAddress,
	})
}

// LogClientRegistrationRateLimitExceeded logs when client registration rate limit is exceeded
func (a *Auditor) LogClientRegistrationRateLimitExceeded(ipAddress string) {
	a.LogEvent(Event{
		Type:      EventClientRegistrationRateLimitExceeded,
		IPAddress: ipAddress,
		Details: map[string]any{
			"severity": "medium",
			"action":   "registration_denied",
		},
	})
}

// LogClientRegistered logs when a new client is registered
func (a *Auditor) LogClientRegistered(clientID, clientType, ipAddress string) {
	a.LogEvent(Event{
		Type:      EventClientRegistered,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"client_type": clientType,
		},
	})
}

// LogInvalidPKCE logs when PKCE validation fails
func (a *Auditor) LogInvalidPKCE(clientID, ipAddress, reason string) {
	a.LogEvent(Event{
		Type:      EventInvalidPKCE,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"reason": reason,
		},
	})
}

// LogTokenReuse logs when refresh token reuse is detected (security event)
func (a *Auditor) LogTokenReuse(userID, ipAddress string) {
	a.LogEvent(Event{
		Type:      EventTokenReuseDetected,
		UserID:    userID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"severity": "critical",
			"action":   "all_tokens_revoked",
		},
	})
}

// LogSuspiciousActivity logs suspicious activity
func (a *Auditor) LogSuspiciousActivity(userID, clientID, ipAddress, description string) {
	a.LogEvent(Event{
		Type:      EventSuspiciousActivity,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"description": description,
		},
	})
}

// LogInvalidRedirect logs invalid redirect URI attempts
func (a *Auditor) LogInvalidRedirect(clientID, ipAddress, uri, reason string) {
	a.LogEvent(Event{
		Type:      EventInvalidRedirect,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"uri":    uri,
			"reason": reason,
		},
	})
}

// hashForLogging creates a SHA256 hash of sensitive data for logging
func hashForLogging(sensitive string) string {
	if sensitive == "" {
		return "<empty>"
	}
	hash := sha256.Sum256([]byte(sensitive))
	return hex.EncodeToString(hash[:])[:16]
}
