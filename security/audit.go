// Package security provides security features for OAuth including encryption,
// rate limiting, audit logging, and secure header management.
package security

import (
	"context"
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

// LogEvent logs a security event with hashed PII. Attributes are emitted
// under a single [slog.Group] named "audit" so consumers can split-route
// audit records from operational logs in their slog.Handler.
//
// ctx is forwarded to the underlying [slog.Handler]; otelslog and similar
// trace-aware handlers use it to attach trace/span IDs to the record.
// Callers handling an HTTP request should pass r.Context(); background
// emissions should pass [context.Background].
func (a *Auditor) LogEvent(ctx context.Context, event Event) {
	if !a.enabled {
		recordAuditDrop(ctx, a, "disabled")
		return
	}

	event.Timestamp = time.Now()

	a.logger.LogAttrs(ctx, slog.LevelInfo, "security_audit",
		slog.Group("audit",
			slog.String("event_type", event.Type),
			slog.String("user_id_hash", hashForLogging(event.UserID)),
			slog.String("client_id", event.ClientID),
			slog.String("ip_address", event.IPAddress),
			slog.String("user_agent", event.UserAgent),
			slog.String("request_id", event.RequestID),
			slog.Any("details", event.Details),
			slog.Time("timestamp", event.Timestamp),
		),
	)
}

// LogTokenIssued logs when a token is issued
func (a *Auditor) LogTokenIssued(ctx context.Context, userID, clientID, ipAddress, scope string) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogTokenRefreshed(ctx context.Context, userID, clientID, ipAddress string, rotated bool) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogTokenRevoked(ctx context.Context, userID, clientID, ipAddress, tokenType string) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogAuthFailure(ctx context.Context, userID, clientID, ipAddress, reason string) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogRateLimitExceeded(ctx context.Context, ipAddress, userID string) {
	a.LogEvent(ctx, Event{
		Type:      EventRateLimitExceeded,
		UserID:    userID,
		IPAddress: ipAddress,
	})
}

// LogClientRegistrationRateLimitExceeded logs when client registration rate limit is exceeded
func (a *Auditor) LogClientRegistrationRateLimitExceeded(ctx context.Context, ipAddress string) {
	a.LogEvent(ctx, Event{
		Type:      EventClientRegistrationRateLimitExceeded,
		IPAddress: ipAddress,
		Details: map[string]any{
			"severity": "medium",
			"action":   "registration_denied",
		},
	})
}

// LogClientRegistered logs when a new client is registered
func (a *Auditor) LogClientRegistered(ctx context.Context, clientID, clientType, ipAddress string) {
	a.LogEvent(ctx, Event{
		Type:      EventClientRegistered,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"client_type": clientType,
		},
	})
}

// LogInvalidPKCE logs when PKCE validation fails
func (a *Auditor) LogInvalidPKCE(ctx context.Context, clientID, ipAddress, reason string) {
	a.LogEvent(ctx, Event{
		Type:      EventInvalidPKCE,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Details: map[string]any{
			"reason": reason,
		},
	})
}

// LogTokenReuse logs when refresh token reuse is detected (security event)
func (a *Auditor) LogTokenReuse(ctx context.Context, userID, ipAddress string) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogSuspiciousActivity(ctx context.Context, userID, clientID, ipAddress, description string) {
	a.LogEvent(ctx, Event{
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
func (a *Auditor) LogInvalidRedirect(ctx context.Context, clientID, ipAddress, uri, reason string) {
	a.LogEvent(ctx, Event{
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
