package oauth

import (
	"log/slog"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Authentication events
	AuditEventTokenIssued    AuditEventType = "token_issued"
	AuditEventTokenRefreshed AuditEventType = "token_refreshed"
	AuditEventTokenRevoked   AuditEventType = "token_revoked"
	AuditEventAuthSuccess    AuditEventType = "auth_success"
	AuditEventAuthFailure    AuditEventType = "auth_failure"
	AuditEventInvalidToken   AuditEventType = "invalid_token"
	AuditEventExpiredToken   AuditEventType = "expired_token"

	// Client registration events
	AuditEventClientRegistered AuditEventType = "client_registered"
	AuditEventClientDeleted    AuditEventType = "client_deleted"

	// Security events
	AuditEventRateLimitExceeded  AuditEventType = "rate_limit_exceeded"
	AuditEventInvalidPKCE        AuditEventType = "invalid_pkce"
	AuditEventInvalidRedirect    AuditEventType = "invalid_redirect"
	AuditEventTokenReuse         AuditEventType = "token_reuse_detected"
	AuditEventSuspiciousActivity AuditEventType = "suspicious_activity"

	// Administrative events
	AuditEventCleanupExpired AuditEventType = "cleanup_expired_tokens"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	// Timestamp when the event occurred
	Timestamp time.Time

	// EventType is the type of audit event
	EventType AuditEventType

	// UserEmail is the email of the user (hashed for privacy)
	UserEmailHash string

	// ClientID is the client identifier
	ClientID string

	// IPAddress is the source IP address (for security monitoring)
	IPAddress string

	// Success indicates if the operation succeeded
	Success bool

	// ErrorMessage contains error details if Success is false
	ErrorMessage string

	// Metadata contains additional context-specific data
	Metadata map[string]string
}

// AuditLogger provides secure audit logging for OAuth events
// All sensitive data (emails, tokens) are hashed before logging
type AuditLogger struct {
	logger *slog.Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditLogger{
		logger: logger,
	}
}

// LogEvent logs an audit event with structured logging
func (a *AuditLogger) LogEvent(event AuditEvent) {
	// Determine log level based on event type
	level := slog.LevelInfo
	if !event.Success {
		level = slog.LevelWarn
	}

	// For security events, always use warn level
	switch event.EventType {
	case AuditEventAuthFailure, AuditEventInvalidToken, AuditEventExpiredToken,
		AuditEventRateLimitExceeded, AuditEventInvalidPKCE, AuditEventInvalidRedirect,
		AuditEventTokenReuse, AuditEventSuspiciousActivity:
		level = slog.LevelWarn
	}

	// Build log attributes
	attrs := []slog.Attr{
		slog.String("event_type", string(event.EventType)),
		slog.Time("timestamp", event.Timestamp),
		slog.Bool("success", event.Success),
	}

	if event.UserEmailHash != "" {
		attrs = append(attrs, slog.String("user_email_hash", event.UserEmailHash))
	}
	if event.ClientID != "" {
		attrs = append(attrs, slog.String("client_id", event.ClientID))
	}
	if event.IPAddress != "" {
		attrs = append(attrs, slog.String("ip_address", event.IPAddress))
	}
	if event.ErrorMessage != "" {
		attrs = append(attrs, slog.String("error", event.ErrorMessage))
	}

	// Add metadata
	for key, value := range event.Metadata {
		attrs = append(attrs, slog.String("meta_"+key, value))
	}

	// Log the event
	a.logger.LogAttrs(nil, level, "audit_event", attrs...)
}

// LogTokenIssued logs when a token is issued
func (a *AuditLogger) LogTokenIssued(userEmail, clientID, ipAddress, scope string) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventTokenIssued,
		UserEmailHash: hashForLogging(userEmail),
		ClientID:      clientID,
		IPAddress:     ipAddress,
		Success:       true,
		Metadata: map[string]string{
			"scope": scope,
		},
	})
}

// LogTokenRefreshed logs when a token is refreshed
func (a *AuditLogger) LogTokenRefreshed(userEmail, clientID, ipAddress string, rotated bool) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventTokenRefreshed,
		UserEmailHash: hashForLogging(userEmail),
		ClientID:      clientID,
		IPAddress:     ipAddress,
		Success:       true,
		Metadata: map[string]string{
			"rotated": boolToString(rotated),
		},
	})
}

// LogTokenRevoked logs when a token is revoked
func (a *AuditLogger) LogTokenRevoked(userEmail, clientID, ipAddress, tokenType string) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventTokenRevoked,
		UserEmailHash: hashForLogging(userEmail),
		ClientID:      clientID,
		IPAddress:     ipAddress,
		Success:       true,
		Metadata: map[string]string{
			"token_type": tokenType,
		},
	})
}

// LogAuthFailure logs an authentication failure
func (a *AuditLogger) LogAuthFailure(userEmail, clientID, ipAddress, reason string) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventAuthFailure,
		UserEmailHash: hashForLogging(userEmail),
		ClientID:      clientID,
		IPAddress:     ipAddress,
		Success:       false,
		ErrorMessage:  reason,
	})
}

// LogRateLimitExceeded logs when rate limit is exceeded
func (a *AuditLogger) LogRateLimitExceeded(ipAddress, userEmail string) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventRateLimitExceeded,
		UserEmailHash: hashForLogging(userEmail),
		IPAddress:     ipAddress,
		Success:       false,
		ErrorMessage:  "Rate limit exceeded",
	})
}

// LogInvalidPKCE logs when PKCE validation fails
func (a *AuditLogger) LogInvalidPKCE(clientID, ipAddress, reason string) {
	a.LogEvent(AuditEvent{
		Timestamp:    time.Now(),
		EventType:    AuditEventInvalidPKCE,
		ClientID:     clientID,
		IPAddress:    ipAddress,
		Success:      false,
		ErrorMessage: reason,
	})
}

// LogClientRegistered logs when a new client is registered
func (a *AuditLogger) LogClientRegistered(clientID, clientType, ipAddress string) {
	a.LogEvent(AuditEvent{
		Timestamp: time.Now(),
		EventType: AuditEventClientRegistered,
		ClientID:  clientID,
		IPAddress: ipAddress,
		Success:   true,
		Metadata: map[string]string{
			"client_type": clientType,
		},
	})
}

// LogTokenReuse logs when refresh token reuse is detected (security event)
func (a *AuditLogger) LogTokenReuse(userEmail, ipAddress string) {
	a.LogEvent(AuditEvent{
		Timestamp:     time.Now(),
		EventType:     AuditEventTokenReuse,
		UserEmailHash: hashForLogging(userEmail),
		IPAddress:     ipAddress,
		Success:       false,
		ErrorMessage:  "Possible token theft - refresh token reuse detected",
		Metadata: map[string]string{
			"severity": "high",
			"action":   "all_tokens_revoked",
		},
	})
}
