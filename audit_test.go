package oauth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestAuditLogger_LogTokenIssued(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	auditLogger.LogTokenIssued("user@example.com", "client123", "192.168.1.1", "scope1 scope2")

	// Parse the log output
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	// Verify event type
	if logEntry["event_type"] != string(AuditEventTokenIssued) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventTokenIssued)
	}

	// Verify success
	if logEntry["success"] != true {
		t.Error("success should be true")
	}

	// Verify user email is hashed
	userHash := logEntry["user_email_hash"].(string)
	if userHash == "" || userHash == "user@example.com" {
		t.Error("user_email_hash should be hashed, not plaintext")
	}

	// Verify client ID is present
	if logEntry["client_id"] != "client123" {
		t.Errorf("client_id = %v, want client123", logEntry["client_id"])
	}

	// Verify IP address
	if logEntry["ip_address"] != "192.168.1.1" {
		t.Errorf("ip_address = %v, want 192.168.1.1", logEntry["ip_address"])
	}

	// Verify metadata
	if logEntry["meta_scope"] != "scope1 scope2" {
		t.Errorf("meta_scope = %v, want 'scope1 scope2'", logEntry["meta_scope"])
	}
}

func TestAuditLogger_LogAuthFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	auditLogger.LogAuthFailure("user@example.com", "client123", "192.168.1.1", "Invalid credentials")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	// Verify event type
	if logEntry["event_type"] != string(AuditEventAuthFailure) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventAuthFailure)
	}

	// Verify success is false
	if logEntry["success"] != false {
		t.Error("success should be false for auth failure")
	}

	// Verify error message
	if logEntry["error"] != "Invalid credentials" {
		t.Errorf("error = %v, want 'Invalid credentials'", logEntry["error"])
	}

	// Verify log level (should be WARN for failures)
	if logEntry["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", logEntry["level"])
	}
}

func TestAuditLogger_LogRateLimitExceeded(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	auditLogger.LogRateLimitExceeded("192.168.1.1", "user@example.com")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["event_type"] != string(AuditEventRateLimitExceeded) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventRateLimitExceeded)
	}

	// Should be WARN level for security events
	if logEntry["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", logEntry["level"])
	}
}

func TestAuditLogger_LogTokenReuse(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	auditLogger.LogTokenReuse("user@example.com", "192.168.1.1")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	// Token reuse is a critical security event
	if logEntry["event_type"] != string(AuditEventTokenReuse) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventTokenReuse)
	}

	// Should have high severity metadata
	if logEntry["meta_severity"] != "high" {
		t.Errorf("meta_severity = %v, want high", logEntry["meta_severity"])
	}

	// Should indicate action taken
	if logEntry["meta_action"] != "all_tokens_revoked" {
		t.Errorf("meta_action = %v, want all_tokens_revoked", logEntry["meta_action"])
	}
}

func TestAuditLogger_LogClientRegistered(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	auditLogger.LogClientRegistered("client123", "public", "192.168.1.1")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["event_type"] != string(AuditEventClientRegistered) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventClientRegistered)
	}

	if logEntry["meta_client_type"] != "public" {
		t.Errorf("meta_client_type = %v, want public", logEntry["meta_client_type"])
	}
}

func TestHashSensitiveData(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"email", "user@example.com"},
		{"same email", "user@example.com"},
		{"different email", "admin@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashForLogging(tt.input)

			if tt.input == "" {
				if hash != "" {
					t.Errorf("hashForLogging('') = %q, want ''", hash)
				}
				return
			}

			// Hash should be consistent
			hash2 := hashForLogging(tt.input)
			if hash != hash2 {
				t.Error("hashForLogging is not consistent for same input")
			}

			// Hash should be 16 chars (truncated)
			if len(hash) != 16 {
				t.Errorf("hash length = %d, want 16", len(hash))
			}

			// Hash should not contain original data
			if strings.Contains(hash, tt.input) {
				t.Error("hash contains original data (not properly hashed)")
			}

			// Hash should be hex-encoded
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("hash contains non-hex character: %c", c)
				}
			}
		})
	}

	// Test that different inputs produce different hashes
	hash1 := hashForLogging("user@example.com")
	hash2 := hashForLogging("admin@example.com")
	if hash1 == hash2 {
		t.Error("Different inputs produced same hash")
	}
}

func TestAuditLogger_NoSensitiveDataInLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	sensitiveEmail := "topsecret@company.com"
	sensitiveToken := "super_secret_token_12345"

	// Log various events with sensitive data
	auditLogger.LogTokenIssued(sensitiveEmail, "client1", "1.2.3.4", "scope1")
	auditLogger.LogAuthFailure(sensitiveEmail, "client2", "1.2.3.5", "bad password")
	auditLogger.LogTokenRefreshed(sensitiveEmail, "client3", "1.2.3.6", true)

	logOutput := buf.String()

	// Verify no sensitive data in plaintext
	if strings.Contains(logOutput, sensitiveEmail) {
		t.Error("Log contains plaintext email address - security violation!")
	}

	if strings.Contains(logOutput, sensitiveToken) {
		t.Error("Log contains plaintext token - security violation!")
	}

	// Verify hashes are present
	expectedHash := hashForLogging(sensitiveEmail)
	if !strings.Contains(logOutput, expectedHash) {
		t.Error("Log should contain hashed email, but doesn't")
	}
}

func TestAuditEvent_AllFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLogger := NewAuditLogger(logger)

	event := AuditEvent{
		EventType:     AuditEventTokenRevoked,
		UserEmailHash: "hash123",
		ClientID:      "client456",
		IPAddress:     "10.0.0.1",
		Success:       true,
		ErrorMessage:  "",
		Metadata: map[string]string{
			"token_type": "refresh_token",
			"reason":     "user_request",
		},
	}

	auditLogger.LogEvent(event)

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	// Verify all fields are logged
	if logEntry["event_type"] != string(AuditEventTokenRevoked) {
		t.Errorf("event_type = %v, want %v", logEntry["event_type"], AuditEventTokenRevoked)
	}

	if logEntry["user_email_hash"] != "hash123" {
		t.Errorf("user_email_hash = %v, want hash123", logEntry["user_email_hash"])
	}

	if logEntry["client_id"] != "client456" {
		t.Errorf("client_id = %v, want client456", logEntry["client_id"])
	}

	if logEntry["ip_address"] != "10.0.0.1" {
		t.Errorf("ip_address = %v, want 10.0.0.1", logEntry["ip_address"])
	}

	if logEntry["meta_token_type"] != "refresh_token" {
		t.Errorf("meta_token_type = %v, want refresh_token", logEntry["meta_token_type"])
	}

	if logEntry["meta_reason"] != "user_request" {
		t.Errorf("meta_reason = %v, want user_request", logEntry["meta_reason"])
	}
}
