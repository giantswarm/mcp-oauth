package security

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAuditor(t *testing.T) {
	tests := []struct {
		name    string
		logger  *slog.Logger
		enabled bool
	}{
		{
			name:    "enabled with logger",
			logger:  slog.Default(),
			enabled: true,
		},
		{
			name:    "disabled with logger",
			logger:  slog.Default(),
			enabled: false,
		},
		{
			name:    "enabled with nil logger",
			logger:  nil,
			enabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor := NewAuditor(tt.logger, tt.enabled)
			if auditor == nil {
				t.Fatal("NewAuditor() returned nil")
			}
			if auditor.enabled != tt.enabled {
				t.Errorf("enabled = %v, want %v", auditor.enabled, tt.enabled)
			}
			if auditor.logger == nil {
				t.Error("logger should not be nil")
			}
		})
	}
}

func TestAuditor_LogEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	tests := []struct {
		name    string
		enabled bool
		event   Event
		wantLog bool
	}{
		{
			name:    "enabled",
			enabled: true,
			event: Event{
				Type:      "test_event",
				UserID:    "user-123",
				ClientID:  "client-456",
				IPAddress: "192.168.1.1",
				Details:   map[string]any{"key": "value"},
			},
			wantLog: true,
		},
		{
			name:    "disabled",
			enabled: false,
			event: Event{
				Type:      "test_event",
				UserID:    "user-123",
				ClientID:  "client-456",
				IPAddress: "192.168.1.1",
			},
			wantLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			auditor := NewAuditor(logger, tt.enabled)

			auditor.LogEvent(tt.event)

			hasLog := buf.Len() > 0
			if hasLog != tt.wantLog {
				t.Errorf("LogEvent() logged = %v, want %v", hasLog, tt.wantLog)
			}

			if tt.wantLog {
				logOutput := buf.String()
				if len(logOutput) == 0 {
					t.Error("LogEvent() should have produced log output")
				}
			}
		})
	}
}

func TestAuditor_LogTokenIssued(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogTokenIssued("user-123", "client-456", "192.168.1.1", "openid email")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogTokenIssued() should have produced log output")
	}
}

func TestAuditor_LogTokenRefreshed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogTokenRefreshed("user-123", "client-456", "192.168.1.1", true)

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogTokenRefreshed() should have produced log output")
	}
}

func TestAuditor_LogTokenRevoked(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogTokenRevoked("user-123", "client-456", "192.168.1.1", "refresh_token")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogTokenRevoked() should have produced log output")
	}
}

func TestAuditor_LogAuthFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogAuthFailure("user-123", "client-456", "192.168.1.1", "invalid credentials")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogAuthFailure() should have produced log output")
	}
}

func TestAuditor_LogRateLimitExceeded(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogRateLimitExceeded("192.168.1.1", "user-123")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogRateLimitExceeded() should have produced log output")
	}
}

func TestAuditor_LogClientRegistered(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogClientRegistered("client-123", "confidential", "192.168.1.1")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogClientRegistered() should have produced log output")
	}
}

func TestAuditor_LogInvalidPKCE(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogInvalidPKCE("client-123", "192.168.1.1", "challenge mismatch")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogInvalidPKCE() should have produced log output")
	}
}

func TestAuditor_LogTokenReuse(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogTokenReuse("user-123", "192.168.1.1")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogTokenReuse() should have produced log output")
	}
}

func TestAuditor_LogSuspiciousActivity(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogSuspiciousActivity("user-123", "client-456", "192.168.1.1", "unusual access pattern")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogSuspiciousActivity() should have produced log output")
	}
}

func TestAuditor_LogInvalidRedirect(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditor := NewAuditor(logger, true)

	auditor.LogInvalidRedirect("client-123", "192.168.1.1", "https://evil.com", "not registered")

	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Error("LogInvalidRedirect() should have produced log output")
	}
}

func Test_hashForLogging(t *testing.T) {
	tests := []struct {
		name      string
		sensitive string
		want      string
	}{
		{
			name:      "empty string",
			sensitive: "",
			want:      "<empty>",
		},
		{
			name:      "non-empty string",
			sensitive: "sensitive-data",
			want:      "", // We just verify it's not empty and not the original
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashForLogging(tt.sensitive)
			if tt.sensitive == "" {
				if got != tt.want {
					t.Errorf("hashForLogging() = %q, want %q", got, tt.want)
				}
			} else {
				// Should not be empty and should not be the original
				if got == "" {
					t.Error("hashForLogging() returned empty string for non-empty input")
				}
				if got == tt.sensitive {
					t.Error("hashForLogging() returned unhashed sensitive data")
				}
				// Should be 16 characters (truncated hash)
				if len(got) != 16 {
					t.Errorf("hashForLogging() returned hash of length %d, want 16", len(got))
				}
			}
		})
	}
}

func Test_hashForLogging_Deterministic(t *testing.T) {
	input := "test-data"
	hash1 := hashForLogging(input)
	hash2 := hashForLogging(input)

	if hash1 != hash2 {
		t.Error("hashForLogging() should return same hash for same input")
	}
}

func Test_hashForLogging_Different(t *testing.T) {
	hash1 := hashForLogging("data1")
	hash2 := hashForLogging("data2")

	if hash1 == hash2 {
		t.Error("hashForLogging() should return different hashes for different inputs")
	}
}

// TestAuditor_LogEvent_EmitsAuditGroup asserts that LogEvent emits at INFO
// and bundles every attribute under a single "audit" group so consumers can
// route audit records separately from operational logs.
func TestAuditor_LogEvent_EmitsAuditGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor := NewAuditor(logger, true)

	auditor.LogEvent(Event{
		Type:      "test_event",
		UserID:    "user-123",
		ClientID:  "client-456",
		IPAddress: "192.168.1.1",
		Details:   map[string]any{"key": "value"},
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	require.Equal(t, "INFO", payload["level"])
	require.Equal(t, "security_audit", payload["msg"])

	audit, ok := payload["audit"].(map[string]any)
	require.True(t, ok, "expected audit group in payload, got %v", payload)
	require.Equal(t, "test_event", audit["event_type"])
	require.Equal(t, "client-456", audit["client_id"])
	require.Equal(t, "192.168.1.1", audit["ip_address"])
	require.NotEmpty(t, audit["user_id_hash"], "user_id must be hashed, not raw")
	require.NotEqual(t, "user-123", audit["user_id_hash"], "user_id must not be emitted as raw")

	details, ok := audit["details"].(map[string]any)
	require.True(t, ok, "expected details map under audit group, got %v", audit)
	require.Equal(t, "value", details["key"])
}
