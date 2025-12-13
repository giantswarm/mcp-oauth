package instrumentation

import (
	"context"
	"testing"
)

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test recording various HTTP requests
	tests := []struct {
		name       string
		method     string
		endpoint   string
		statusCode int
		durationMs float64
	}{
		{"successful GET", "GET", "/oauth/authorize", 200, 123.45},
		{"successful POST", "POST", "/oauth/token", 200, 234.56},
		{"bad request", "POST", "/oauth/token", 400, 45.67},
		{"server error", "GET", "/oauth/callback", 500, 567.89},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			metrics.RecordHTTPRequest(ctx, tt.method, tt.endpoint, tt.statusCode, tt.durationMs)
		})
	}
}

func TestMetrics_RecordAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test authorization flow metrics
	metrics.RecordAuthorizationStarted(ctx, "test-client-1")
	metrics.RecordAuthorizationStarted(ctx, "test-client-2")

	metrics.RecordCallbackProcessed(ctx, "test-client-1", true)
	metrics.RecordCallbackProcessed(ctx, "test-client-2", false)

	metrics.RecordCodeExchange(ctx, "test-client-1", "S256")
	metrics.RecordCodeExchange(ctx, "test-client-2", "plain")

	metrics.RecordTokenRefresh(ctx, "test-client-1", true)
	metrics.RecordTokenRefresh(ctx, "test-client-2", false)

	metrics.RecordTokenRevocation(ctx, "test-client-1")

	metrics.RecordClientRegistration(ctx, "public")
	metrics.RecordClientRegistration(ctx, "confidential")

	// All should complete without panic
}

func TestMetrics_RecordSecurityEvents(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test security metrics
	metrics.RecordRateLimitExceeded(ctx, "ip")
	metrics.RecordRateLimitExceeded(ctx, "user")
	metrics.RecordRateLimitExceeded(ctx, "client_registration")

	metrics.RecordPKCEValidationFailed(ctx, "S256")
	metrics.RecordPKCEValidationFailed(ctx, "plain")

	metrics.RecordCodeReuseDetected(ctx)
	metrics.RecordCodeReuseDetected(ctx)

	metrics.RecordTokenReuseDetected(ctx)

	// Test redirect URI security rejection metrics
	metrics.RecordRedirectURISecurityRejected(ctx, "blocked_scheme", "registration")
	metrics.RecordRedirectURISecurityRejected(ctx, "private_ip", "registration")
	metrics.RecordRedirectURISecurityRejected(ctx, "link_local", "registration")
	metrics.RecordRedirectURISecurityRejected(ctx, "dns_resolves_to_private_ip", "authorization")
	metrics.RecordRedirectURISecurityRejected(ctx, "http_not_allowed", "registration")

	// All should complete without panic
}

func TestMetrics_RecordStorageOperations(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test storage metrics
	metrics.RecordStorageOperation(ctx, "save_token", "success", 12.34)
	metrics.RecordStorageOperation(ctx, "get_token", "success", 5.67)
	metrics.RecordStorageOperation(ctx, "delete_token", "success", 3.45)
	metrics.RecordStorageOperation(ctx, "save_token", "error", 23.45)

	// All should complete without panic
}

func TestMetrics_RecordProviderAPICalls(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test provider metrics
	tests := []struct {
		name       string
		provider   string
		operation  string
		statusCode int
		durationMs float64
		err        error
	}{
		{"successful exchange", "google", "exchange_code", 200, 234.56, nil},
		{"successful validate", "google", "validate_token", 200, 123.45, nil},
		{"client error", "google", "refresh_token", 401, 100.0, context.DeadlineExceeded},
		{"server error", "google", "revoke_token", 500, 150.0, context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.RecordProviderAPICall(ctx, tt.provider, tt.operation, tt.statusCode, tt.durationMs, tt.err)
		})
	}
}

func TestMetrics_RecordAuditEvents(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test audit metrics
	metrics.RecordAuditEvent(ctx, "authorization_flow_started")
	metrics.RecordAuditEvent(ctx, "token_issued")
	metrics.RecordAuditEvent(ctx, "token_revoked")
	metrics.RecordAuditEvent(ctx, "auth_failure")

	// All should complete without panic
}

func TestMetrics_RecordEncryptionOperations(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test encryption metrics
	metrics.RecordEncryptionOperation(ctx, "encrypt", 5.67)
	metrics.RecordEncryptionOperation(ctx, "decrypt", 4.32)

	// All should complete without panic
}

func TestMetrics_ConcurrentRecording(t *testing.T) {
	ctx := context.Background()
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// Test concurrent metric recording
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				metrics.RecordHTTPRequest(ctx, "GET", "/test", 200, 10.0)
				metrics.RecordAuthorizationStarted(ctx, "client")
				metrics.RecordCodeExchange(ctx, "client", "S256")
				metrics.RecordStorageOperation(ctx, "save", "success", 5.0)
				metrics.RecordProviderAPICall(ctx, "google", "exchange", 200, 100.0, nil)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should complete without race conditions or panics
}

func TestMetrics_NoOpBehavior(t *testing.T) {
	ctx := context.Background()
	// Test that disabled instrumentation doesn't error on metric recording
	inst, err := New(Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	// All these should be no-ops and not panic
	metrics.RecordHTTPRequest(ctx, "GET", "/test", 200, 10.0)
	metrics.RecordAuthorizationStarted(ctx, "client")
	metrics.RecordCodeExchange(ctx, "client", "S256")
	metrics.RecordTokenRefresh(ctx, "client", true)
	metrics.RecordTokenRevocation(ctx, "client")
	metrics.RecordClientRegistration(ctx, "public")
	metrics.RecordRateLimitExceeded(ctx, "ip")
	metrics.RecordPKCEValidationFailed(ctx, "S256")
	metrics.RecordCodeReuseDetected(ctx)
	metrics.RecordTokenReuseDetected(ctx)
	metrics.RecordRedirectURISecurityRejected(ctx, "blocked_scheme", "registration")
	metrics.RecordStorageOperation(ctx, "save", "success", 5.0)
	metrics.RecordProviderAPICall(ctx, "google", "exchange", 200, 100.0, nil)
	metrics.RecordAuditEvent(ctx, "test_event")
	metrics.RecordEncryptionOperation(ctx, "encrypt", 5.0)

	// No panics = success
}
