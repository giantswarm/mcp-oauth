package instrumentation

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
)

func TestRecordError(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test recording an error
	testErr := errors.New("test error")
	RecordError(span, testErr)

	// Should not panic
}

func TestSetSpanSuccess(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test setting span as successful
	SetSpanSuccess(span)

	// Should not panic
}

func TestAddOAuthFlowAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding OAuth flow attributes
	AddOAuthFlowAttributes(span, "test-client", "test-user", "openid email")
	AddOAuthFlowAttributes(span, "test-client-2", "", "")
	AddOAuthFlowAttributes(span, "", "test-user-2", "")

	// Should not panic
}

func TestAddPKCEAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding PKCE attributes
	AddPKCEAttributes(span, "S256")
	AddPKCEAttributes(span, "plain")
	AddPKCEAttributes(span, "")

	// Should not panic
}

func TestAddTokenFamilyAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding token family attributes
	AddTokenFamilyAttributes(span, "family-123", 1)
	AddTokenFamilyAttributes(span, "family-456", 5)
	AddTokenFamilyAttributes(span, "", 0)

	// Should not panic
}

func TestAddStorageAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding storage attributes
	AddStorageAttributes(span, "save_token", "memory")
	AddStorageAttributes(span, "get_token", "redis")

	// Should not panic
}

func TestAddProviderAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding provider attributes
	AddProviderAttributes(span, "google", "exchange_code")
	AddProviderAttributes(span, "github", "validate_token")

	// Should not panic
}

func TestAddHTTPAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding HTTP attributes
	AddHTTPAttributes(span, "GET", "/oauth/authorize", 200)
	AddHTTPAttributes(span, "POST", "/oauth/token", 401)

	// Should not panic
}

func TestAddSecurityAttributes(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	defer span.End()

	// Test adding security attributes
	AddSecurityAttributes(span, "192.168.1.1")
	AddSecurityAttributes(span, "")

	// Should not panic
}

func TestSpanLifecycle(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()

	// Test full span lifecycle with attributes and error
	_, span := inst.ServerTracer().Start(ctx, "oauth.exchange_authorization_code")

	// Add attributes
	AddOAuthFlowAttributes(span, "test-client", "test-user", "openid email")
	AddPKCEAttributes(span, "S256")
	AddHTTPAttributes(span, "POST", "/oauth/token", 200)

	// Simulate some work
	testErr := errors.New("validation failed")
	RecordError(span, testErr)

	// End span
	span.End()

	// Should complete without panic
}

func TestSpanNesting(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()

	// Create nested spans
	ctx, span1 := inst.HTTPTracer().Start(ctx, "http.request")
	AddHTTPAttributes(span1, "POST", "/oauth/token", 200)

	ctx, span2 := inst.ServerTracer().Start(ctx, "oauth.exchange_code")
	AddOAuthFlowAttributes(span2, "test-client", "test-user", "openid")

	_, span3 := inst.StorageTracer().Start(ctx, "storage.get_authorization_code")
	AddStorageAttributes(span3, "get_code", "memory")
	SetSpanSuccess(span3)
	span3.End()

	SetSpanSuccess(span2)
	span2.End()

	SetSpanSuccess(span1)
	span1.End()

	// Should complete without panic
}

func TestSpanConcurrency(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	done := make(chan bool)

	// Create spans concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				_, span := inst.ServerTracer().Start(ctx, "concurrent-span")
				AddOAuthFlowAttributes(span, "client", "user", "scope")
				AddPKCEAttributes(span, "S256")
				SetSpanSuccess(span)
				span.End()
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should complete without race conditions
}

func TestNoOpSpans(t *testing.T) {
	// Test that disabled instrumentation produces no-op spans
	inst, err := New(Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()

	// Create and manipulate spans - should all be no-ops
	_, span := inst.ServerTracer().Start(ctx, "test-span")
	AddOAuthFlowAttributes(span, "client", "user", "scope")
	AddPKCEAttributes(span, "S256")
	AddHTTPAttributes(span, "GET", "/test", 200)
	AddStorageAttributes(span, "save", "memory")
	AddProviderAttributes(span, "google", "exchange")
	AddSecurityAttributes(span, "192.168.1.1")
	RecordError(span, errors.New("test"))
	SetSpanSuccess(span)
	span.SetStatus(codes.Ok, "")
	span.End()

	// Should not panic
}
