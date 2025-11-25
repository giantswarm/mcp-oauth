package instrumentation

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "default config",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "with service name and version",
			config: Config{
				Enabled:        true,
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
			},
			wantErr: false,
		},
		{
			name: "empty service name gets default",
			config: Config{
				Enabled:        true,
				ServiceName:    "",
				ServiceVersion: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := New(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				// Verify instrumentation was created
				if inst == nil {
					t.Error("New() returned nil instrumentation")
					return
				}

				// Verify meters can be created for different scopes
				if inst.Meter("http") == nil {
					t.Error("Meter('http') returned nil")
				}
				if inst.Meter("server") == nil {
					t.Error("Meter('server') returned nil")
				}

				// Verify tracers can be created for different scopes
				if inst.Tracer("http") == nil {
					t.Error("Tracer('http') returned nil")
				}
				if inst.Tracer("server") == nil {
					t.Error("Tracer('server') returned nil")
				}

				// Verify metrics holder is not nil
				if inst.Metrics() == nil {
					t.Error("Metrics() returned nil")
				}

				// Verify providers are not nil
				if inst.TracerProvider() == nil {
					t.Error("TracerProvider() returned nil")
				}
				if inst.MeterProvider() == nil {
					t.Error("MeterProvider() returned nil")
				}

				// Test shutdown
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				shutdownErr := inst.Shutdown(ctx)
				if shutdownErr != nil {
					t.Errorf("Shutdown() error = %v", shutdownErr)
				}

				// Verify shutdown is idempotent (can be called multiple times)
				shutdownErr = inst.Shutdown(ctx)
				if shutdownErr != nil {
					t.Errorf("Second Shutdown() error = %v", shutdownErr)
				}
			}
		})
	}
}

func TestInstrumentation_NoOpProviders(t *testing.T) {
	// Test that disabled instrumentation uses no-op providers
	inst, err := New(Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify that we can use meters and tracers without errors
	ctx := context.Background()

	// Test metrics recording (should be no-op)
	inst.Metrics().RecordAuthorizationStarted(ctx, "test-client")
	inst.Metrics().RecordCodeExchange(ctx, "test-client", "S256")
	inst.Metrics().RecordTokenRefresh(ctx, "test-client", true)

	// Test span creation (should be no-op)
	_, span := inst.Tracer("server").Start(ctx, "test-span")
	span.End()

	// Should not panic or error
}

func TestInstrumentation_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to instrumentation
	inst, err := New(Config{
		Enabled:        true,
		ServiceName:    "concurrent-test",
		ServiceVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = inst.Shutdown(context.Background()) }()

	// Launch concurrent goroutines recording metrics
	done := make(chan bool)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				clientID := fmt.Sprintf("client-%d", id)
				inst.Metrics().RecordAuthorizationStarted(ctx, clientID)
				inst.Metrics().RecordCodeExchange(ctx, clientID, "S256")

				// Create and end spans
				_, span := inst.Tracer("server").Start(ctx, "concurrent-span")
				span.End()
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should complete without panic or race conditions
}

func TestConfig_Defaults(t *testing.T) {
	inst, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	}()

	// Verify defaults are applied
	if inst.config.ServiceName != "mcp-oauth" {
		t.Errorf("Default ServiceName = %q, want %q", inst.config.ServiceName, "mcp-oauth")
	}
	if inst.config.ServiceVersion != "unknown" {
		t.Errorf("Default ServiceVersion = %q, want %q", inst.config.ServiceVersion, "unknown")
	}
}

// Benchmark tests to measure instrumentation overhead

func BenchmarkMetrics_RecordHTTPRequest(b *testing.B) {
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	metrics := inst.Metrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest(ctx, "GET", "/oauth/authorize", 200, 123.45)
	}
}

func BenchmarkMetrics_RecordHTTPRequest_NoOp(b *testing.B) {
	inst, _ := New(Config{Enabled: false})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	metrics := inst.Metrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest(ctx, "GET", "/oauth/authorize", 200, 123.45)
	}
}

func BenchmarkTracing_SpanCreation(b *testing.B) {
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	tracer := inst.Tracer("server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "test-operation")
		span.End()
	}
}

func BenchmarkTracing_SpanCreation_NoOp(b *testing.B) {
	inst, _ := New(Config{Enabled: false})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	tracer := inst.Tracer("server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "test-operation")
		span.End()
	}
}

func BenchmarkTracing_SpanWithAttributes(b *testing.B) {
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	tracer := inst.Tracer("server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "test-operation")
		AddOAuthFlowAttributes(span, "client-123", "user-456", "openid email")
		AddPKCEAttributes(span, "S256")
		SetSpanSuccess(span)
		span.End()
	}
}

func BenchmarkConcurrentMetrics(b *testing.B) {
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	metrics := inst.Metrics()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			metrics.RecordAuthorizationStarted(ctx, "client-123")
		}
	})
}

func BenchmarkConcurrentSpans(b *testing.B) {
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	ctx := context.Background()
	tracer := inst.Tracer("server")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, span := tracer.Start(ctx, "concurrent-operation")
			AddOAuthFlowAttributes(span, "client", "user", "scope")
			span.End()
		}
	})
}
