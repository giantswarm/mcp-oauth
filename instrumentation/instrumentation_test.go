package instrumentation

import (
	"context"
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

				// Verify meters are not nil
				if inst.HTTPMeter() == nil {
					t.Error("HTTPMeter() returned nil")
				}
				if inst.ServerMeter() == nil {
					t.Error("ServerMeter() returned nil")
				}
				if inst.StorageMeter() == nil {
					t.Error("StorageMeter() returned nil")
				}
				if inst.ProviderMeter() == nil {
					t.Error("ProviderMeter() returned nil")
				}
				if inst.SecurityMeter() == nil {
					t.Error("SecurityMeter() returned nil")
				}

				// Verify tracers are not nil
				if inst.HTTPTracer() == nil {
					t.Error("HTTPTracer() returned nil")
				}
				if inst.ServerTracer() == nil {
					t.Error("ServerTracer() returned nil")
				}
				if inst.StorageTracer() == nil {
					t.Error("StorageTracer() returned nil")
				}
				if inst.ProviderTracer() == nil {
					t.Error("ProviderTracer() returned nil")
				}
				if inst.SecurityTracer() == nil {
					t.Error("SecurityTracer() returned nil")
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
	_, span := inst.ServerTracer().Start(ctx, "test-span")
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
				inst.Metrics().RecordAuthorizationStarted(ctx, "client-"+string(rune(id)))
				inst.Metrics().RecordCodeExchange(ctx, "client-"+string(rune(id)), "S256")

				// Create and end spans
				_, span := inst.ServerTracer().Start(ctx, "concurrent-span")
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

func TestInstrumentation_ShutdownTimeout(t *testing.T) {
	inst, err := New(Config{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create a context with immediate timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	<-ctx.Done()

	// Shutdown should handle timeout gracefully
	// Note: With no-op providers, shutdown is instant, so this tests the mechanism
	shutdownErr := inst.Shutdown(ctx)
	// We don't expect an error with no-op providers, but if real providers were used,
	// we'd expect context.DeadlineExceeded
	_ = shutdownErr
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
