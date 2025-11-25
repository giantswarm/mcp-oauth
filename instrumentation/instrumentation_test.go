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
	ctx := context.Background()
	// Test that disabled instrumentation uses no-op providers
	inst, err := New(Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify that we can use meters and tracers without errors

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
	ctx := context.Background()
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
	ctx := context.Background()
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest(ctx, "GET", "/oauth/authorize", 200, 123.45)
	}
}

func BenchmarkMetrics_RecordHTTPRequest_NoOp(b *testing.B) {
	ctx := context.Background()
	inst, _ := New(Config{Enabled: false})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest(ctx, "GET", "/oauth/authorize", 200, 123.45)
	}
}

func BenchmarkTracing_SpanCreation(b *testing.B) {
	ctx := context.Background()
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	tracer := inst.Tracer("server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "test-operation")
		span.End()
	}
}

func BenchmarkTracing_SpanCreation_NoOp(b *testing.B) {
	ctx := context.Background()
	inst, _ := New(Config{Enabled: false})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	tracer := inst.Tracer("server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "test-operation")
		span.End()
	}
}

func BenchmarkTracing_SpanWithAttributes(b *testing.B) {
	ctx := context.Background()
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

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
	ctx := context.Background()
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

	metrics := inst.Metrics()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			metrics.RecordAuthorizationStarted(ctx, "client-123")
		}
	})
}

func BenchmarkConcurrentSpans(b *testing.B) {
	ctx := context.Background()
	inst, _ := New(Config{Enabled: true})
	defer func() { _ = inst.Shutdown(context.Background()) }()

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

func TestNewWithPrometheusExporter(t *testing.T) {
	config := Config{
		Enabled:         true,
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsExporter: "prometheus",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() with prometheus exporter failed: %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() failed: %v", err)
		}
	}()

	// Verify prometheus exporter is available
	if inst.PrometheusExporter() == nil {
		t.Error("PrometheusExporter() returned nil, expected exporter instance")
	}

	// Verify meter provider is not nil
	if inst.MeterProvider() == nil {
		t.Error("MeterProvider() returned nil")
	}

	// Test that metrics can be created
	meter := inst.Meter("test")
	counter, err := meter.Int64Counter("test.counter")
	if err != nil {
		t.Errorf("Failed to create counter: %v", err)
	}
	counter.Add(context.Background(), 1)
}

func TestNewWithStdoutMetricsExporter(t *testing.T) {
	config := Config{
		Enabled:         true,
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsExporter: "stdout",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() with stdout metrics exporter failed: %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() failed: %v", err)
		}
	}()

	// Verify prometheus exporter is NOT available for stdout
	if inst.PrometheusExporter() != nil {
		t.Error("PrometheusExporter() should return nil for stdout exporter")
	}

	// Verify meter provider is not nil
	if inst.MeterProvider() == nil {
		t.Error("MeterProvider() returned nil")
	}
}

func TestNewWithStdoutTracesExporter(t *testing.T) {
	config := Config{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		TracesExporter: "stdout",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() with stdout traces exporter failed: %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() failed: %v", err)
		}
	}()

	// Verify tracer provider is not nil
	if inst.TracerProvider() == nil {
		t.Error("TracerProvider() returned nil")
	}

	// Create a span and verify it works
	tracer := inst.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	span.End()
	if ctx == nil {
		t.Error("Start() returned nil context")
	}
}

func TestNewWithOTLPTracesExporter(t *testing.T) {
	config := Config{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		TracesExporter: "otlp",
		OTLPEndpoint:   "localhost:4318",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() with OTLP traces exporter failed: %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() failed: %v", err)
		}
	}()

	// Verify tracer provider is not nil
	if inst.TracerProvider() == nil {
		t.Error("TracerProvider() returned nil")
	}
}

func TestNewWithOTLPMissingEndpoint(t *testing.T) {
	config := Config{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		TracesExporter: "otlp",
		// OTLPEndpoint is intentionally missing
	}

	_, err := New(config)
	if err == nil {
		t.Error("New() should fail when TracesExporter=otlp but OTLPEndpoint is not set")
	}
}

func TestNewWithInvalidMetricsExporter(t *testing.T) {
	config := Config{
		Enabled:         true,
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsExporter: "invalid-exporter",
	}

	_, err := New(config)
	if err == nil {
		t.Error("New() should fail with invalid metrics exporter")
	}
}

func TestNewWithInvalidTracesExporter(t *testing.T) {
	config := Config{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		TracesExporter: "invalid-exporter",
	}

	_, err := New(config)
	if err == nil {
		t.Error("New() should fail with invalid traces exporter")
	}
}

func TestNewWithMultipleExporters(t *testing.T) {
	config := Config{
		Enabled:         true,
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsExporter: "prometheus",
		TracesExporter:  "stdout",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() with multiple exporters failed: %v", err)
	}
	defer func() {
		if err := inst.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() failed: %v", err)
		}
	}()

	// Verify both providers are working
	if inst.PrometheusExporter() == nil {
		t.Error("PrometheusExporter() returned nil")
	}
	if inst.TracerProvider() == nil {
		t.Error("TracerProvider() returned nil")
	}
	if inst.MeterProvider() == nil {
		t.Error("MeterProvider() returned nil")
	}
}

func TestShutdownWithExporters(t *testing.T) {
	ctx := context.Background()
	config := Config{
		Enabled:         true,
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsExporter: "prometheus",
		TracesExporter:  "stdout",
	}

	inst, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Shutdown should succeed
	if err := inst.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() failed: %v", err)
	}

	// Shutdown is idempotent - calling again should not error
	if err := inst.Shutdown(ctx); err != nil {
		t.Errorf("Second Shutdown() failed: %v", err)
	}
}

// TestShouldIncludeClientIDInMetrics tests the cardinality mitigation control
func TestShouldIncludeClientIDInMetrics(t *testing.T) {
	tests := []struct {
		name                     string
		includeClientIDInMetrics bool
		expectedResult           bool
	}{
		{
			name:                     "client ID in metrics enabled",
			includeClientIDInMetrics: true,
			expectedResult:           true,
		},
		{
			name:                     "client ID in metrics disabled (low cardinality mode)",
			includeClientIDInMetrics: false,
			expectedResult:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Enabled:                  true,
				IncludeClientIDInMetrics: tt.includeClientIDInMetrics,
			}

			inst, err := New(config)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer func() {
				_ = inst.Shutdown(context.Background())
			}()

			result := inst.ShouldIncludeClientIDInMetrics()
			if result != tt.expectedResult {
				t.Errorf("ShouldIncludeClientIDInMetrics() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

// TestOTLPInsecureWarning tests that insecure OTLP triggers properly
func TestOTLPInsecureConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		insecure     bool
		shouldCreate bool
	}{
		{
			name:         "secure OTLP (default)",
			insecure:     false,
			shouldCreate: true,
		},
		{
			name:         "insecure OTLP (development only)",
			insecure:     true,
			shouldCreate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip if no OTLP endpoint available (this is expected in CI)
			t.Skip("Skipping OTLP test - requires running OTLP collector")

			config := Config{
				Enabled:        true,
				TracesExporter: "otlp",
				OTLPEndpoint:   "localhost:4318",
				OTLPInsecure:   tt.insecure,
			}

			inst, err := New(config)
			if tt.shouldCreate {
				if err != nil {
					t.Logf("Expected: OTLP creation may fail without collector: %v", err)
				}
				if inst != nil {
					_ = inst.Shutdown(context.Background())
				}
			}
		})
	}
}

// TestMetricCardinalityControl tests that client_id is conditionally included in metrics
func TestMetricCardinalityControl(t *testing.T) {
	tests := []struct {
		name                     string
		includeClientIDInMetrics bool
	}{
		{
			name:                     "high cardinality mode (include client_id)",
			includeClientIDInMetrics: true,
		},
		{
			name:                     "low cardinality mode (exclude client_id)",
			includeClientIDInMetrics: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Enabled:                  true,
				IncludeClientIDInMetrics: tt.includeClientIDInMetrics,
				MetricsExporter:          "none", // Use no-op for testing
			}

			inst, err := New(config)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer func() {
				_ = inst.Shutdown(context.Background())
			}()

			metrics := inst.Metrics()
			if metrics == nil {
				t.Fatal("Metrics() returned nil")
			}

			// Test that the instrumentation reference is set
			if metrics.instrumentation == nil {
				t.Error("Metrics.instrumentation is nil")
			}

			// Test that ShouldIncludeClientIDInMetrics matches config
			if metrics.instrumentation.ShouldIncludeClientIDInMetrics() != tt.includeClientIDInMetrics {
				t.Errorf("ShouldIncludeClientIDInMetrics() = %v, want %v",
					metrics.instrumentation.ShouldIncludeClientIDInMetrics(),
					tt.includeClientIDInMetrics)
			}
		})
	}
}
