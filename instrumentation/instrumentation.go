package instrumentation

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const (
	// DefaultServiceVersion is the default service version used when none is provided
	DefaultServiceVersion = "unknown"
)

// Config holds instrumentation configuration
type Config struct {
	// ServiceName is the name of the service (e.g., "mcp-oauth", "my-oauth-server")
	ServiceName string

	// ServiceVersion is the version of the service
	ServiceVersion string

	// Enabled controls whether instrumentation is active
	// When false, uses no-op providers (zero overhead)
	// Default: true
	Enabled bool

	// MetricExporter specifies the metric exporter to use
	// Options: "prometheus", "otlp", "stdout", "none"
	// Default: "none" (no-op)
	MetricExporter string

	// TraceExporter specifies the trace exporter to use
	// Options: "otlp", "stdout", "none"
	// Default: "none" (no-op)
	TraceExporter string

	// Resource allows custom resource attributes
	// If nil, default resource is created with service name and version
	Resource *resource.Resource
}

// Instrumentation provides OpenTelemetry instrumentation components
type Instrumentation struct {
	config   Config
	resource *resource.Resource

	// Providers
	meterProvider  metric.MeterProvider
	tracerProvider trace.TracerProvider

	// Meters and tracers for different layers
	httpMeter     metric.Meter
	serverMeter   metric.Meter
	storageMeter  metric.Meter
	providerMeter metric.Meter
	securityMeter metric.Meter

	httpTracer     trace.Tracer
	serverTracer   trace.Tracer
	storageTracer  trace.Tracer
	providerTracer trace.Tracer
	securityTracer trace.Tracer

	// Metrics holder
	metrics *Metrics

	// Shutdown function (called when instrumentation is no longer needed)
	shutdownFuncs []func(context.Context) error
	shutdownOnce  sync.Once
}

// New creates a new instrumentation instance
func New(config Config) (*Instrumentation, error) {
	// Apply defaults
	if config.ServiceName == "" {
		config.ServiceName = "mcp-oauth"
	}
	if config.ServiceVersion == "" {
		config.ServiceVersion = DefaultServiceVersion
	}

	// Create or use provided resource
	var res *resource.Resource
	var err error
	if config.Resource != nil {
		res = config.Resource
	} else {
		res, err = resource.New(
			context.Background(),
			resource.WithAttributes(
				semconv.ServiceName(config.ServiceName),
				semconv.ServiceVersion(config.ServiceVersion),
			),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create resource: %w", err)
		}
	}

	inst := &Instrumentation{
		config:   config,
		resource: res,
	}

	// Initialize providers based on configuration
	if config.Enabled {
		if err := inst.initializeProviders(); err != nil {
			return nil, fmt.Errorf("failed to initialize providers: %w", err)
		}
	} else {
		// Use no-op providers for zero overhead
		inst.meterProvider = noop.NewMeterProvider()
		inst.tracerProvider = tracenoop.NewTracerProvider()
	}

	// Create meters and tracers for each layer
	inst.httpMeter = inst.meterProvider.Meter("github.com/giantswarm/mcp-oauth/http")
	inst.serverMeter = inst.meterProvider.Meter("github.com/giantswarm/mcp-oauth/server")
	inst.storageMeter = inst.meterProvider.Meter("github.com/giantswarm/mcp-oauth/storage")
	inst.providerMeter = inst.meterProvider.Meter("github.com/giantswarm/mcp-oauth/provider")
	inst.securityMeter = inst.meterProvider.Meter("github.com/giantswarm/mcp-oauth/security")

	inst.httpTracer = inst.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/http")
	inst.serverTracer = inst.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/server")
	inst.storageTracer = inst.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/storage")
	inst.providerTracer = inst.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/provider")
	inst.securityTracer = inst.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/security")

	// Initialize metrics
	inst.metrics, err = newMetrics(inst)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics: %w", err)
	}

	// Set global providers (optional, but recommended for libraries)
	if config.Enabled {
		otel.SetMeterProvider(inst.meterProvider)
		otel.SetTracerProvider(inst.tracerProvider)
	}

	return inst, nil
}

// initializeProviders initializes metric and trace providers based on configuration
func (i *Instrumentation) initializeProviders() error {
	// For now, we'll use no-op providers
	// In a follow-up, we'll add actual exporters (Prometheus, OTLP, etc.)
	// This allows the core structure to be in place while we implement exporters
	i.meterProvider = noop.NewMeterProvider()
	i.tracerProvider = tracenoop.NewTracerProvider()

	// TODO: Implement actual exporters based on config.MetricExporter and config.TraceExporter
	// This will be done in a subsequent implementation phase

	return nil
}

// Shutdown gracefully shuts down all instrumentation providers
// This should be called when the application is terminating
func (i *Instrumentation) Shutdown(ctx context.Context) error {
	var shutdownErr error

	i.shutdownOnce.Do(func() {
		// Call all registered shutdown functions
		for _, fn := range i.shutdownFuncs {
			if err := fn(ctx); err != nil {
				// Capture first error, but continue shutting down other components
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}
	})

	return shutdownErr
}

// HTTPMeter returns the meter for HTTP layer instrumentation
func (i *Instrumentation) HTTPMeter() metric.Meter {
	return i.httpMeter
}

// ServerMeter returns the meter for server layer instrumentation
func (i *Instrumentation) ServerMeter() metric.Meter {
	return i.serverMeter
}

// StorageMeter returns the meter for storage layer instrumentation
func (i *Instrumentation) StorageMeter() metric.Meter {
	return i.storageMeter
}

// ProviderMeter returns the meter for provider layer instrumentation
func (i *Instrumentation) ProviderMeter() metric.Meter {
	return i.providerMeter
}

// SecurityMeter returns the meter for security layer instrumentation
func (i *Instrumentation) SecurityMeter() metric.Meter {
	return i.securityMeter
}

// HTTPTracer returns the tracer for HTTP layer instrumentation
func (i *Instrumentation) HTTPTracer() trace.Tracer {
	return i.httpTracer
}

// ServerTracer returns the tracer for server layer instrumentation
func (i *Instrumentation) ServerTracer() trace.Tracer {
	return i.serverTracer
}

// StorageTracer returns the tracer for storage layer instrumentation
func (i *Instrumentation) StorageTracer() trace.Tracer {
	return i.storageTracer
}

// ProviderTracer returns the tracer for provider layer instrumentation
func (i *Instrumentation) ProviderTracer() trace.Tracer {
	return i.providerTracer
}

// SecurityTracer returns the tracer for security layer instrumentation
func (i *Instrumentation) SecurityTracer() trace.Tracer {
	return i.securityTracer
}

// Metrics returns the metrics holder for recording metric values
func (i *Instrumentation) Metrics() *Metrics {
	return i.metrics
}

// TracerProvider returns the underlying tracer provider
func (i *Instrumentation) TracerProvider() trace.TracerProvider {
	return i.tracerProvider
}

// MeterProvider returns the underlying meter provider
func (i *Instrumentation) MeterProvider() metric.MeterProvider {
	return i.meterProvider
}
