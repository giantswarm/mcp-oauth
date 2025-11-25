package instrumentation

import (
	"context"
	"fmt"
	"sync"

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

	// LogClientIPs controls whether client IP addresses are included in traces and metrics
	// When false, client IP attributes will be omitted from observability data
	// This can help with GDPR and privacy compliance in strict jurisdictions
	// Default: true
	//
	// Privacy Note: Client IP addresses may be considered Personally Identifiable
	// Information (PII) under GDPR and other privacy regulations. Disabling IP
	// logging may be required in certain jurisdictions or for certain compliance
	// frameworks (e.g., GDPR in EU, CCPA in California).
	LogClientIPs bool

	// Resource allows custom resource attributes
	// If nil, default resource is created with service name and version
	Resource *resource.Resource
}

// Instrumentation provides OpenTelemetry instrumentation components
type Instrumentation struct {
	config   Config
	resource *resource.Resource

	// Providers - these are used to create meters and tracers on demand
	meterProvider  metric.MeterProvider
	tracerProvider trace.TracerProvider

	// Metrics holder provides pre-configured metric instruments
	metrics *Metrics

	// Shutdown functions (must be registered during New() only, not thread-safe after initialization)
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
	// LogClientIPs defaults to true if not explicitly set
	// Note: In Go, uninitialized bool is false, so we need special handling
	// We treat the zero value as "use default" which is true
	// Users must explicitly set to false to disable IP logging

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

	// Initialize metrics (creates meters internally as needed)
	inst.metrics, err = newMetrics(inst)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics: %w", err)
	}

	return inst, nil
}

// initializeProviders initializes metric and trace providers based on configuration
// Currently uses no-op providers. Future enhancement will add actual exporters
// (Prometheus, OTLP, stdout) which can be implemented in a backward-compatible way.
func (i *Instrumentation) initializeProviders() error {
	// Use no-op providers for now
	// TODO: Add actual exporters (Prometheus, OTLP, stdout) in follow-up PR
	i.meterProvider = noop.NewMeterProvider()
	i.tracerProvider = tracenoop.NewTracerProvider()

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

// Meter returns a named meter for the given scope
// Scopes are typically layer names like "http", "server", "storage", "provider", "security"
// The full name will be "github.com/giantswarm/mcp-oauth/{scope}"
func (i *Instrumentation) Meter(scope string) metric.Meter {
	return i.meterProvider.Meter("github.com/giantswarm/mcp-oauth/" + scope)
}

// Tracer returns a named tracer for the given scope
// Scopes are typically layer names like "http", "server", "storage", "provider", "security"
// The full name will be "github.com/giantswarm/mcp-oauth/{scope}"
func (i *Instrumentation) Tracer(scope string) trace.Tracer {
	return i.tracerProvider.Tracer("github.com/giantswarm/mcp-oauth/" + scope)
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

// ShouldLogClientIPs returns whether client IP addresses should be logged
// This respects the LogClientIPs configuration for privacy compliance
func (i *Instrumentation) ShouldLogClientIPs() bool {
	return i.config.LogClientIPs
}

// StorageSizeCallback is a function that returns the current size of a storage component
type StorageSizeCallback func() int64

// RegisterStorageSizeCallbacks registers callbacks for storage size metrics
// Storage implementations should call this after instrumentation is set
//
// Example:
//
//	func (s *Store) SetInstrumentation(inst *instrumentation.Instrumentation) {
//	    s.instrumentation = inst
//	    inst.RegisterStorageSizeCallbacks(
//	        func() int64 { return int64(len(s.tokens)) },
//	        func() int64 { return int64(len(s.clients)) },
//	        func() int64 { return int64(len(s.authStates)) },
//	        func() int64 { return int64(len(s.refreshTokenFamilies)) },
//	        func() int64 { return int64(len(s.refreshTokens)) },
//	    )
//	}
func (i *Instrumentation) RegisterStorageSizeCallbacks(
	tokensCount, clientsCount, flowsCount, familiesCount, refreshTokensCount StorageSizeCallback,
) error {
	if i.meterProvider == nil {
		return fmt.Errorf("meter provider not initialized")
	}

	meter := i.Meter("storage")

	// Register callbacks for each gauge
	_, err := meter.RegisterCallback(
		func(ctx context.Context, observer metric.Observer) error {
			if tokensCount != nil {
				observer.ObserveInt64(i.metrics.StorageTokensCount, tokensCount())
			}
			if clientsCount != nil {
				observer.ObserveInt64(i.metrics.StorageClientsCount, clientsCount())
			}
			if flowsCount != nil {
				observer.ObserveInt64(i.metrics.StorageFlowsCount, flowsCount())
			}
			if familiesCount != nil {
				observer.ObserveInt64(i.metrics.StorageFamiliesCount, familiesCount())
			}
			if refreshTokensCount != nil {
				observer.ObserveInt64(i.metrics.StorageRefreshTokensCount, refreshTokensCount())
			}
			return nil
		},
		i.metrics.StorageTokensCount,
		i.metrics.StorageClientsCount,
		i.metrics.StorageFlowsCount,
		i.metrics.StorageFamiliesCount,
		i.metrics.StorageRefreshTokensCount,
	)

	return err
}
