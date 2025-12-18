package instrumentation

import (
	"context"
	"fmt"
	"os"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const (
	// DefaultServiceVersion is the default service version used when none is provided
	DefaultServiceVersion = "unknown"

	// Warning messages for development-only features
	warnMetricsStdout = "⚠️  [mcp-oauth] Metrics stdout exporter enabled - for development/debugging only, not for production\n"
	warnTracesStdout  = "⚠️  [mcp-oauth] Traces stdout exporter enabled - for development/debugging only, not for production\n"
	warnOTLPInsecure  = "⚠️  [mcp-oauth] OTLP insecure transport enabled - traces will be sent unencrypted (HTTP). Use only for local development!\n"
)

// Config holds instrumentation configuration
type Config struct {
	// ServiceName is the name of the service (e.g., "mcp-oauth", "my-oauth-server")
	ServiceName string

	// ServiceVersion is the version of the service
	ServiceVersion string

	// Enabled controls whether instrumentation is active
	// When false (zero value), uses no-op providers (zero overhead)
	// When true, initializes exporters based on MetricsExporter and TracesExporter settings
	// You must explicitly set this to true to enable instrumentation
	Enabled bool

	// LogClientIPs controls whether client IP addresses are included in traces and metrics
	// Set to true to include client IP addresses in observability data
	// Set to false (zero value/default) to omit client IP for GDPR/privacy compliance
	//
	// Privacy Note: Client IP addresses may be considered Personally Identifiable
	// Information (PII) under GDPR and other privacy regulations. The default
	// behavior (false) omits IP addresses to be privacy-safe by default.
	// Only enable this if your privacy policy and jurisdiction allow it.
	LogClientIPs bool

	// IncludeClientIDInMetrics controls whether client_id is included as a label in metrics
	// Set to true to include client_id in metrics for detailed per-client visibility
	// Set to false (zero value/default) to reduce cardinality for high-scale deployments
	//
	// Cardinality Warning: Each unique client_id creates a new metric time series.
	// With 10,000+ clients, this can cause:
	// - Memory pressure on metrics backends (Prometheus, etc.)
	// - Slower query performance
	// - Higher storage costs
	//
	// Default (false) is recommended for production deployments with many clients.
	// Use traces with sampling for per-client debugging instead.
	IncludeClientIDInMetrics bool

	// MetricsExporter controls which metrics exporter to use
	// Options: "prometheus", "stdout", "none" (default: "none")
	// - "prometheus": Export metrics in Prometheus format (use prometheus.Handler())
	// - "stdout": Print metrics to stdout (useful for development/debugging)
	// - "none": Use no-op provider (zero overhead)
	MetricsExporter string

	// TracesExporter controls which traces exporter to use
	// Options: "otlp", "stdout", "none" (default: "none")
	// - "otlp": Export traces via OTLP HTTP (requires OTLPEndpoint)
	// - "stdout": Print traces to stdout (useful for development/debugging)
	// - "none": Use no-op provider (zero overhead)
	TracesExporter string

	// OTLPEndpoint is the endpoint for OTLP trace export
	// Required when TracesExporter="otlp"
	// Example: "localhost:4318" (default OTLP HTTP port)
	OTLPEndpoint string

	// OTLPInsecure controls whether to use insecure HTTP for OTLP export
	// When false (default), uses TLS for secure transport
	// Set to true only for local development or testing with unencrypted endpoints
	// Default: false (uses TLS)
	// WARNING: Never use insecure transport in production - traces may contain
	// user metadata and should be encrypted in transit
	OTLPInsecure bool

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

	// prometheusExporter is stored separately to enable prometheus.Handler() access
	// Only set when MetricsExporter="prometheus"
	prometheusExporter *prometheus.Exporter

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
// Supports multiple exporters: Prometheus, OTLP, stdout, or no-op (none)
func (i *Instrumentation) initializeProviders() error {
	// Initialize metrics provider based on config
	if err := i.initializeMetricsProvider(); err != nil {
		return fmt.Errorf("failed to initialize metrics provider: %w", err)
	}

	// Initialize traces provider based on config
	if err := i.initializeTracesProvider(); err != nil {
		return fmt.Errorf("failed to initialize traces provider: %w", err)
	}

	return nil
}

// initializeMetricsProvider initializes the metrics provider based on configuration
func (i *Instrumentation) initializeMetricsProvider() error {
	switch i.config.MetricsExporter {
	case "prometheus":
		// Create Prometheus exporter
		exporter, err := prometheus.New()
		if err != nil {
			return fmt.Errorf("failed to create Prometheus exporter: %w", err)
		}

		// Store exporter for prometheus.Handler() access
		i.prometheusExporter = exporter

		// Create meter provider with Prometheus exporter
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(i.resource),
			sdkmetric.WithReader(exporter),
		)

		i.meterProvider = provider

		// Register shutdown function
		i.shutdownFuncs = append(i.shutdownFuncs, func(ctx context.Context) error {
			return provider.Shutdown(ctx)
		})

	case "stdout":
		// SECURITY WARNING: Stdout exporter is for development only
		fmt.Fprint(os.Stderr, warnMetricsStdout)

		// Create stdout exporter for development/debugging
		exporter, err := stdoutmetric.New()
		if err != nil {
			return fmt.Errorf("failed to create stdout metrics exporter: %w", err)
		}

		// Create meter provider with periodic reader (exports every 10 seconds)
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(i.resource),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		)

		i.meterProvider = provider

		// Register shutdown function
		i.shutdownFuncs = append(i.shutdownFuncs, func(ctx context.Context) error {
			return provider.Shutdown(ctx)
		})

	case "none", "":
		// Use no-op provider (zero overhead)
		i.meterProvider = noop.NewMeterProvider()

	default:
		return fmt.Errorf("unsupported metrics exporter: %s (supported: prometheus, stdout, none)", i.config.MetricsExporter)
	}

	return nil
}

// initializeTracesProvider initializes the traces provider based on configuration
func (i *Instrumentation) initializeTracesProvider() error {
	switch i.config.TracesExporter {
	case "otlp":
		// Validate OTLP endpoint is provided
		if i.config.OTLPEndpoint == "" {
			return fmt.Errorf("OTLPEndpoint is required when TracesExporter is 'otlp'")
		}

		// Create OTLP HTTP exporter with TLS by default
		// Only use insecure if explicitly configured (for local dev/testing)
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(i.config.OTLPEndpoint),
		}

		if i.config.OTLPInsecure {
			// SECURITY WARNING: Traces may contain user metadata
			// Only use insecure transport for local development/testing
			fmt.Fprint(os.Stderr, warnOTLPInsecure)
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		// If not insecure, the exporter will use TLS by default

		exporter, err := otlptracehttp.New(
			context.Background(),
			opts...,
		)
		if err != nil {
			return fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}

		// Create trace provider with batch span processor
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithResource(i.resource),
			sdktrace.WithBatcher(exporter),
		)

		i.tracerProvider = provider

		// Register shutdown function
		i.shutdownFuncs = append(i.shutdownFuncs, func(ctx context.Context) error {
			return provider.Shutdown(ctx)
		})

	case "stdout":
		// SECURITY WARNING: Stdout exporter is for development only
		fmt.Fprint(os.Stderr, warnTracesStdout)

		// Create stdout exporter for development/debugging
		exporter, err := stdouttrace.New(
			stdouttrace.WithWriter(os.Stdout),
			stdouttrace.WithPrettyPrint(),
		)
		if err != nil {
			return fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}

		// Create trace provider with simple span processor (immediate export)
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithResource(i.resource),
			sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)),
		)

		i.tracerProvider = provider

		// Register shutdown function
		i.shutdownFuncs = append(i.shutdownFuncs, func(ctx context.Context) error {
			return provider.Shutdown(ctx)
		})

	case "none", "":
		// Use no-op provider (zero overhead)
		i.tracerProvider = tracenoop.NewTracerProvider()

	default:
		return fmt.Errorf("unsupported traces exporter: %s (supported: otlp, stdout, none)", i.config.TracesExporter)
	}

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

// ShouldIncludeClientIDInMetrics returns whether client_id should be included in metric labels
// This respects the IncludeClientIDInMetrics configuration for cardinality management
func (i *Instrumentation) ShouldIncludeClientIDInMetrics() bool {
	return i.config.IncludeClientIDInMetrics
}

// PrometheusExporter returns the Prometheus exporter if configured
// Returns nil if MetricsExporter is not "prometheus"
//
// Usage with prometheus/client_golang:
//
//	import "github.com/prometheus/client_golang/prometheus/promhttp"
//
//	if exporter := inst.PrometheusExporter(); exporter != nil {
//	    http.Handle("/metrics", promhttp.Handler())
//	}
func (i *Instrumentation) PrometheusExporter() *prometheus.Exporter {
	return i.prometheusExporter
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
		func(_ context.Context, observer metric.Observer) error {
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
