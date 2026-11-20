package instrumentation

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestStorageCallbacksUnregisterWithoutShuttingDownSharedProvider(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
	instrumentation, err := New(Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instrumentation.Shutdown(context.WithoutCancel(t.Context()))) })
	var calls atomic.Int64
	require.NoError(t, instrumentation.RegisterStorageSizeCallbacks(func() int64 {
		calls.Add(1)
		return 4
	}, nil, nil, nil, nil))
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &collected))
	require.EqualValues(t, 1, calls.Load())
	require.NoError(t, instrumentation.Shutdown(t.Context()))

	counter, err := provider.Meter("host").Int64Counter("host.after.shutdown")
	require.NoError(t, err)
	counter.Add(t.Context(), 7)
	require.NoError(t, reader.Collect(t.Context(), &collected))
	require.EqualValues(t, 1, calls.Load(), "shutdown must detach callbacks from the shared provider")
	var counterValue int64
	for _, scope := range collected.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			if measurement.Name == "host.after.shutdown" {
				values, ok := measurement.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.Len(t, values.DataPoints, 1)
				counterValue = values.DataPoints[0].Value
			}
		}
	}
	require.EqualValues(t, 7, counterValue, "the caller must retain ownership of the meter provider")
	require.ErrorContains(t, instrumentation.RegisterStorageSizeCallbacks(nil, nil, nil, nil, nil), "shut down")
}

func TestStorageCallbacksPartialRegistrationErrorRetainsCleanupOwnership(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
	instrumentation, err := New(Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instrumentation.Shutdown(context.WithoutCancel(t.Context()))) })
	foreignGauge, err := provider.Meter("foreign").Int64ObservableGauge("foreign.clients")
	require.NoError(t, err)
	instrumentation.metrics.StorageClientsCount = foreignGauge
	var calls atomic.Int64
	err = instrumentation.RegisterStorageSizeCallbacks(func() int64 { return calls.Add(1) }, nil, nil, nil, nil)
	require.Error(t, err)
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &collected))
	require.EqualValues(t, 1, calls.Load())
	require.NoError(t, instrumentation.Shutdown(t.Context()))
	require.NoError(t, reader.Collect(t.Context(), &collected))
	require.EqualValues(t, 1, calls.Load(), "a registration handle returned alongside an error must still be detached")
}

func TestStorageCallbacksConcurrentRegistrationCollectionAndShutdown(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.WithoutCancel(t.Context()))) })
	instrumentation, err := New(Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instrumentation.Shutdown(context.WithoutCancel(t.Context()))) })
	var calls atomic.Int64
	callback := func() int64 { return calls.Add(1) }
	require.NoError(t, instrumentation.RegisterStorageSizeCallbacks(callback, nil, nil, nil, nil))
	start := make(chan struct{})
	registrationErrors := make(chan error, 32)
	operationErrors := make(chan error, 2)
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			<-start
			registrationErrors <- instrumentation.RegisterStorageSizeCallbacks(callback, nil, nil, nil, nil)
		})
	}
	workers.Go(func() {
		<-start
		operationErrors <- instrumentation.Shutdown(t.Context())
	})
	workers.Go(func() {
		<-start
		var collected metricdata.ResourceMetrics
		for range 16 {
			if err := reader.Collect(t.Context(), &collected); err != nil {
				operationErrors <- err
				return
			}
		}
		operationErrors <- nil
	})
	close(start)
	workers.Wait()
	close(registrationErrors)
	close(operationErrors)
	for err := range registrationErrors {
		if err != nil {
			require.ErrorContains(t, err, "shut down")
		}
	}
	for err := range operationErrors {
		require.NoError(t, err)
	}
	callsAtShutdown := calls.Load()
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &collected))
	require.Equal(t, callsAtShutdown, calls.Load(), "no concurrent registration may survive shutdown")
	require.ErrorContains(t, instrumentation.RegisterStorageSizeCallbacks(callback, nil, nil, nil, nil), "shut down")
}
