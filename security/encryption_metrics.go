package security

import (
	"context"
	"sync/atomic"
	"time"
)

// encryptionMetricRecorder is the hook the [Encryptor] calls after each
// Encrypt/Decrypt operation. Set via [SetEncryptionMetricRecorder] from
// the instrumentation package (no direct dependency from security).
//
// operation is "encrypt" or "decrypt"; result is "ok" or "fail".
type encryptionMetricRecorder func(ctx context.Context, operation, result string, durationMs float64)

var encryptionMetricFn atomic.Pointer[encryptionMetricRecorder]

// SetEncryptionMetricRecorder registers a callback invoked on every
// completed Encrypt/Decrypt. Setting nil disables the hook (zero overhead
// when no metrics backend is wired). Safe to call from multiple goroutines.
//
// The hook is process-wide. Constructing a second [instrumentation.Instrumentation]
// re-registers it, so Encrypt/Decrypt calls from any [Encryptor] in the
// process route to the most recently constructed Instrumentation's meter
// — even if a different Encryptor is attached to a different Server.
// Production deployments build one Server; tests that spin up multiple
// in parallel will see the second registration win.
func SetEncryptionMetricRecorder(fn encryptionMetricRecorder) {
	if fn == nil {
		encryptionMetricFn.Store(nil)
		return
	}
	encryptionMetricFn.Store(&fn)
}

// recordEncryption invokes the configured metric recorder, if any.
func recordEncryption(operation string, err error, start time.Time) {
	fnPtr := encryptionMetricFn.Load()
	if fnPtr == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "fail"
	}
	(*fnPtr)(context.Background(), operation, result, float64(time.Since(start).Microseconds())/1000.0)
}
