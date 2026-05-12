package security

import (
	"context"
	"time"
)

// encryptionMetricRecorder is the hook the [Encryptor] calls after each
// Encrypt/Decrypt operation. Set via [SetEncryptionMetricRecorder] from
// the instrumentation package (no direct dependency from security).
//
// operation is "encrypt" or "decrypt"; result is "ok" or "fail".
type encryptionMetricRecorder func(ctx context.Context, operation, result string, durationMs float64)

var encryptionMetricFn encryptionMetricRecorder

// SetEncryptionMetricRecorder registers a callback invoked on every
// completed Encrypt/Decrypt. Setting nil disables the hook (zero overhead
// when no metrics backend is wired). Intended to be called once at
// startup from instrumentation wiring code; not safe to swap at request
// time (no synchronization on the package-level global).
func SetEncryptionMetricRecorder(fn encryptionMetricRecorder) {
	encryptionMetricFn = fn
}

// recordEncryption invokes the configured metric recorder, if any.
func recordEncryption(operation string, err error, start time.Time) {
	fn := encryptionMetricFn
	if fn == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "fail"
	}
	fn(context.Background(), operation, result, float64(time.Since(start).Microseconds())/1000.0)
}
