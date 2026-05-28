package security

import (
	"context"
	"sync"
	"testing"
)

func TestSetEncryptionMetricRecorderConcurrent(t *testing.T) {
	t.Cleanup(func() { SetEncryptionMetricRecorder(nil) })

	recorder := func(_ context.Context, _, _ string, _ float64) {}

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			SetEncryptionMetricRecorder(recorder)
		}()
		go func() {
			defer wg.Done()
			SetEncryptionMetricRecorder(nil)
		}()
	}
	wg.Wait()
}
