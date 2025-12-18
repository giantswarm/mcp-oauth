package security

import (
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 20, nil)
	defer rl.Stop()

	if rl == nil {
		t.Fatal("NewRateLimiter() returned nil")
	}

	if rl.rate != 10 {
		t.Errorf("rate = %d, want 10", rl.rate)
	}

	if rl.burst != 20 {
		t.Errorf("burst = %d, want 20", rl.burst)
	}

	if rl.logger == nil {
		t.Error("logger should not be nil")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(10, 5, slog.Default())
	defer rl.Stop()

	identifier := "test-identifier"

	// First requests up to burst should be allowed
	for i := 0; i < 5; i++ {
		if !rl.Allow(identifier) {
			t.Errorf("Allow() request %d should be allowed", i+1)
		}
	}

	// Next request should be rate limited
	if rl.Allow(identifier) {
		t.Error("Allow() should return false when rate limited")
	}
}

func TestRateLimiter_Allow_MultipleIdentifiers(t *testing.T) {
	rl := NewRateLimiter(10, 2, slog.Default())
	defer rl.Stop()

	// Different identifiers should have separate limits
	id1 := "identifier-1"
	id2 := "identifier-2"

	// Exhaust limit for id1
	for i := 0; i < 2; i++ {
		if !rl.Allow(id1) {
			t.Errorf("Allow(id1) request %d should be allowed", i+1)
		}
	}

	// id1 should be limited
	if rl.Allow(id1) {
		t.Error("Allow(id1) should return false when rate limited")
	}

	// id2 should still be allowed
	if !rl.Allow(id2) {
		t.Error("Allow(id2) should be allowed (different identifier)")
	}
}

func TestRateLimiter_Allow_RefillOverTime(t *testing.T) {
	// Create rate limiter: 2 requests per second, burst of 2
	rl := NewRateLimiter(2, 2, slog.Default())
	defer rl.Stop()

	identifier := "test-identifier"

	// Exhaust burst
	for i := 0; i < 2; i++ {
		if !rl.Allow(identifier) {
			t.Errorf("Allow() request %d should be allowed", i+1)
		}
	}

	// Should be rate limited immediately
	if rl.Allow(identifier) {
		t.Error("Allow() should return false when rate limited")
	}

	// Wait for token refill (500ms for 1 token at 2 req/s)
	time.Sleep(550 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow(identifier) {
		t.Error("Allow() should be allowed after token refill")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := NewRateLimiter(10, 20, slog.Default())
	defer rl.Stop()

	// Create some limiters
	rl.Allow("id-1")
	rl.Allow("id-2")
	rl.Allow("id-3")

	// Verify they exist
	rl.mu.RLock()
	initialCount := len(rl.limiters)
	rl.mu.RUnlock()

	if initialCount != 3 {
		t.Errorf("initial limiter count = %d, want 3", initialCount)
	}

	// Manually update last access time to make them appear idle
	rl.mu.Lock()
	for elem := rl.lruList.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*rateLimiterEntry)
		entry.lastAccess = time.Now().Add(-1 * time.Hour)
	}
	rl.mu.Unlock()

	// Run cleanup
	rl.Cleanup(30 * time.Minute)

	// Verify they were cleaned up
	rl.mu.RLock()
	finalCount := len(rl.limiters)
	rl.mu.RUnlock()

	if finalCount != 0 {
		t.Errorf("final limiter count = %d, want 0", finalCount)
	}
}

func TestRateLimiter_Cleanup_KeepsActive(t *testing.T) {
	rl := NewRateLimiter(10, 20, slog.Default())
	defer rl.Stop()

	// Create some limiters
	rl.Allow("id-1")
	rl.Allow("id-2")

	// Manually update only one to be idle
	rl.mu.Lock()
	for elem := rl.lruList.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*rateLimiterEntry)
		if entry.identifier == "id-1" {
			entry.lastAccess = time.Now().Add(-1 * time.Hour)
		}
	}
	rl.mu.Unlock()

	// Run cleanup
	rl.Cleanup(30 * time.Minute)

	// Verify only the idle one was cleaned up
	rl.mu.RLock()
	finalCount := len(rl.limiters)
	_, hasActive := rl.limiters["id-2"]
	rl.mu.RUnlock()

	if finalCount != 1 {
		t.Errorf("final limiter count = %d, want 1", finalCount)
	}

	if !hasActive {
		t.Error("active limiter should not be cleaned up")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	_ = t // Test verifies no race conditions when run with -race flag
	rl := NewRateLimiter(100, 100, slog.Default())
	defer rl.Stop()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Concurrent requests from different identifiers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			identifier := fmt.Sprintf("identifier-%d", id)
			for j := 0; j < 10; j++ {
				rl.Allow(identifier)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify no race conditions (test passes if no data race detected)
}

func TestRateLimiter_Stop(t *testing.T) {
	_ = t // Test verifies Stop() doesn't panic
	rl := NewRateLimiter(10, 20, slog.Default())

	// Stop should not panic
	rl.Stop()

	// Calling Stop again should not panic (now safe to call multiple times)
	rl.Stop()
	rl.Stop() // Third time for good measure
}

// Test concurrent Stop() calls don't cause race conditions or panics
func TestRateLimiter_Stop_Concurrent(t *testing.T) {
	rl := NewRateLimiter(10, 20, slog.Default())

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	// Launch many goroutines all trying to Stop() simultaneously
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Stop() panicked: %v", r)
				}
				done <- true
			}()
			rl.Stop()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify cleanup goroutine actually stopped by checking channel is closed
	select {
	case <-rl.stopCleanup:
		// Channel is closed, as expected
	default:
		t.Error("stopCleanup channel should be closed")
	}
}

// Test Stop() is safe even while rate limiter is actively processing requests
func TestRateLimiter_Stop_WhileActive(t *testing.T) {
	_ = t // Test verifies no race conditions when run with -race flag
	rl := NewRateLimiter(100, 100, slog.Default())

	const numWorkers = 50
	done := make(chan bool, numWorkers)
	stop := make(chan bool)

	// Workers continuously making requests
	for i := 0; i < numWorkers; i++ {
		go func(id int) {
			identifier := fmt.Sprintf("worker-%d", id)
			for {
				select {
				case <-stop:
					done <- true
					return
				default:
					rl.Allow(identifier)
				}
			}
		}(i)
	}

	// Let workers run for a bit
	time.Sleep(50 * time.Millisecond)

	// Stop the rate limiter while workers are active
	rl.Stop()

	// Stop workers
	close(stop)
	for i := 0; i < numWorkers; i++ {
		<-done
	}

	// Should be able to call Stop() again without panic
	rl.Stop()
}

// Test max entries configuration
func TestNewRateLimiterWithConfig(t *testing.T) {
	tests := []struct {
		name        string
		maxEntries  int
		expectedMax int
		shouldWarn  bool
	}{
		{
			name:        "valid max entries",
			maxEntries:  1000,
			expectedMax: 1000,
			shouldWarn:  false,
		},
		{
			name:        "zero max entries (unlimited)",
			maxEntries:  0,
			expectedMax: 0,
			shouldWarn:  false,
		},
		{
			name:        "negative max entries defaults to DefaultMaxEntries",
			maxEntries:  -1,
			expectedMax: DefaultMaxEntries,
			shouldWarn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiterWithConfig(10, 20, tt.maxEntries, slog.Default())
			defer rl.Stop()

			if rl.maxEntries != tt.expectedMax {
				t.Errorf("maxEntries = %d, want %d", rl.maxEntries, tt.expectedMax)
			}
		})
	}
}

// Test LRU eviction when max entries is reached
func TestRateLimiter_LRUEviction(t *testing.T) {
	// Create rate limiter with max 3 entries
	rl := NewRateLimiterWithConfig(100, 100, 3, slog.Default())
	defer rl.Stop()

	// Add 3 identifiers
	rl.Allow("id-1")
	rl.Allow("id-2")
	rl.Allow("id-3")

	stats := rl.GetStats()
	if stats.CurrentEntries != 3 {
		t.Errorf("CurrentEntries = %d, want 3", stats.CurrentEntries)
	}

	// Add 4th identifier - should evict id-1 (least recently used)
	rl.Allow("id-4")

	stats = rl.GetStats()
	if stats.CurrentEntries != 3 {
		t.Errorf("CurrentEntries = %d, want 3 (after eviction)", stats.CurrentEntries)
	}

	if stats.TotalEvictions != 1 {
		t.Errorf("TotalEvictions = %d, want 1", stats.TotalEvictions)
	}

	// Verify id-1 was evicted
	rl.mu.RLock()
	_, hasID1 := rl.limiters["id-1"]
	_, hasID2 := rl.limiters["id-2"]
	_, hasID3 := rl.limiters["id-3"]
	_, hasID4 := rl.limiters["id-4"]
	rl.mu.RUnlock()

	if hasID1 {
		t.Error("id-1 should have been evicted")
	}
	if !hasID2 || !hasID3 || !hasID4 {
		t.Error("id-2, id-3, and id-4 should be present")
	}
}

// Test that accessing an entry moves it to front (prevents eviction)
func TestRateLimiter_LRUAccessUpdatesOrder(t *testing.T) {
	// Create rate limiter with max 3 entries
	rl := NewRateLimiterWithConfig(100, 100, 3, slog.Default())
	defer rl.Stop()

	// Add 3 identifiers
	rl.Allow("id-1")
	rl.Allow("id-2")
	rl.Allow("id-3")

	// Access id-1 again (moves to front)
	rl.Allow("id-1")

	// Add 4th identifier - should evict id-2 (now least recently used)
	rl.Allow("id-4")

	// Verify id-2 was evicted, not id-1
	rl.mu.RLock()
	_, hasID1 := rl.limiters["id-1"]
	_, hasID2 := rl.limiters["id-2"]
	_, hasID3 := rl.limiters["id-3"]
	_, hasID4 := rl.limiters["id-4"]
	rl.mu.RUnlock()

	if !hasID1 {
		t.Error("id-1 should be present (was accessed recently)")
	}
	if hasID2 {
		t.Error("id-2 should have been evicted (least recently used)")
	}
	if !hasID3 || !hasID4 {
		t.Error("id-3 and id-4 should be present")
	}
}

// Test memory bounds with many unique identifiers
func TestRateLimiter_MemoryBounds(t *testing.T) {
	const maxEntries = 100
	const totalRequests = 500

	rl := NewRateLimiterWithConfig(1000, 1000, maxEntries, slog.Default())
	defer rl.Stop()

	// Generate requests for many unique identifiers
	for i := 0; i < totalRequests; i++ {
		identifier := "id-" + string(rune('0'+i))
		rl.Allow(identifier)
	}

	stats := rl.GetStats()

	// Should never exceed max entries
	if stats.CurrentEntries > maxEntries {
		t.Errorf("CurrentEntries = %d, exceeds maxEntries = %d", stats.CurrentEntries, maxEntries)
	}

	// Should have evicted some entries
	expectedEvictions := totalRequests - maxEntries
	if stats.TotalEvictions < int64(expectedEvictions) {
		t.Errorf("TotalEvictions = %d, expected at least %d", stats.TotalEvictions, expectedEvictions)
	}
}

// Test GetStats returns accurate information
func TestRateLimiter_GetStats(t *testing.T) {
	rl := NewRateLimiterWithConfig(10, 20, 100, slog.Default())
	defer rl.Stop()

	// Initial stats
	stats := rl.GetStats()
	if stats.CurrentEntries != 0 {
		t.Errorf("Initial CurrentEntries = %d, want 0", stats.CurrentEntries)
	}
	if stats.MaxEntries != 100 {
		t.Errorf("MaxEntries = %d, want 100", stats.MaxEntries)
	}
	if stats.MemoryPressure != 0 {
		t.Errorf("Initial MemoryPressure = %.2f, want 0", stats.MemoryPressure)
	}

	// Add some entries
	for i := 0; i < 50; i++ {
		rl.Allow("id-" + string(rune('0'+i)))
	}

	stats = rl.GetStats()
	if stats.CurrentEntries != 50 {
		t.Errorf("CurrentEntries = %d, want 50", stats.CurrentEntries)
	}

	expectedPressure := 50.0
	if stats.MemoryPressure < expectedPressure-1 || stats.MemoryPressure > expectedPressure+1 {
		t.Errorf("MemoryPressure = %.2f, want ~%.2f", stats.MemoryPressure, expectedPressure)
	}
}

// Test cleanup also updates LRU list correctly
func TestRateLimiter_CleanupWithLRU(t *testing.T) {
	rl := NewRateLimiterWithConfig(10, 20, 100, slog.Default())
	defer rl.Stop()

	// Create some limiters
	rl.Allow("id-1")
	rl.Allow("id-2")
	rl.Allow("id-3")

	// Manually update last access time to make some appear idle
	rl.mu.Lock()
	for elem := rl.lruList.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*rateLimiterEntry)
		if entry.identifier == "id-1" || entry.identifier == "id-2" {
			entry.lastAccess = time.Now().Add(-1 * time.Hour)
		}
	}
	rl.mu.Unlock()

	// Run cleanup
	rl.Cleanup(30 * time.Minute)

	// Verify idle ones were cleaned up
	rl.mu.RLock()
	currentCount := len(rl.limiters)
	lruCount := rl.lruList.Len()
	_, hasID1 := rl.limiters["id-1"]
	_, hasID2 := rl.limiters["id-2"]
	_, hasID3 := rl.limiters["id-3"]
	rl.mu.RUnlock()

	if currentCount != 1 {
		t.Errorf("limiter map count = %d, want 1", currentCount)
	}

	if lruCount != 1 {
		t.Errorf("LRU list count = %d, want 1", lruCount)
	}

	if hasID1 || hasID2 {
		t.Error("id-1 and id-2 should be cleaned up")
	}

	if !hasID3 {
		t.Error("id-3 should be present")
	}

	stats := rl.GetStats()
	if stats.TotalCleanups != 1 {
		t.Errorf("TotalCleanups = %d, want 1", stats.TotalCleanups)
	}
}

// Test concurrent access with LRU eviction
func TestRateLimiter_ConcurrentWithEviction(t *testing.T) {
	rl := NewRateLimiterWithConfig(1000, 1000, 50, slog.Default())
	defer rl.Stop()

	const numGoroutines = 20
	const requestsPerGoroutine = 100
	done := make(chan bool, numGoroutines)

	// Concurrent requests from many identifiers
	for i := 0; i < numGoroutines; i++ {
		go func(base int) {
			for j := 0; j < requestsPerGoroutine; j++ {
				identifier := "id-" + string(rune('0'+base*requestsPerGoroutine+j))
				rl.Allow(identifier)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	stats := rl.GetStats()

	// Should respect max entries limit even under concurrent load
	if stats.CurrentEntries > 50 {
		t.Errorf("CurrentEntries = %d, exceeds max 50 under concurrent load", stats.CurrentEntries)
	}

	// Should have performed evictions
	if stats.TotalEvictions == 0 {
		t.Error("Expected evictions under concurrent load")
	}
}

// Test unlimited mode (maxEntries = 0)
func TestRateLimiter_UnlimitedMode(t *testing.T) {
	rl := NewRateLimiterWithConfig(100, 100, 0, slog.Default())
	defer rl.Stop()

	// Add many entries
	for i := 0; i < 1000; i++ {
		rl.Allow("id-" + string(rune('0'+i)))
	}

	stats := rl.GetStats()

	// Should allow all entries without eviction
	if stats.CurrentEntries != 1000 {
		t.Errorf("CurrentEntries = %d, want 1000 (unlimited mode)", stats.CurrentEntries)
	}

	if stats.TotalEvictions != 0 {
		t.Errorf("TotalEvictions = %d, want 0 (unlimited mode)", stats.TotalEvictions)
	}

	if stats.MaxEntries != 0 {
		t.Errorf("MaxEntries = %d, want 0 (unlimited mode)", stats.MaxEntries)
	}
}

// Benchmark memory usage with large number of entries
func BenchmarkRateLimiter_LargeScale(b *testing.B) {
	rl := NewRateLimiterWithConfig(1000, 1000, 10000, slog.Default())
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		identifier := "id-" + string(rune('0'+(i%15000)))
		rl.Allow(identifier)
	}
}

// Benchmark LRU eviction overhead
func BenchmarkRateLimiter_Eviction(b *testing.B) {
	rl := NewRateLimiterWithConfig(1000, 1000, 100, slog.Default())
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Will cause evictions after first 100
		identifier := "id-" + string(rune('0'+i))
		rl.Allow(identifier)
	}
}
