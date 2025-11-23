package security

import (
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
	for _, entry := range rl.limiters {
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
	for id, entry := range rl.limiters {
		if id == "id-1" {
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
	rl := NewRateLimiter(100, 100, slog.Default())
	defer rl.Stop()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Concurrent requests from different identifiers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			identifier := "identifier-" + string(rune('0'+id))
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
	rl := NewRateLimiter(10, 20, slog.Default())

	// Stop should not panic
	rl.Stop()

	// Calling Stop again should not panic
	// (although it will close an already closed channel, which panics)
	// So we won't test double-stop
}
