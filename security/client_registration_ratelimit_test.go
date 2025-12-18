package security

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

const testIP = "192.168.1.1"

func TestNewClientRegistrationRateLimiter(t *testing.T) {
	logger := slog.Default()

	rl := NewClientRegistrationRateLimiter(logger)
	if rl == nil {
		t.Fatal("Expected rate limiter to be created")
	}
	defer rl.Stop()

	if rl.maxPerWindow != DefaultMaxRegistrationsPerHour {
		t.Errorf("Expected maxPerWindow=%d, got %d", DefaultMaxRegistrationsPerHour, rl.maxPerWindow)
	}
	if rl.window != DefaultRegistrationWindow {
		t.Errorf("Expected window=%v, got %v", DefaultRegistrationWindow, rl.window)
	}
	if rl.maxEntries != DefaultMaxRegistrationEntries {
		t.Errorf("Expected maxEntries=%d, got %d", DefaultMaxRegistrationEntries, rl.maxEntries)
	}
}

func TestNewClientRegistrationRateLimiterWithConfig(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name         string
		maxPerWindow int
		window       time.Duration
		maxEntries   int
		wantMax      int
		wantWindow   time.Duration
		wantEntries  int
	}{
		{
			name:         "valid config",
			maxPerWindow: 5,
			window:       30 * time.Minute,
			maxEntries:   1000,
			wantMax:      5,
			wantWindow:   30 * time.Minute,
			wantEntries:  1000,
		},
		{
			name:         "invalid maxPerWindow uses default",
			maxPerWindow: 0,
			window:       time.Hour,
			maxEntries:   1000,
			wantMax:      DefaultMaxRegistrationsPerHour,
			wantWindow:   time.Hour,
			wantEntries:  1000,
		},
		{
			name:         "invalid window uses default",
			maxPerWindow: 10,
			window:       0,
			maxEntries:   1000,
			wantMax:      10,
			wantWindow:   DefaultRegistrationWindow,
			wantEntries:  1000,
		},
		{
			name:         "negative maxEntries uses default",
			maxPerWindow: 10,
			window:       time.Hour,
			maxEntries:   -1,
			wantMax:      10,
			wantWindow:   time.Hour,
			wantEntries:  DefaultMaxRegistrationEntries,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewClientRegistrationRateLimiterWithConfig(tt.maxPerWindow, tt.window, tt.maxEntries, logger)
			defer rl.Stop()

			if rl.maxPerWindow != tt.wantMax {
				t.Errorf("maxPerWindow: got %d, want %d", rl.maxPerWindow, tt.wantMax)
			}
			if rl.window != tt.wantWindow {
				t.Errorf("window: got %v, want %v", rl.window, tt.wantWindow)
			}
			if rl.maxEntries != tt.wantEntries {
				t.Errorf("maxEntries: got %d, want %d", rl.maxEntries, tt.wantEntries)
			}
		})
	}
}

func TestClientRegistrationRateLimiter_Allow(t *testing.T) {
	logger := slog.Default()
	rl := NewClientRegistrationRateLimiterWithConfig(3, time.Hour, 10, logger)
	defer rl.Stop()

	ip := testIP

	// First 3 registrations should be allowed
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Registration %d should be allowed", i+1)
		}
	}

	// 4th registration should be blocked
	if rl.Allow(ip) {
		t.Error("4th registration should be blocked")
	}

	// Check stats
	stats := rl.GetStats()
	if stats.TotalAllowed != 3 {
		t.Errorf("Expected TotalAllowed=3, got %d", stats.TotalAllowed)
	}
	if stats.TotalBlocked != 1 {
		t.Errorf("Expected TotalBlocked=1, got %d", stats.TotalBlocked)
	}
}

func TestClientRegistrationRateLimiter_AllowMultipleIPs(t *testing.T) {
	logger := slog.Default()
	rl := NewClientRegistrationRateLimiterWithConfig(2, time.Hour, 10, logger)
	defer rl.Stop()

	// Two different IPs should have independent limits
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// IP1: 2 registrations allowed
	if !rl.Allow(ip1) {
		t.Error("IP1 registration 1 should be allowed")
	}
	if !rl.Allow(ip1) {
		t.Error("IP1 registration 2 should be allowed")
	}
	if rl.Allow(ip1) {
		t.Error("IP1 registration 3 should be blocked")
	}

	// IP2: should still have 2 registrations available
	if !rl.Allow(ip2) {
		t.Error("IP2 registration 1 should be allowed")
	}
	if !rl.Allow(ip2) {
		t.Error("IP2 registration 2 should be allowed")
	}
	if rl.Allow(ip2) {
		t.Error("IP2 registration 3 should be blocked")
	}
}

func TestClientRegistrationRateLimiter_WindowExpiry(t *testing.T) {
	logger := slog.Default()
	// Use a short window for testing
	window := 100 * time.Millisecond
	rl := NewClientRegistrationRateLimiterWithConfig(2, window, 10, logger)
	defer rl.Stop()

	ip := testIP

	// Use up the limit
	if !rl.Allow(ip) {
		t.Error("Registration 1 should be allowed")
	}
	if !rl.Allow(ip) {
		t.Error("Registration 2 should be allowed")
	}
	if rl.Allow(ip) {
		t.Error("Registration 3 should be blocked")
	}

	// Wait for window to expire
	time.Sleep(window + 50*time.Millisecond)

	// Should be allowed again after window expiry
	if !rl.Allow(ip) {
		t.Error("Registration should be allowed after window expiry")
	}
}

func TestClientRegistrationRateLimiter_LRUEviction(t *testing.T) {
	logger := slog.Default()
	// Small maxEntries to test eviction
	rl := NewClientRegistrationRateLimiterWithConfig(5, time.Hour, 3, logger)
	defer rl.Stop()

	// Fill up to max capacity
	for i := 1; i <= 3; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if !rl.Allow(ip) {
			t.Errorf("IP %s should be allowed", ip)
		}
	}

	// Access IP 1 and 2 to make them recently used
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.2")

	// Add a 4th IP - should evict IP 3 (least recently used)
	if !rl.Allow("192.168.1.4") {
		t.Error("New IP should be allowed")
	}

	stats := rl.GetStats()
	if stats.TotalEvictions != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats.TotalEvictions)
	}
	if stats.CurrentEntries != 3 {
		t.Errorf("Expected 3 entries, got %d", stats.CurrentEntries)
	}
}

func TestClientRegistrationRateLimiter_Cleanup(t *testing.T) {
	logger := slog.Default()
	window := 100 * time.Millisecond
	rl := NewClientRegistrationRateLimiterWithConfig(5, window, 10, logger)
	defer rl.Stop()

	// Create some entries
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.2")
	rl.Allow("192.168.1.3")

	// Verify entries exist
	stats := rl.GetStats()
	if stats.CurrentEntries != 3 {
		t.Errorf("Expected 3 entries, got %d", stats.CurrentEntries)
	}

	// Wait for entries to become idle (2x window)
	time.Sleep(window*2 + 50*time.Millisecond)

	// Run cleanup
	rl.Cleanup()

	// All entries should be removed
	stats = rl.GetStats()
	if stats.CurrentEntries != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", stats.CurrentEntries)
	}
	if stats.TotalCleanups != 1 {
		t.Errorf("Expected 1 cleanup, got %d", stats.TotalCleanups)
	}
}

func TestClientRegistrationRateLimiter_CleanupLoop(t *testing.T) {
	logger := slog.Default()
	window := 50 * time.Millisecond
	cleanupInterval := 100 * time.Millisecond
	rl := newClientRegistrationRateLimiterWithCleanupInterval(5, window, 10, cleanupInterval, logger)
	defer rl.Stop()

	// Create an entry
	rl.Allow("192.168.1.1")

	// Wait for cleanup loop to run (cleanup interval + 2x window)
	time.Sleep(cleanupInterval + window*2 + 100*time.Millisecond)

	// Entry should be cleaned up automatically
	stats := rl.GetStats()
	if stats.CurrentEntries > 0 {
		t.Errorf("Expected automatic cleanup, but still have %d entries", stats.CurrentEntries)
	}
}

func TestClientRegistrationRateLimiter_ConcurrentAccess(t *testing.T) {
	logger := slog.Default()
	rl := NewClientRegistrationRateLimiterWithConfig(100, time.Hour, 1000, logger)
	defer rl.Stop()

	// Test concurrent access from multiple goroutines
	var wg sync.WaitGroup
	numGoroutines := 10
	numRequestsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			ip := testIP
			for j := 0; j < numRequestsPerGoroutine; j++ {
				rl.Allow(ip)
			}
		}(i)
	}

	wg.Wait()

	// Verify total registrations tracked correctly
	stats := rl.GetStats()
	expectedTotal := int64(numGoroutines * numRequestsPerGoroutine)
	actualTotal := stats.TotalAllowed + stats.TotalBlocked
	if actualTotal != expectedTotal {
		t.Errorf("Expected total=%d, got %d (allowed=%d, blocked=%d)",
			expectedTotal, actualTotal, stats.TotalAllowed, stats.TotalBlocked)
	}
}

func TestClientRegistrationRateLimiter_Stop(t *testing.T) {
	_ = t // Test verifies Stop() doesn't panic
	logger := slog.Default()
	rl := NewClientRegistrationRateLimiter(logger)

	// Stop should work multiple times
	rl.Stop()
	rl.Stop()
	rl.Stop()

	// Should not panic
}

func TestClientRegistrationRateLimiter_GetStats(t *testing.T) {
	logger := slog.Default()
	maxPerWindow := 5
	window := time.Hour
	maxEntries := 100
	rl := NewClientRegistrationRateLimiterWithConfig(maxPerWindow, window, maxEntries, logger)
	defer rl.Stop()

	// Add some registrations
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.2")

	stats := rl.GetStats()

	if stats.CurrentEntries != 2 {
		t.Errorf("CurrentEntries: got %d, want 2", stats.CurrentEntries)
	}
	if stats.MaxEntries != maxEntries {
		t.Errorf("MaxEntries: got %d, want %d", stats.MaxEntries, maxEntries)
	}
	if stats.TotalAllowed != 3 {
		t.Errorf("TotalAllowed: got %d, want 3", stats.TotalAllowed)
	}
	if stats.TotalBlocked != 0 {
		t.Errorf("TotalBlocked: got %d, want 0", stats.TotalBlocked)
	}
	if stats.MaxPerWindow != maxPerWindow {
		t.Errorf("MaxPerWindow: got %d, want %d", stats.MaxPerWindow, maxPerWindow)
	}
	if stats.Window != window.String() {
		t.Errorf("Window: got %s, want %s", stats.Window, window.String())
	}

	expectedPressure := (2.0 / 100.0) * 100.0
	if stats.MemoryPressure != expectedPressure {
		t.Errorf("MemoryPressure: got %f, want %f", stats.MemoryPressure, expectedPressure)
	}
}

func TestClientRegistrationRateLimiter_MemoryPressure(t *testing.T) {
	logger := slog.Default()
	rl := NewClientRegistrationRateLimiterWithConfig(10, time.Hour, 10, logger)
	defer rl.Stop()

	// Fill up half the capacity
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		rl.Allow(ip)
	}

	stats := rl.GetStats()
	expectedPressure := 50.0
	if stats.MemoryPressure != expectedPressure {
		t.Errorf("MemoryPressure: got %f, want %f", stats.MemoryPressure, expectedPressure)
	}

	// Fill to capacity
	for i := 6; i <= 10; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		rl.Allow(ip)
	}

	stats = rl.GetStats()
	expectedPressure = 100.0
	if stats.MemoryPressure != expectedPressure {
		t.Errorf("MemoryPressure at capacity: got %f, want %f", stats.MemoryPressure, expectedPressure)
	}
}

func TestClientRegistrationRateLimiter_ZeroMaxEntries(t *testing.T) {
	logger := slog.Default()
	// maxEntries=0 means unlimited
	rl := NewClientRegistrationRateLimiterWithConfig(10, time.Hour, 0, logger)
	defer rl.Stop()

	// Should be able to add many entries without eviction
	for i := 1; i <= 100; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if !rl.Allow(ip) {
			t.Errorf("IP %s should be allowed", ip)
		}
	}

	stats := rl.GetStats()
	if stats.CurrentEntries != 100 {
		t.Errorf("Expected 100 entries, got %d", stats.CurrentEntries)
	}
	if stats.TotalEvictions != 0 {
		t.Errorf("Expected 0 evictions with unlimited capacity, got %d", stats.TotalEvictions)
	}
	if stats.MemoryPressure != 0.0 {
		t.Errorf("Expected 0 memory pressure with unlimited capacity, got %f", stats.MemoryPressure)
	}
}
