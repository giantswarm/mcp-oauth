package security

import (
	"container/list"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiterEntry tracks a rate limiter and its last access time
type rateLimiterEntry struct {
	identifier string
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter provides per-identifier rate limiting using token bucket algorithm
// with LRU eviction to prevent unbounded memory growth.
type RateLimiter struct {
	limiters        map[string]*list.Element // identifier -> list element
	lruList         *list.List               // LRU list of *rateLimiterEntry
	mu              sync.RWMutex
	rate            int
	burst           int
	maxEntries      int
	logger          *slog.Logger
	cleanupInterval time.Duration
	stopCleanup     chan struct{}

	// Statistics
	totalEvictions int64
	totalCleanups  int64
}

// NewRateLimiter creates a new rate limiter with automatic cleanup and LRU eviction.
// Default max entries is 10,000. Use NewRateLimiterWithConfig for custom max entries.
func NewRateLimiter(requestsPerSecond, burst int, logger *slog.Logger) *RateLimiter {
	return NewRateLimiterWithConfig(requestsPerSecond, burst, 10000, logger)
}

// NewRateLimiterWithConfig creates a new rate limiter with custom max entries configuration.
// maxEntries controls the maximum number of unique identifiers tracked simultaneously.
// When limit is reached, least recently used entries are evicted.
// Set maxEntries to 0 for unlimited (not recommended for production).
func NewRateLimiterWithConfig(requestsPerSecond, burst, maxEntries int, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	if maxEntries < 0 {
		maxEntries = 10000
		logger.Warn("Invalid maxEntries, using default", "maxEntries", maxEntries)
	}

	rl := &RateLimiter{
		limiters:        make(map[string]*list.Element),
		lruList:         list.New(),
		rate:            requestsPerSecond,
		burst:           burst,
		maxEntries:      maxEntries,
		logger:          logger,
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
		totalEvictions:  0,
		totalCleanups:   0,
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given identifier is allowed.
// Implements LRU eviction when max entries limit is reached.
func (rl *RateLimiter) Allow(identifier string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if limiter exists for this identifier
	if elem, exists := rl.limiters[identifier]; exists {
		// Move to front (most recently used)
		rl.lruList.MoveToFront(elem)
		entry := elem.Value.(*rateLimiterEntry)
		entry.lastAccess = now
		return entry.limiter.Allow()
	}

	// Need to create new limiter - check if we're at capacity
	if rl.maxEntries > 0 && len(rl.limiters) >= rl.maxEntries {
		// Evict least recently used entry
		rl.evictLRU()
	}

	// Create new limiter entry
	entry := &rateLimiterEntry{
		identifier: identifier,
		limiter:    rate.NewLimiter(rate.Limit(rl.rate), rl.burst),
		lastAccess: now,
	}

	// Add to front of LRU list (most recently used)
	elem := rl.lruList.PushFront(entry)
	rl.limiters[identifier] = elem

	return entry.limiter.Allow()
}

// evictLRU removes the least recently used entry from the cache.
// Must be called with mutex locked.
func (rl *RateLimiter) evictLRU() {
	if rl.lruList.Len() == 0 {
		return
	}

	// Remove from back (least recently used)
	elem := rl.lruList.Back()
	if elem != nil {
		entry := elem.Value.(*rateLimiterEntry)
		delete(rl.limiters, entry.identifier)
		rl.lruList.Remove(elem)
		rl.totalEvictions++

		rl.logger.Debug("Rate limiter LRU eviction",
			"identifier", entry.identifier,
			"total_evictions", rl.totalEvictions,
			"current_entries", len(rl.limiters))
	}
}

// cleanupLoop periodically removes inactive rate limiters to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.Cleanup(30 * time.Minute) // Remove limiters idle for 30 minutes
		case <-rl.stopCleanup:
			return
		}
	}
}

// Cleanup removes inactive limiters that haven't been accessed for the given duration.
// Also removes corresponding entries from the LRU list.
func (rl *RateLimiter) Cleanup(maxIdleTime time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	removed := 0

	// Iterate through LRU list to find and remove idle entries
	var next *list.Element
	for elem := rl.lruList.Front(); elem != nil; elem = next {
		next = elem.Next()
		entry := elem.Value.(*rateLimiterEntry)

		if now.Sub(entry.lastAccess) > maxIdleTime {
			delete(rl.limiters, entry.identifier)
			rl.lruList.Remove(elem)
			removed++
		}
	}

	if removed > 0 {
		rl.totalCleanups++
		rl.logger.Debug("Rate limiter cleanup completed",
			"removed", removed,
			"remaining", len(rl.limiters),
			"total_cleanups", rl.totalCleanups)
	}
}

// Stop gracefully stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// Stats holds rate limiter statistics for monitoring
type Stats struct {
	CurrentEntries int     // Current number of tracked identifiers
	MaxEntries     int     // Maximum allowed entries (0 = unlimited)
	TotalEvictions int64   // Total number of LRU evictions
	TotalCleanups  int64   // Total number of cleanup operations
	MemoryPressure float64 // Percentage of max capacity used (0-100)
}

// GetStats returns current rate limiter statistics for monitoring and alerting.
// This is useful for detecting memory pressure and tuning maxEntries configuration.
func (rl *RateLimiter) GetStats() Stats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := Stats{
		CurrentEntries: len(rl.limiters),
		MaxEntries:     rl.maxEntries,
		TotalEvictions: rl.totalEvictions,
		TotalCleanups:  rl.totalCleanups,
	}

	if rl.maxEntries > 0 {
		stats.MemoryPressure = float64(stats.CurrentEntries) / float64(rl.maxEntries) * 100.0
	}

	return stats
}
