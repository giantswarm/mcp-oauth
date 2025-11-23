package security

import (
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiterEntry tracks a rate limiter and its last access time
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter provides per-identifier rate limiting using token bucket algorithm.
type RateLimiter struct {
	limiters        map[string]*rateLimiterEntry
	mu              sync.RWMutex
	rate            int
	burst           int
	logger          *slog.Logger
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewRateLimiter creates a new rate limiter with automatic cleanup
func NewRateLimiter(requestsPerSecond, burst int, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	rl := &RateLimiter{
		limiters:        make(map[string]*rateLimiterEntry),
		rate:            requestsPerSecond,
		burst:           burst,
		logger:          logger,
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given identifier is allowed
func (rl *RateLimiter) Allow(identifier string) bool {
	now := time.Now()

	rl.mu.Lock()
	entry, exists := rl.limiters[identifier]
	if !exists {
		entry = &rateLimiterEntry{
			limiter:    rate.NewLimiter(rate.Limit(rl.rate), rl.burst),
			lastAccess: now,
		}
		rl.limiters[identifier] = entry
	} else {
		entry.lastAccess = now
	}
	rl.mu.Unlock()

	return entry.limiter.Allow()
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

// Cleanup removes inactive limiters that haven't been accessed for the given duration
func (rl *RateLimiter) Cleanup(maxIdleTime time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	removed := 0
	for identifier, entry := range rl.limiters {
		if now.Sub(entry.lastAccess) > maxIdleTime {
			delete(rl.limiters, identifier)
			removed++
		}
	}

	if removed > 0 {
		rl.logger.Debug("Rate limiter cleanup completed",
			"removed", removed,
			"remaining", len(rl.limiters))
	}
}

// Stop gracefully stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}
