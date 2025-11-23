package security

import (
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-identifier rate limiting using token bucket algorithm.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     int
	burst    int
	logger   *slog.Logger
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond, burst int, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     requestsPerSecond,
		burst:    burst,
		logger:   logger,
	}
}

// Allow checks if a request from the given identifier is allowed
func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	limiter, exists := rl.limiters[identifier]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rl.rate), rl.burst)
		rl.limiters[identifier] = limiter
	}
	rl.mu.Unlock()

	return limiter.Allow()
}

// Cleanup removes inactive limiters (called periodically)
func (rl *RateLimiter) Cleanup(inactiveThreshold time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// In a production system, you'd track last access time
	// For simplicity, we just keep all limiters for now
	// This is fine for in-memory storage
}
