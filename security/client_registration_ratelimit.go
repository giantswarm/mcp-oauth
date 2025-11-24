package security

import (
	"container/list"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultMaxRegistrationsPerHour is the default limit for client registrations per IP per hour
	DefaultMaxRegistrationsPerHour = 10

	// DefaultRegistrationWindow is the default time window for rate limiting (1 hour)
	DefaultRegistrationWindow = time.Hour

	// DefaultRegistrationCleanupInterval is how often the cleanup goroutine runs
	DefaultRegistrationCleanupInterval = 15 * time.Minute

	// DefaultMaxRegistrationEntries is the maximum number of IPs to track
	DefaultMaxRegistrationEntries = 10000
)

// registrationEntry tracks registration timestamps for an IP address
type registrationEntry struct {
	ip            string
	registrations []time.Time // timestamps of recent registrations
	lastAccess    time.Time   // last time this entry was accessed
}

// ClientRegistrationRateLimiter provides time-windowed rate limiting for client registrations
// to prevent resource exhaustion through repeated registration/deletion cycles.
type ClientRegistrationRateLimiter struct {
	entries         map[string]*list.Element // IP -> list element
	lruList         *list.List               // LRU list of *registrationEntry
	mu              sync.RWMutex
	maxPerWindow    int           // maximum registrations per time window
	window          time.Duration // time window for rate limiting
	maxEntries      int           // maximum number of IPs to track
	logger          *slog.Logger
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	stopOnce        sync.Once

	// Statistics
	totalBlocked   int64 // total registrations blocked
	totalAllowed   int64 // total registrations allowed
	totalEvictions int64 // total LRU evictions
	totalCleanups  int64 // total cleanup operations
}

// NewClientRegistrationRateLimiter creates a new client registration rate limiter with default settings
func NewClientRegistrationRateLimiter(logger *slog.Logger) *ClientRegistrationRateLimiter {
	return NewClientRegistrationRateLimiterWithConfig(
		DefaultMaxRegistrationsPerHour,
		DefaultRegistrationWindow,
		DefaultMaxRegistrationEntries,
		logger,
	)
}

// NewClientRegistrationRateLimiterWithConfig creates a new client registration rate limiter with custom configuration
func NewClientRegistrationRateLimiterWithConfig(maxPerWindow int, window time.Duration, maxEntries int, logger *slog.Logger) *ClientRegistrationRateLimiter {
	return newClientRegistrationRateLimiterWithCleanupInterval(maxPerWindow, window, maxEntries, DefaultRegistrationCleanupInterval, logger)
}

// newClientRegistrationRateLimiterWithCleanupInterval creates a rate limiter with custom cleanup interval (for testing)
func newClientRegistrationRateLimiterWithCleanupInterval(maxPerWindow int, window time.Duration, maxEntries int, cleanupInterval time.Duration, logger *slog.Logger) *ClientRegistrationRateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	if maxPerWindow <= 0 {
		maxPerWindow = DefaultMaxRegistrationsPerHour
		logger.Warn("Invalid maxPerWindow, using default", "maxPerWindow", maxPerWindow)
	}
	if window <= 0 {
		window = DefaultRegistrationWindow
		logger.Warn("Invalid window, using default", "window", window)
	}
	if maxEntries < 0 {
		maxEntries = DefaultMaxRegistrationEntries
		logger.Warn("Invalid maxEntries, using default", "maxEntries", maxEntries)
	}
	if cleanupInterval <= 0 {
		cleanupInterval = DefaultRegistrationCleanupInterval
		logger.Warn("Invalid cleanupInterval, using default", "cleanupInterval", cleanupInterval)
	}

	rl := &ClientRegistrationRateLimiter{
		entries:         make(map[string]*list.Element),
		lruList:         list.New(),
		maxPerWindow:    maxPerWindow,
		window:          window,
		maxEntries:      maxEntries,
		logger:          logger,
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	logger.Info("Client registration rate limiter initialized",
		"max_per_window", maxPerWindow,
		"window", window,
		"max_entries", maxEntries)

	return rl
}

// Allow checks if a client registration from the given IP is allowed
// Returns true if allowed, false if rate limit exceeded
func (rl *ClientRegistrationRateLimiter) Allow(ip string) bool {
	now := time.Now()
	windowStart := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if entry exists for this IP
	if elem, exists := rl.entries[ip]; exists {
		// Move to front (most recently used)
		rl.lruList.MoveToFront(elem)
		entry := elem.Value.(*registrationEntry)
		entry.lastAccess = now

		// Clean old timestamps outside the window (in-place filtering)
		n := 0
		for _, t := range entry.registrations {
			if t.After(windowStart) {
				entry.registrations[n] = t
				n++
			}
		}
		entry.registrations = entry.registrations[:n]

		// Check if limit exceeded
		if len(entry.registrations) >= rl.maxPerWindow {
			rl.totalBlocked++
			rl.logger.Warn("Client registration rate limit exceeded",
				"ip", ip,
				"registrations_in_window", len(entry.registrations),
				"max_per_window", rl.maxPerWindow,
				"window", rl.window,
				"total_blocked", rl.totalBlocked)
			return false
		}

		// Add new registration timestamp
		entry.registrations = append(entry.registrations, now)
		rl.totalAllowed++
		return true
	}

	// Need to create new entry - check if we're at capacity
	if rl.maxEntries > 0 && len(rl.entries) >= rl.maxEntries {
		// Evict least recently used entry
		rl.evictLRU()
	}

	// Create new entry
	entry := &registrationEntry{
		ip:            ip,
		registrations: []time.Time{now},
		lastAccess:    now,
	}

	// Add to front of LRU list (most recently used)
	elem := rl.lruList.PushFront(entry)
	rl.entries[ip] = elem

	rl.totalAllowed++
	rl.logger.Debug("New IP tracked for client registration rate limiting",
		"ip", ip,
		"total_tracked_ips", len(rl.entries))
	return true
}

// evictLRU removes the least recently used entry from the cache
// Must be called with mutex locked
func (rl *ClientRegistrationRateLimiter) evictLRU() {
	if rl.lruList.Len() == 0 {
		return
	}

	// Remove from back (least recently used)
	elem := rl.lruList.Back()
	if elem != nil {
		entry := elem.Value.(*registrationEntry)
		delete(rl.entries, entry.ip)
		rl.lruList.Remove(elem)
		rl.totalEvictions++

		rl.logger.Debug("Client registration rate limiter LRU eviction",
			"ip", entry.ip,
			"total_evictions", rl.totalEvictions,
			"current_entries", len(rl.entries))
	}
}

// cleanupLoop periodically removes inactive entries to prevent memory leaks
func (rl *ClientRegistrationRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.Cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Cleanup removes entries that haven't been accessed recently
// Entries are considered inactive if their last access is older than 2x the window
func (rl *ClientRegistrationRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	// Remove entries that haven't been accessed in 2x the window duration
	maxIdleTime := rl.window * 2
	removed := 0

	// Iterate through LRU list to find and remove idle entries
	var next *list.Element
	for elem := rl.lruList.Front(); elem != nil; elem = next {
		next = elem.Next()
		entry := elem.Value.(*registrationEntry)

		if now.Sub(entry.lastAccess) > maxIdleTime {
			delete(rl.entries, entry.ip)
			rl.lruList.Remove(elem)
			removed++
		}
	}

	if removed > 0 {
		rl.totalCleanups++
		rl.logger.Debug("Client registration rate limiter cleanup completed",
			"removed", removed,
			"remaining", len(rl.entries),
			"total_cleanups", rl.totalCleanups)
	}
}

// Stop gracefully stops the cleanup goroutine
// Safe to call multiple times concurrently
func (rl *ClientRegistrationRateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCleanup)
		rl.logger.Debug("Client registration rate limiter stopped")
	})
}

// RegistrationStats holds client registration rate limiter statistics for monitoring
type RegistrationStats struct {
	CurrentEntries int     // Current number of tracked IPs
	MaxEntries     int     // Maximum allowed entries (0 = unlimited)
	TotalBlocked   int64   // Total registrations blocked
	TotalAllowed   int64   // Total registrations allowed
	TotalEvictions int64   // Total number of LRU evictions
	TotalCleanups  int64   // Total number of cleanup operations
	MaxPerWindow   int     // Maximum registrations per window
	Window         string  // Time window duration
	MemoryPressure float64 // Percentage of max capacity used (0-100)
}

// GetStats returns current rate limiter statistics for monitoring and alerting
func (rl *ClientRegistrationRateLimiter) GetStats() RegistrationStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := RegistrationStats{
		CurrentEntries: len(rl.entries),
		MaxEntries:     rl.maxEntries,
		TotalBlocked:   rl.totalBlocked,
		TotalAllowed:   rl.totalAllowed,
		TotalEvictions: rl.totalEvictions,
		TotalCleanups:  rl.totalCleanups,
		MaxPerWindow:   rl.maxPerWindow,
		Window:         rl.window.String(),
	}

	if rl.maxEntries > 0 {
		stats.MemoryPressure = float64(stats.CurrentEntries) / float64(rl.maxEntries) * 100.0
	}

	return stats
}
