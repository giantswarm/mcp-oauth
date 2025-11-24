// Package security provides security-related functionality for the OAuth server,
// including rate limiting, encryption, IP validation, and audit logging.
//
// # Rate Limiting
//
// The RateLimiter provides per-identifier rate limiting using a token bucket algorithm
// with automatic memory management through LRU (Least Recently Used) eviction.
//
// ## Memory Management
//
// To prevent unbounded memory growth under distributed attacks, the rate limiter
// implements a configurable maximum entries limit. When this limit is reached,
// the least recently used entries are automatically evicted.
//
// Default configuration:
//   - MaxEntries: 10,000 unique identifiers
//   - CleanupInterval: 5 minutes
//   - IdleTimeout: 30 minutes
//
// ## Example Usage
//
//	// Create rate limiter with default settings (10,000 max entries)
//	limiter := security.NewRateLimiter(10, 20, logger)
//	defer limiter.Stop()
//
//	// Create rate limiter with custom max entries
//	limiter := security.NewRateLimiterWithConfig(10, 20, 5000, logger)
//	defer limiter.Stop()
//
//	// Check if request is allowed
//	if !limiter.Allow(clientIP) {
//	    // Rate limit exceeded
//	    return http.StatusTooManyRequests
//	}
//
//	// Monitor memory usage
//	stats := limiter.GetStats()
//	if stats.MemoryPressure > 80.0 {
//	    logger.Warn("Rate limiter memory pressure high",
//	        "pressure", stats.MemoryPressure,
//	        "current_entries", stats.CurrentEntries,
//	        "max_entries", stats.MaxEntries)
//	}
//
// ## Monitoring and Alerting
//
// The GetStats() method provides metrics for monitoring:
//   - CurrentEntries: Number of tracked identifiers
//   - MaxEntries: Configured limit (0 = unlimited)
//   - TotalEvictions: Number of LRU evictions performed
//   - TotalCleanups: Number of cleanup operations completed
//   - MemoryPressure: Percentage of max capacity used (0-100)
//
// Set up alerts when:
//   - MemoryPressure consistently > 80%: Consider increasing MaxEntries
//   - TotalEvictions increasing rapidly: Possible distributed attack
//   - CurrentEntries near MaxEntries: May need capacity adjustment
//
// ## Security Considerations
//
// The rate limiter is designed to prevent:
//   - Memory exhaustion from distributed attacks
//   - Resource exhaustion through controlled limits
//   - Timing attacks (constant-time operations where possible)
//
// The LRU eviction strategy ensures that legitimate users (who make repeated requests)
// are less likely to be evicted, while one-time attack IPs are evicted first.
package security
