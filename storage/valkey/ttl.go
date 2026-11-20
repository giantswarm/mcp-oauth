package valkey

import "time"

func ceilSeconds(ttl time.Duration) int64 {
	seconds := int64(ttl / time.Second)
	if ttl%time.Second > 0 {
		seconds++
	}
	return max(seconds, 1)
}
