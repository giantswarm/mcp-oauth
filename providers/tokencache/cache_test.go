package tokencache

import (
	"testing"
)

// tokenTypeAccessToken is the RFC 8693 URN for access tokens.
//
//nolint:gosec // G101: RFC-defined URN identifier, not a credential.
const tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

func TestCache(t *testing.T) {
	t.Run("basic get and set", func(t *testing.T) {
		cache := New()

		key := GenerateCacheKey("https://dex.cluster-b.example.com/token", "cluster-a", "user-123")
		cache.Set(key, "test-token", tokenTypeAccessToken, 3600)

		cached := cache.Get(key)
		if cached == nil {
			t.Fatal("Get() returned nil for existing key")
		}
		if cached.AccessToken != "test-token" {
			t.Errorf("AccessToken = %v, want test-token", cached.AccessToken)
		}
		if cached.IssuedTokenType != tokenTypeAccessToken {
			t.Errorf("IssuedTokenType = %v, want %v", cached.IssuedTokenType, tokenTypeAccessToken)
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		cache := New()

		cached := cache.Get("non-existent")
		if cached != nil {
			t.Error("Get() should return nil for non-existent key")
		}
	})

	t.Run("expired token returns nil", func(t *testing.T) {
		cache := New()

		key := "expired-key"
		// Negative expiresIn puts the expiry well in the past regardless of the buffer.
		cache.Set(key, "expired-token", tokenTypeAccessToken, -60)

		cached := cache.Get(key)
		if cached != nil {
			t.Error("Get() should return nil for expired token")
		}
	})

	t.Run("delete", func(t *testing.T) {
		cache := New()

		key := "delete-key"
		cache.Set(key, "token", tokenTypeAccessToken, 3600)

		if cache.Get(key) == nil {
			t.Fatal("token should exist before delete")
		}

		cache.Delete(key)

		if cache.Get(key) != nil {
			t.Error("token should not exist after delete")
		}
	})

	t.Run("clear", func(t *testing.T) {
		cache := New()

		cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", tokenTypeAccessToken, 3600)

		if cache.Size() != 2 {
			t.Errorf("Size() = %d, want 2", cache.Size())
		}

		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Size() = %d, want 0 after clear", cache.Size())
		}
	})

	t.Run("size", func(t *testing.T) {
		cache := New()

		if cache.Size() != 0 {
			t.Errorf("Size() = %d, want 0 for empty cache", cache.Size())
		}

		cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", tokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", tokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Errorf("Size() = %d, want 3", cache.Size())
		}
	})

	t.Run("cleanup removes expired tokens", func(t *testing.T) {
		cache := New()

		// Add some valid tokens
		cache.Set("valid1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("valid2", "token2", tokenTypeAccessToken, 3600)

		// Negative expiresIn puts the expiry well in the past regardless of the buffer.
		cache.Set("expired1", "token3", tokenTypeAccessToken, -60)
		cache.Set("expired2", "token4", tokenTypeAccessToken, -60)

		if cache.Size() != 4 {
			t.Errorf("Size() = %d, want 4 before cleanup", cache.Size())
		}

		removed := cache.Cleanup()
		if removed != 2 {
			t.Errorf("Cleanup() removed %d, want 2", removed)
		}

		if cache.Size() != 2 {
			t.Errorf("Size() = %d, want 2 after cleanup", cache.Size())
		}

		if cache.Get("valid1") == nil {
			t.Error("valid1 should still exist")
		}
		if cache.Get("valid2") == nil {
			t.Error("valid2 should still exist")
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		cache := New()
		done := make(chan bool)

		// Writer goroutine
		go func() {
			for i := 0; i < 100; i++ {
				key := GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26)))
				cache.Set(key, "token", tokenTypeAccessToken, 3600)
			}
			done <- true
		}()

		// Reader goroutine
		go func() {
			for i := 0; i < 100; i++ {
				key := GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26)))
				_ = cache.Get(key)
			}
			done <- true
		}()

		// Cleanup goroutine
		go func() {
			for i := 0; i < 10; i++ {
				cache.Cleanup()
			}
			done <- true
		}()

		<-done
		<-done
		<-done
	})
}

func TestGenerateCacheKey(t *testing.T) {
	t.Run("generates consistent hash", func(t *testing.T) {
		key1 := GenerateCacheKey("https://dex.example.com/token", "source-cluster", "user-123")
		key2 := GenerateCacheKey("https://dex.example.com/token", "source-cluster", "user-123")
		if key1 != key2 {
			t.Errorf("GenerateCacheKey() should be deterministic, got %v and %v", key1, key2)
		}
		// Key should be base64url encoded SHA-256 (43 chars without padding)
		if len(key1) != 43 {
			t.Errorf("GenerateCacheKey() length = %d, want 43 (base64url SHA-256)", len(key1))
		}
	})

	t.Run("different inputs produce different keys", func(t *testing.T) {
		key1 := GenerateCacheKey("https://dex.example.com/token", "cluster-a", "user-1")
		key2 := GenerateCacheKey("https://dex.example.com/token", "cluster-b", "user-1")
		key3 := GenerateCacheKey("https://dex.example.com/token", "cluster-a", "user-2")
		if key1 == key2 {
			t.Error("Different connector IDs should produce different keys")
		}
		if key1 == key3 {
			t.Error("Different user IDs should produce different keys")
		}
	})

	t.Run("prevents collision with delimiter characters", func(t *testing.T) {
		key1 := GenerateCacheKey("https://a:b", "c", "d")
		key2 := GenerateCacheKey("https://a", "b:c", "d")
		if key1 == key2 {
			t.Error("Keys with delimiter characters in values should not collide")
		}
	})
}

func TestCache_LRUEviction(t *testing.T) {
	t.Run("evicts least recently used when at capacity", func(t *testing.T) {
		cache := NewWithMaxEntries(3)

		cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", tokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", tokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Fatalf("Size() = %d, want 3", cache.Size())
		}

		// Add 4th entry, should evict key1 (least recently used)
		cache.Set("key4", "token4", tokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Errorf("Size() = %d, want 3 after eviction", cache.Size())
		}

		if cache.Get("key1") != nil {
			t.Error("key1 should have been evicted")
		}
		if cache.Get("key2") == nil {
			t.Error("key2 should still exist")
		}
		if cache.Get("key3") == nil {
			t.Error("key3 should still exist")
		}
		if cache.Get("key4") == nil {
			t.Error("key4 should still exist")
		}
	})

	t.Run("accessing entry prevents eviction", func(t *testing.T) {
		cache := NewWithMaxEntries(3)

		cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", tokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", tokenTypeAccessToken, 3600)

		// Access key1 to move it to front
		_ = cache.Get("key1")

		// Add 4th entry, should evict key2 (now least recently used)
		cache.Set("key4", "token4", tokenTypeAccessToken, 3600)

		if cache.Get("key1") == nil {
			t.Error("key1 should still exist after access")
		}
		if cache.Get("key2") != nil {
			t.Error("key2 should have been evicted")
		}
	})

	t.Run("updating entry moves it to front", func(t *testing.T) {
		cache := NewWithMaxEntries(3)

		cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", tokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", tokenTypeAccessToken, 3600)

		cache.Set("key1", "token1-updated", tokenTypeAccessToken, 3600)

		// Add 4th entry, should evict key2 (now least recently used)
		cache.Set("key4", "token4", tokenTypeAccessToken, 3600)

		if cache.Get("key1") == nil {
			t.Error("key1 should still exist after update")
		}
		if cache.Get("key1").AccessToken != "token1-updated" {
			t.Error("key1 should have updated value")
		}
		if cache.Get("key2") != nil {
			t.Error("key2 should have been evicted")
		}
	})
}

func TestCache_GetStats(t *testing.T) {
	cache := NewWithMaxEntries(100)

	stats := cache.GetStats()
	if stats.CurrentEntries != 0 {
		t.Errorf("CurrentEntries = %d, want 0", stats.CurrentEntries)
	}
	if stats.MaxEntries != 100 {
		t.Errorf("MaxEntries = %d, want 100", stats.MaxEntries)
	}
	if stats.TotalEvictions != 0 {
		t.Errorf("TotalEvictions = %d, want 0", stats.TotalEvictions)
	}

	cache.Set("key1", "token1", tokenTypeAccessToken, 3600)
	cache.Set("key2", "token2", tokenTypeAccessToken, 3600)

	stats = cache.GetStats()
	if stats.CurrentEntries != 2 {
		t.Errorf("CurrentEntries = %d, want 2", stats.CurrentEntries)
	}
	if stats.MemoryPressure != 2.0 {
		t.Errorf("MemoryPressure = %f, want 2.0", stats.MemoryPressure)
	}
}

func TestCache_UnlimitedMode(t *testing.T) {
	cache := NewWithMaxEntries(0)

	for i := 0; i < 100; i++ {
		cache.Set(GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26))), "token", tokenTypeAccessToken, 3600)
	}

	stats := cache.GetStats()
	if stats.TotalEvictions != 0 {
		t.Errorf("TotalEvictions = %d, want 0 in unlimited mode", stats.TotalEvictions)
	}
}
