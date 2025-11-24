package security

import (
	"testing"
	"time"
)

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "expired 10 minutes ago",
			expiresAt: time.Now().Add(-10 * time.Minute),
			want:      true,
		},
		{
			name:      "expires in 10 minutes",
			expiresAt: time.Now().Add(10 * time.Minute),
			want:      false,
		},
		{
			name:      "expires in 1 second (within grace period)",
			expiresAt: time.Now().Add(1 * time.Second),
			want:      false,
		},
		{
			name:      "expired 1 second ago (within grace period)",
			expiresAt: time.Now().Add(-1 * time.Second),
			want:      false,
		},
		{
			name:      "expired 10 seconds ago (beyond grace period)",
			expiresAt: time.Now().Add(-10 * time.Second),
			want:      true,
		},
		{
			name:      "zero time (never expires)",
			expiresAt: time.Time{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTokenExpired(tt.expiresAt)
			if got != tt.want {
				t.Errorf("IsTokenExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTokenExpiredWithGracePeriod(t *testing.T) {
	tests := []struct {
		name        string
		expiresAt   time.Time
		gracePeriod time.Duration
		want        bool
	}{
		{
			name:        "expired beyond grace period",
			expiresAt:   time.Now().Add(-20 * time.Second),
			gracePeriod: 10 * time.Second,
			want:        true,
		},
		{
			name:        "expired within grace period",
			expiresAt:   time.Now().Add(-5 * time.Second),
			gracePeriod: 10 * time.Second,
			want:        false,
		},
		{
			name:        "not expired",
			expiresAt:   time.Now().Add(10 * time.Minute),
			gracePeriod: 10 * time.Second,
			want:        false,
		},
		{
			name:        "zero grace period",
			expiresAt:   time.Now().Add(-1 * time.Second),
			gracePeriod: 0,
			want:        true,
		},
		{
			name:        "zero time with grace period",
			expiresAt:   time.Time{},
			gracePeriod: 10 * time.Second,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTokenExpiredWithGracePeriod(tt.expiresAt, tt.gracePeriod)
			if got != tt.want {
				t.Errorf("IsTokenExpiredWithGracePeriod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTokenExpiringSoon(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		threshold time.Duration
		want      bool
	}{
		{
			name:      "expiring in 1 minute (threshold 5 minutes)",
			expiresAt: time.Now().Add(1 * time.Minute),
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name:      "expiring in 10 minutes (threshold 5 minutes)",
			expiresAt: time.Now().Add(10 * time.Minute),
			threshold: 5 * time.Minute,
			want:      false,
		},
		{
			name:      "already expired",
			expiresAt: time.Now().Add(-1 * time.Minute),
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name:      "zero time (never expires)",
			expiresAt: time.Time{},
			threshold: 5 * time.Minute,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTokenExpiringSoon(tt.expiresAt, tt.threshold)
			if got != tt.want {
				t.Errorf("IsTokenExpiringSoon() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultClockSkewGracePeriod(t *testing.T) {
	if DefaultClockSkewGracePeriod != 5*time.Second {
		t.Errorf("DefaultClockSkewGracePeriod = %v, want %v", DefaultClockSkewGracePeriod, 5*time.Second)
	}
}
