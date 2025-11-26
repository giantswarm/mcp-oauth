package util

import "testing"

func TestSafeTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "string shorter than maxLen",
			input:  "short",
			maxLen: 10,
			want:   "short",
		},
		{
			name:   "string equal to maxLen",
			input:  "exactly10c",
			maxLen: 10,
			want:   "exactly10c",
		},
		{
			name:   "string longer than maxLen",
			input:  "this-is-a-very-long-token-string",
			maxLen: 8,
			want:   "this-is-",
		},
		{
			name:   "empty string",
			input:  "",
			maxLen: 5,
			want:   "",
		},
		{
			name:   "maxLen is zero",
			input:  "test",
			maxLen: 0,
			want:   "",
		},
		{
			name:   "maxLen is negative (edge case)",
			input:  "test",
			maxLen: -1,
			want:   "",
		},
		{
			name:   "unicode characters",
			input:  "hello世界test",
			maxLen: 8,
			want:   "hello世",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeTruncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SafeTruncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSafeTruncate_NoPanic(t *testing.T) {
	// Ensure SafeTruncate never panics, even with edge cases
	testCases := []struct {
		input  string
		maxLen int
	}{
		{"", 0},
		{"", -1},
		{"test", 0},
		{"test", -1},
		{"test", 100},
	}

	for _, tc := range testCases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SafeTruncate(%q, %d) panicked: %v", tc.input, tc.maxLen, r)
				}
			}()
			_ = SafeTruncate(tc.input, tc.maxLen)
		}()
	}
}
