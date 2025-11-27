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

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "URL with trailing slash",
			input: "https://example.com/",
			want:  "https://example.com",
		},
		{
			name:  "URL without trailing slash",
			input: "https://example.com",
			want:  "https://example.com",
		},
		{
			name:  "URL with multiple trailing slashes",
			input: "https://example.com///",
			want:  "https://example.com",
		},
		{
			name:  "URL with path and trailing slash",
			input: "https://example.com/api/v1/",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "URL with path without trailing slash",
			input: "https://example.com/api/v1",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just slashes",
			input: "///",
			want:  "",
		},
		{
			name:  "URL with port and trailing slash",
			input: "https://example.com:8080/",
			want:  "https://example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeURL_Comparison(t *testing.T) {
	// Test that URLs with and without trailing slashes are equal after normalization
	testCases := []struct {
		url1 string
		url2 string
	}{
		{"https://example.com", "https://example.com/"},
		{"https://example.com/api", "https://example.com/api/"},
		{"https://mcp.example.com:8080", "https://mcp.example.com:8080/"},
		{"https://inboxfewer.k8s-internal.home.derstappen.com", "https://inboxfewer.k8s-internal.home.derstappen.com/"},
	}

	for _, tc := range testCases {
		normalized1 := NormalizeURL(tc.url1)
		normalized2 := NormalizeURL(tc.url2)
		if normalized1 != normalized2 {
			t.Errorf("Expected NormalizeURL(%q) == NormalizeURL(%q), got %q != %q",
				tc.url1, tc.url2, normalized1, normalized2)
		}
	}
}
