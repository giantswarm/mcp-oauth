package util

import (
	"net"
	"testing"
)

func TestClassifyIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected IPClassification
	}{
		// Unspecified addresses
		{"IPv4 unspecified", "0.0.0.0", IPClassificationUnspecified},
		{"IPv6 unspecified", "::", IPClassificationUnspecified},

		// Loopback addresses
		{"IPv4 loopback 127.0.0.1", "127.0.0.1", IPClassificationLoopback},
		{"IPv4 loopback 127.255.255.255", "127.255.255.255", IPClassificationLoopback},
		{"IPv6 loopback", "::1", IPClassificationLoopback},

		// Link-local addresses
		{"IPv4 link-local", "169.254.0.1", IPClassificationLinkLocal},
		{"IPv4 cloud metadata", "169.254.169.254", IPClassificationLinkLocal},
		{"IPv6 link-local unicast", "fe80::1", IPClassificationLinkLocal},
		{"IPv6 link-local multicast", "ff02::1", IPClassificationLinkLocal},

		// Private addresses (RFC 1918)
		{"IPv4 private 10.x", "10.0.0.1", IPClassificationPrivate},
		{"IPv4 private 172.16.x", "172.16.0.1", IPClassificationPrivate},
		{"IPv4 private 192.168.x", "192.168.1.1", IPClassificationPrivate},
		{"IPv6 ULA fc00::", "fc00::1", IPClassificationPrivate},
		{"IPv6 ULA fd00::", "fd00::1", IPClassificationPrivate},

		// Public addresses
		{"IPv4 public", "8.8.8.8", IPClassificationPublic},
		{"IPv4 public Cloudflare", "1.1.1.1", IPClassificationPublic},
		{"IPv6 public Google DNS", "2001:4860:4860::8888", IPClassificationPublic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := ClassifyIP(ip)
			if got != tt.expected {
				t.Errorf("ClassifyIP(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestClassifyIP_Nil(t *testing.T) {
	got := ClassifyIP(nil)
	if got != IPClassificationUnspecified {
		t.Errorf("ClassifyIP(nil) = %v, want %v", got, IPClassificationUnspecified)
	}
}

func TestIPClassification_String(t *testing.T) {
	tests := []struct {
		classification IPClassification
		expected       string
	}{
		{IPClassificationPublic, "public"},
		{IPClassificationLoopback, "loopback"},
		{IPClassificationPrivate, "private"},
		{IPClassificationLinkLocal, "link_local"},
		{IPClassificationUnspecified, "unspecified"},
		{IPClassification(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.classification.String()
			if got != tt.expected {
				t.Errorf("IPClassification.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv4 link-local", "169.254.0.1", true},
		{"IPv4 cloud metadata", "169.254.169.254", true},
		{"IPv6 link-local unicast", "fe80::1", true},
		{"IPv6 link-local multicast", "ff02::1", true},
		{"IPv4 public", "8.8.8.8", false},
		{"IPv4 private", "10.0.0.1", false},
		{"IPv4 loopback", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := IsLinkLocal(ip)
			if got != tt.expected {
				t.Errorf("IsLinkLocal(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestIsPrivateOrInternal(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Public IP", "8.8.8.8", false},
		{"Private IP", "10.0.0.1", true},
		{"Loopback IP", "127.0.0.1", true},
		{"Link-local IP", "169.254.0.1", true},
		{"Unspecified IP", "0.0.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := IsPrivateOrInternal(ip)
			if got != tt.expected {
				t.Errorf("IsPrivateOrInternal(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestIsLoopbackHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		{"localhost", "localhost", true},
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback range", "127.255.255.255", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 loopback bracketed", "[::1]", true},
		{"IPv4 private", "10.0.0.1", false},
		{"Public hostname", "example.com", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLoopbackHostname(tt.hostname)
			if got != tt.expected {
				t.Errorf("IsLoopbackHostname(%s) = %v, want %v", tt.hostname, got, tt.expected)
			}
		})
	}
}
