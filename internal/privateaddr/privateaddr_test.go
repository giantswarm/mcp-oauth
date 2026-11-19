package privateaddr

import (
	"net"
	"net/netip"
	"testing"

	"code.dny.dev/ssrf"
	"github.com/stretchr/testify/require"
)

var globalOnly = ssrf.New(ssrf.WithAnyPort())

// strictGuard refuses every address that is not globally reachable.
func strictGuard(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return !ok || globalOnly.SafeAddr(addr.Unmap()) != nil
}

// narrowGuard refuses loopback, RFC 1918 / RFC 4193, link-local and
// unspecified addresses only.
func narrowGuard(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func TestCheckListedHost(t *testing.T) {
	tests := []struct {
		addr          string
		strictAllowed bool
		narrowAllowed bool
	}{
		{"10.0.0.1", true, true},
		{"172.16.5.4", true, true},
		{"192.168.1.1", true, true},
		{"fd00::1", true, true},
		{"::ffff:10.0.0.1", true, true},
		{"8.8.8.8", true, true},
		{"2606:4700:4700::1111", true, true},

		{"127.0.0.1", false, false},
		{"::1", false, false},
		{"::ffff:127.0.0.1", false, false},
		{"169.254.169.254", false, false},
		{"fe80::1", false, false},
		{"0.0.0.0", false, false},
		{"::", false, false},

		{"100.64.0.1", false, true},
		{"100.100.100.200", false, true},
		{"64:ff9b::a9fe:a9fe", false, true},
		{"198.18.0.1", false, true},
		{"240.0.0.1", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			ip := net.ParseIP(tt.addr)
			for _, guard := range []struct {
				name     string
				refuses  func(net.IP) bool
				expected bool
			}{
				{"strict", strictGuard, tt.strictAllowed},
				{"narrow", narrowGuard, tt.narrowAllowed},
			} {
				err := CheckListedHost("listed.internal", []net.IP{ip}, guard.refuses)
				require.Equal(t, guard.expected, err == nil, "%s guard: %v", guard.name, err)
				if !guard.refuses(ip) {
					require.NoError(t, err, "%s guard: a listed host must reach what an unlisted host reaches", guard.name)
				}
			}
		})
	}
}

func TestCheckListedHostNamesTheRefusedAddress(t *testing.T) {
	require.NoError(t, CheckListedHost("dex.internal", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")}, strictGuard))

	err := CheckListedHost("dex.internal", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("127.0.0.1")}, strictGuard)
	require.ErrorContains(t, err, `"dex.internal" resolved to 127.0.0.1`)

	require.Error(t, CheckListedHost("dex.internal", []net.IP{{1, 2, 3}}, strictGuard))
}

func TestHostSet(t *testing.T) {
	set := NewHostSet([]string{"Dex.Example.com", ""}, []string{"muster.example.com."})

	for _, host := range []string{"dex.example.com", "DEX.example.com", "dex.example.com.", "muster.example.com", "MUSTER.example.com."} {
		require.True(t, set.Contains(host), host)
	}
	for _, host := range []string{"dex.example.com..", "evil.example.com", "", "example.com"} {
		require.False(t, set.Contains(host), host)
	}
}
