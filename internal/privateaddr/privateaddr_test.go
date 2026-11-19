package privateaddr

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowedForListedHost(t *testing.T) {
	tests := []struct {
		addr    string
		allowed bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.4", true},
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"::ffff:10.0.0.1", true},
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},

		{"127.0.0.1", false},
		{"::1", false},
		{"::ffff:127.0.0.1", false},
		{"169.254.169.254", false},
		{"fe80::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"224.0.0.1", false},
		{"100.64.0.1", false},
		{"100.100.100.200", false},
		{"64:ff9b::a9fe:a9fe", false},
		{"192.0.0.1", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			require.Equal(t, tt.allowed, AllowedForListedHost(netip.MustParseAddr(tt.addr)))
		})
	}
}

func TestCheckListedHost(t *testing.T) {
	require.NoError(t, CheckListedHost("dex.internal", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")}))

	err := CheckListedHost("dex.internal", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("127.0.0.1")})
	require.ErrorContains(t, err, `"dex.internal" resolved to 127.0.0.1`)

	require.Error(t, CheckListedHost("dex.internal", []net.IP{{1, 2, 3}}))
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
