// Package privateaddr is the address policy for hosts an operator lists as
// allowed to resolve to private addresses (CIMD, redirect URI and JWKS host
// lists), and the host key those lists are matched on.
package privateaddr

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"code.dny.dev/ssrf"
)

// publicGuard accepts only globally reachable addresses: it refuses the IANA
// special-purpose IPv4 ranges, everything outside IPv6 global unicast, and the
// special-purpose ranges inside it.
var publicGuard = ssrf.New(ssrf.WithAnyPort())

// IsListable reports whether addr is in the private class a host list lifts:
// RFC 1918 (10/8, 172.16/12, 192.168/16) or RFC 4193 (fc00::/7). An IPv4
// address in IPv6 form is checked as IPv4.
func IsListable(addr netip.Addr) bool {
	return addr.Unmap().IsPrivate()
}

// AllowedForListedHost reports whether a listed host may resolve to addr: a
// globally reachable address or one in the listable private class. Loopback,
// link-local (cloud metadata), unspecified, multicast, RFC 6598 shared space
// and translation prefixes stay refused.
func AllowedForListedHost(addr netip.Addr) bool {
	addr = addr.Unmap()
	return IsListable(addr) || publicGuard.SafeAddr(addr) == nil
}

// CheckListedHost returns an error naming the first address in ips that a
// listed host may not resolve to, or nil when every address is allowed.
func CheckListedHost(host string, ips []net.IP) error {
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !AllowedForListedHost(addr) {
			return fmt.Errorf("listed host %q resolved to %s, which a private-IP host list does not allow (only RFC 1918 and RFC 4193 are lifted)", host, ip)
		}
	}
	return nil
}

// HostKey is the form a host takes when matched against a private-IP host
// list: lowercased, with one trailing dot removed. It is never used to decide
// whether two redirect URIs or client IDs are equal.
func HostKey(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// HostSet is a set of host keys.
type HostSet map[string]struct{}

// NewHostSet returns the host keys of every entry in lists.
func NewHostSet(lists ...[]string) HostSet {
	set := HostSet{}
	for _, list := range lists {
		for _, host := range list {
			if key := HostKey(host); key != "" {
				set[key] = struct{}{}
			}
		}
	}
	return set
}

// Contains reports whether host's key is in the set.
func (s HostSet) Contains(host string) bool {
	_, ok := s[HostKey(host)]
	return ok
}
