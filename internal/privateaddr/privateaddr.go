// Package privateaddr is the address policy for hosts an operator lists as
// allowed to resolve to private addresses (CIMD, redirect URI and JWKS host
// lists), and the host key those lists are matched on.
package privateaddr

import (
	"fmt"
	"net"
	"strings"
)

// CheckListedHost returns an error naming the first address in ips that a
// listed host may not resolve to: one that restricted refuses and that is not
// private (net.IP.IsPrivate: RFC 1918 or RFC 4193, an IPv4 address in IPv6
// form checked as IPv4). restricted is the guard the operation applies to an
// unlisted host, so a listed host is never refused an address an unlisted
// host may reach, and gains only RFC 1918 and RFC 4193.
func CheckListedHost(host string, ips []net.IP, restricted func(net.IP) bool) error {
	for _, ip := range ips {
		if restricted(ip) && !ip.IsPrivate() {
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
