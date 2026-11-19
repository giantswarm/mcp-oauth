// Package privateaddrtest lets a loopback test server stand in for a host on
// a private network.
package privateaddrtest

import (
	"net"

	"github.com/giantswarm/mcp-oauth/internal/privateaddr"
)

// LoopbackAsPrivate returns privateaddr.CheckListedHost for the given guard,
// with loopback addresses accepted as if they were in the private class a host
// list lifts. Every other address gets the production policy.
func LoopbackAsPrivate(restricted func(net.IP) bool) func(host string, ips []net.IP) error {
	return func(host string, ips []net.IP) error {
		for _, ip := range ips {
			if ip.IsLoopback() {
				continue
			}
			if err := privateaddr.CheckListedHost(host, []net.IP{ip}, restricted); err != nil {
				return err
			}
		}
		return nil
	}
}
