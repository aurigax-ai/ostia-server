package netkey

import "net/netip"

const ipv6PrefixBits = 64

func Of(address string) string {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return address
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6PrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}
