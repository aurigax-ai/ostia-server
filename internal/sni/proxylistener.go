package sni

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func TrustProxyHeaders(ln net.Listener, trusted func(net.Addr) bool, headerTimeout time.Duration) net.Listener {
	policy := func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		if trusted(opts.Upstream) {
			return proxyproto.REQUIRE, nil
		}
		return proxyproto.SKIP, nil
	}
	return &proxyproto.Listener{Listener: ln, ConnPolicy: policy, ReadHeaderTimeout: headerTimeout}
}
