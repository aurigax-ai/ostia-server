package sni

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func TrustProxyHeaders(ln net.Listener, trusted []string, headerTimeout time.Duration) (net.Listener, error) {
	policy, err := proxyproto.PolicyFromRanges(trusted, proxyproto.REQUIRE, proxyproto.SKIP)
	if err != nil {
		return nil, err
	}
	return &proxyproto.Listener{Listener: ln, ConnPolicy: policy, ReadHeaderTimeout: headerTimeout}, nil
}
