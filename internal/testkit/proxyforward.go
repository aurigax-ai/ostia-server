package testkit

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
)

type ProxyForwarder struct {
	Addr string

	ln      net.Listener
	target  string
	version byte
	mu      sync.Mutex
	source  netip.AddrPort
}

func StartProxyForwarder(t testing.TB, target string, version byte) *ProxyForwarder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &ProxyForwarder{Addr: ln.Addr().String(), ln: ln, target: target, version: version, source: netip.MustParseAddrPort("203.0.113.1:40000")}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *ProxyForwarder) SetSource(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = netip.MustParseAddrPort(addr)
}

func (f *ProxyForwarder) serve() {
	for {
		client, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.pipe(client)
	}
}

func (f *ProxyForwarder) pipe(client net.Conn) {
	f.mu.Lock()
	source := f.source
	f.mu.Unlock()
	upstream, err := net.Dial("tcp", f.target)
	if err != nil {
		_ = client.Close()
		return
	}
	header := proxyproto.HeaderProxyFromAddrs(f.version, net.TCPAddrFromAddrPort(source), upstream.RemoteAddr())
	if _, err := header.WriteTo(upstream); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
	_ = client.Close()
	_ = upstream.Close()
}
