package testkit

import (
	"net"
	"net/netip"
	"sync"

	"github.com/aurigax-ai/ostia-server/internal/sni"
)

type ProxyProtocolListener struct {
	net.Listener

	mu      sync.Mutex
	sources []netip.AddrPort
}

type sourcedConn struct {
	net.Conn
	remote net.Addr
}

func (c sourcedConn) RemoteAddr() net.Addr { return c.remote }

func (l *ProxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		src, err := sni.ReadProxyV2(conn)
		if err != nil || !src.IsValid() {
			_ = conn.Close()
			continue
		}
		l.mu.Lock()
		l.sources = append(l.sources, src)
		l.mu.Unlock()
		return sourcedConn{Conn: conn, remote: net.TCPAddrFromAddrPort(src)}, nil
	}
}

func (l *ProxyProtocolListener) Sources() []netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]netip.AddrPort(nil), l.sources...)
}
