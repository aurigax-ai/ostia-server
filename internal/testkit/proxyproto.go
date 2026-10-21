package testkit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
)

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

var errNotProxyV2 = errors.New("not a PROXY protocol v2 header")

func readProxyV2(r io.Reader) (netip.AddrPort, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return netip.AddrPort{}, err
	}
	if !bytes.Equal(header[:12], proxyV2Signature) {
		return netip.AddrPort{}, errNotProxyV2
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[14:16]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return netip.AddrPort{}, err
	}
	if header[12] != 0x21 {
		return netip.AddrPort{}, nil
	}
	switch header[13] {
	case 0x11:
		addr, _ := netip.AddrFromSlice(payload[0:4])
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(payload[8:10])), nil
	case 0x21:
		addr, _ := netip.AddrFromSlice(payload[0:16])
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(payload[32:34])), nil
	}
	return netip.AddrPort{}, nil
}

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
		src, err := readProxyV2(conn)
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
