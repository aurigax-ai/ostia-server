package sni

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
)

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyV2Version2Proxy = 0x21
	proxyV2Version2Local = 0x20
	proxyV2TCP4          = 0x11
	proxyV2TCP6          = 0x21
	proxyV2Unspec        = 0x00
	proxyV2AddrBytes4    = 12
	proxyV2AddrBytes6    = 36
	proxyV2MaxPayload    = 536
)

func tcpAddrOf(addr net.Addr) (netip.AddrPort, bool) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return tcp.AddrPort(), true
}

func WriteProxyV2(w io.Writer, src, dst net.Addr) error {
	from, srcOK := tcpAddrOf(src)
	to, dstOK := tcpAddrOf(dst)
	var buf bytes.Buffer
	buf.Write(proxyV2Signature)
	if !srcOK || !dstOK {
		buf.Write([]byte{proxyV2Version2Local, proxyV2Unspec, 0, 0})
		_, err := w.Write(buf.Bytes())
		return err
	}
	fromAddr, toAddr := from.Addr().Unmap(), to.Addr().Unmap()
	family, length := byte(proxyV2TCP4), proxyV2AddrBytes4
	if !fromAddr.Is4() || !toAddr.Is4() {
		fromAddr, toAddr = netip.AddrFrom16(from.Addr().As16()), netip.AddrFrom16(to.Addr().As16())
		family, length = proxyV2TCP6, proxyV2AddrBytes6
	}
	buf.Write([]byte{proxyV2Version2Proxy, family})
	_ = binary.Write(&buf, binary.BigEndian, uint16(length))
	buf.Write(fromAddr.AsSlice())
	buf.Write(toAddr.AsSlice())
	_ = binary.Write(&buf, binary.BigEndian, from.Port())
	_ = binary.Write(&buf, binary.BigEndian, to.Port())
	_, err := w.Write(buf.Bytes())
	return err
}
