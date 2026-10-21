package sni

import (
	"bytes"
	"encoding/binary"
	"errors"
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

var ErrNotProxyV2 = errors.New("not a PROXY protocol v2 header")

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

func ReadProxyV2(r io.Reader) (src netip.AddrPort, err error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return netip.AddrPort{}, err
	}
	if !bytes.Equal(header[:12], proxyV2Signature) {
		return netip.AddrPort{}, ErrNotProxyV2
	}
	length := int(binary.BigEndian.Uint16(header[14:16]))
	if length > proxyV2MaxPayload {
		return netip.AddrPort{}, ErrNotProxyV2
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return netip.AddrPort{}, err
	}
	if header[12] != proxyV2Version2Proxy {
		return netip.AddrPort{}, nil
	}
	switch header[13] {
	case proxyV2TCP4:
		if length < proxyV2AddrBytes4 {
			return netip.AddrPort{}, ErrNotProxyV2
		}
		addr, _ := netip.AddrFromSlice(payload[0:4])
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(payload[8:10])), nil
	case proxyV2TCP6:
		if length < proxyV2AddrBytes6 {
			return netip.AddrPort{}, ErrNotProxyV2
		}
		addr, _ := netip.AddrFromSlice(payload[0:16])
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(payload[32:34])), nil
	}
	return netip.AddrPort{}, nil
}
