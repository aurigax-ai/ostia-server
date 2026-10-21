package sni

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func tcp(addr string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))
}

func TestProxyV2RoundTripsIPv4AndIPv6(t *testing.T) {
	for _, c := range []struct{ src, dst string }{
		{"203.0.113.9:51000", "192.0.2.1:443"},
		{"[2001:db8::5]:51000", "[2001:db8::1]:443"},
		{"[::ffff:203.0.113.9]:51000", "192.0.2.1:443"},
	} {
		var buf bytes.Buffer
		if err := WriteProxyV2(&buf, tcp(c.src), tcp(c.dst)); err != nil {
			t.Fatal(err)
		}
		buf.WriteString("tls bytes follow")
		got, err := ReadProxyV2(&buf)
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got.Addr().Unmap() != netip.MustParseAddrPort(c.src).Addr().Unmap() || got.Port() != 51000 {
			t.Errorf("%s came back as %s", c.src, got)
		}
		if buf.String() != "tls bytes follow" {
			t.Errorf("%s: the reader consumed the payload: %q", c.src, buf.String())
		}
	}
}

func TestProxyV2LocalForNonTCPAddresses(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteProxyV2(&buf, &net.UnixAddr{Name: "a"}, &net.UnixAddr{Name: "b"}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadProxyV2(&buf)
	if err != nil || got.IsValid() {
		t.Fatalf("a local header carries no address: %v %v", got, err)
	}
}

func TestReadProxyV2RefusesOtherBytes(t *testing.T) {
	if _, err := ReadProxyV2(bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))); err == nil {
		t.Fatal("accepted a request as a header")
	}
	var buf bytes.Buffer
	_ = WriteProxyV2(&buf, tcp("203.0.113.9:1"), tcp("192.0.2.1:2"))
	raw := buf.Bytes()
	raw[14], raw[15] = 0xff, 0xff
	if _, err := ReadProxyV2(bytes.NewReader(raw)); err == nil {
		t.Fatal("accepted an oversize payload length")
	}
}

func FuzzReadProxyV2(f *testing.F) {
	var buf bytes.Buffer
	_ = WriteProxyV2(&buf, tcp("203.0.113.9:1"), tcp("192.0.2.1:2"))
	f.Add(buf.Bytes())
	f.Add([]byte("junk"))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = ReadProxyV2(bytes.NewReader(in))
	})
}
