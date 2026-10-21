package sni

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: serverName == "", MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.HandshakeContext(ctx)
		_ = client.Close()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	return append(header, body...)
}

func TestPeekReadsServerNameAndReturnsEveryByteConsumed(t *testing.T) {
	hello := clientHello(t, "Abc.R.Example.com")
	name, consumed, err := Peek(bytes.NewReader(hello))
	if err != nil || name != "abc.r.example.com" {
		t.Fatalf("name %q err %v", name, err)
	}
	if !bytes.Equal(consumed, hello) {
		t.Fatal("consumed bytes differ from what was read")
	}
}

func TestPeekWithoutServerName(t *testing.T) {
	name, _, err := Peek(bytes.NewReader(clientHello(t, "")))
	if err != nil || name != "" {
		t.Fatalf("name %q err %v", name, err)
	}
}

func TestPeekReassemblesAHelloSplitAcrossRecords(t *testing.T) {
	hello := clientHello(t, "split.example.com")
	handshake := hello[5:]
	cut := len(handshake) / 2
	var split []byte
	for _, part := range [][]byte{handshake[:cut], handshake[cut:]} {
		split = append(split, 0x16, 0x03, 0x01, byte(len(part)>>8), byte(len(part)))
		split = append(split, part...)
	}
	name, consumed, err := Peek(bytes.NewReader(split))
	if err != nil || name != "split.example.com" || !bytes.Equal(consumed, split) {
		t.Fatalf("name %q err %v", name, err)
	}
}

func TestPeekRefusesWhatIsNotAClientHello(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"http":          {[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), ErrNotTLS},
		"zero length":   {[]byte{0x16, 3, 1, 0, 0}, ErrNotTLS},
		"huge record":   {[]byte{0x16, 3, 1, 0xff, 0xff}, ErrNotTLS},
		"server hello":  {[]byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}, ErrNotClientHello},
		"truncated":     {[]byte{0x16, 3, 1, 0, 50, 1, 0}, io.ErrUnexpectedEOF},
		"empty":         {nil, io.EOF},
		"hello too big": {[]byte{0x16, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff}, ErrMalformed},
	}
	for name, c := range cases {
		if _, _, err := Peek(bytes.NewReader(c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

func TestPeekMalformedBodies(t *testing.T) {
	short := []byte{0x16, 3, 1, 0, 8, 1, 0, 0, 4, 3, 3, 0, 0}
	if _, _, err := Peek(bytes.NewReader(short)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short body: %v", err)
	}
}

func FuzzPeek(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{0x16, 3, 1, 0, 8, 1, 0, 0, 4, 3, 3, 0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		name, consumed, _ := Peek(bytes.NewReader(in))
		if len(consumed) > len(in) {
			t.Fatalf("consumed %d of %d bytes", len(consumed), len(in))
		}
		if !bytes.HasPrefix(in, consumed) {
			t.Fatal("consumed bytes are not a prefix of the input")
		}
		_ = name
	})
}

func TestRouterSplicesRelayHostsAndReplaysOthers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	relayed := make(chan struct {
		label string
		hello []byte
	}, 1)
	others := make(chan net.Conn, 1)
	router := &Router{
		HelloTimeout: time.Second,
		MaxPending:   4,
		Classify: func(name string) (Kind, string) {
			if label, ok := stripSuffix(name, ".r.test"); ok {
				return Relay, label
			}
			return Other, ""
		},
		OnRelay: func(conn net.Conn, label string, hello []byte, _ time.Time) {
			relayed <- struct {
				label string
				hello []byte
			}{label, hello}
			_ = conn.Close()
		},
		OnOther: func(conn net.Conn) { others <- conn },
	}
	go func() { _ = router.Serve(ln) }()

	dial := func(name string) {
		go func() {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				return
			}
			c := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			_ = c.Handshake()
			_ = conn.Close()
		}()
	}
	dial("label1.r.test")
	select {
	case got := <-relayed:
		if got.label != "label1" || len(got.hello) == 0 || got.hello[0] != 0x16 {
			t.Fatalf("relay got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay host not routed")
	}

	dial("api.test")
	select {
	case conn := <-others:
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x16 {
			t.Fatalf("prefix not replayed: %v %v", buf, err)
		}
		_ = conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("other host not routed")
	}
}

func stripSuffix(name, suffix string) (string, bool) {
	if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
		return name[:len(name)-len(suffix)], true
	}
	return "", false
}

func TestRouterHoldsNonTLSThenClosesWithoutReply(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	router := &Router{
		HelloTimeout: 300 * time.Millisecond,
		MaxPending:   4,
		Classify:     func(string) (Kind, string) { return Other, "" },
		OnRelay:      func(net.Conn, string, []byte, time.Time) {},
		OnOther:      func(c net.Conn) { _ = c.Close() },
	}
	go func() { _ = router.Serve(ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("server replied to non-TLS: %q %v", buf[:n], err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatalf("non-TLS connection closed after %v, it must be held until the hello timeout", time.Since(start))
	}
}

func TestRouterRefusesBeyondMaxPending(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	router := &Router{
		HelloTimeout: 2 * time.Second,
		MaxPending:   1,
		Classify:     func(string) (Kind, string) { return Other, "" },
		OnRelay:      func(net.Conn, string, []byte, time.Time) {},
		OnOther:      func(c net.Conn) { _ = c.Close() },
	}
	go func() { _ = router.Serve(ln) }()
	first, _ := net.Dial("tcp", ln.Addr().String())
	defer first.Close()
	time.Sleep(100 * time.Millisecond)
	second, _ := net.Dial("tcp", ln.Addr().String())
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second connection beyond the cap must be closed at once, got %v", err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("second connection was held instead of closed: %v", err)
	}
}

type fakeAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeAddrConn) RemoteAddr() net.Addr { return c.remote }

type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn, 64), closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error   { close(l.closed); return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (l *fakeListener) dial(ip string) net.Conn {
	client, server := net.Pipe()
	l.conns <- fakeAddrConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}}
	return client
}

func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	ne, timeout := err.(net.Error)
	return err != nil && !(timeout && ne.Timeout())
}

func TestOneAddressCannotUseUpTheHelloPool(t *testing.T) {
	ln := newFakeListener()
	defer ln.Close()
	router := &Router{
		HelloTimeout:    3 * time.Second,
		MaxPending:      8,
		MaxPendingPerIP: 2,
		Classify:        func(string) (Kind, string) { return Other, "" },
		OnRelay:         func(net.Conn, string, []byte, time.Time) {},
		OnOther:         func(c net.Conn) { _ = c.Close() },
	}
	go func() { _ = router.Serve(ln) }()

	var flood []net.Conn
	for range 6 {
		flood = append(flood, ln.dial("198.51.100.1"))
	}
	defer func() {
		for _, c := range flood {
			_ = c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	refused := 0
	for _, c := range flood {
		if closedWithin(c, 50*time.Millisecond) {
			refused++
		}
	}
	if refused != 4 {
		t.Fatalf("a single address may hold 2 pending hellos, so 4 of 6 must be closed at once, got %d", refused)
	}

	hello := clientHello(t, "api.test")
	other := ln.dial("203.0.113.7")
	defer other.Close()
	done := make(chan struct{})
	go func() {
		_, _ = other.Write(hello)
		_ = other.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = other.Read(make([]byte, 1))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("another address was not served while one address flooded")
	}
}

func TestNonTLSConnectionsAreNotHeldWhenThePoolIsNearlyFull(t *testing.T) {
	ln := newFakeListener()
	defer ln.Close()
	router := &Router{
		HelloTimeout:    2 * time.Second,
		MaxPending:      8,
		MaxPendingPerIP: 8,
		Classify:        func(string) (Kind, string) { return Other, "" },
		OnRelay:         func(net.Conn, string, []byte, time.Time) {},
		OnOther:         func(c net.Conn) { _ = c.Close() },
	}
	go func() { _ = router.Serve(ln) }()
	var idle []net.Conn
	for i := range 7 {
		idle = append(idle, ln.dial(fmt.Sprintf("198.51.100.%d", i+1)))
	}
	defer func() {
		for _, c := range idle {
			_ = c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	garbage := ln.dial("203.0.113.9")
	defer garbage.Close()
	start := time.Now()
	go func() { _, _ = garbage.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }()
	if !closedWithin(garbage, time.Second) || time.Since(start) > time.Second {
		t.Fatal("a non-TLS connection was held instead of closed while the pool was nearly full")
	}
}

func TestAddressesInOneIPv6PrefixShareThePerAddressCap(t *testing.T) {
	ln := newFakeListener()
	defer ln.Close()
	router := &Router{
		HelloTimeout:    3 * time.Second,
		MaxPending:      32,
		MaxPendingPerIP: 2,
		Classify:        func(string) (Kind, string) { return Other, "" },
		OnRelay:         func(net.Conn, string, []byte, time.Time) {},
		OnOther:         func(c net.Conn) { _ = c.Close() },
	}
	go func() { _ = router.Serve(ln) }()
	var held []net.Conn
	for i := range 8 {
		held = append(held, ln.dial(fmt.Sprintf("2001:db8:1:2::%x", i+1)))
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	refused := 0
	for _, c := range held {
		if closedWithin(c, 50*time.Millisecond) {
			refused++
		}
	}
	if refused != 6 {
		t.Fatalf("a host that owns a /64 must not get a cap per address: %d of 8 refused", refused)
	}
	other := ln.dial("2001:db8:1:3::1")
	defer other.Close()
	if closedWithin(other, 50*time.Millisecond) {
		t.Fatal("a different /64 was refused")
	}
}
