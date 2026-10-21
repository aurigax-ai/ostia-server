package sni

import (
	"io"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/aurigax-ai/ostia-server/internal/httpx"
)

func trusting(t *testing.T, entries ...string) func(net.Addr) bool {
	t.Helper()
	proxies, err := httpx.ParseProxies(entries, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	return proxies.Trusts
}

func acceptOne(t *testing.T, trusted []string) (accepted chan net.Conn, dial func() net.Conn) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	ln := TrustProxyHeaders(raw, trusting(t, trusted...), time.Second)
	accepted = make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return accepted, func() net.Conn {
		conn, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
}

func TestTrustedPeerAddressComesFromTheProxyHeader(t *testing.T) {
	for _, version := range []byte{1, 2} {
		accepted, dial := acceptOne(t, []string{"127.0.0.0/8"})
		client := dial()
		header := proxyproto.HeaderProxyFromAddrs(version, tcp("203.0.113.9:51000"), tcp("192.0.2.1:443"))
		if _, err := header.WriteTo(client); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		conn := <-accepted
		if got := conn.RemoteAddr().String(); got != "203.0.113.9:51000" {
			t.Errorf("v%d: remote %s", version, got)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
			t.Errorf("v%d: payload after the header: %q %v", version, buf, err)
		}
	}
}

func TestTrustedPeerWithoutAHeaderIsRefused(t *testing.T) {
	accepted, dial := acceptOne(t, []string{"127.0.0.1"})
	client := dial()
	if _, err := client.Write([]byte("\x16\x03\x01\x00\x01\x00")); err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a trusted proxy must always send a header")
	}
}

func TestUntrustedPeerCannotSetItsAddress(t *testing.T) {
	accepted, dial := acceptOne(t, []string{"198.51.100.0/24"})
	client := dial()
	header := proxyproto.HeaderProxyFromAddrs(2, tcp("203.0.113.9:51000"), tcp("192.0.2.1:443"))
	if _, err := header.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	if got := conn.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("an untrusted peer chose its own address: %s", got)
	}
	if _, _, err := Peek(conn); err != ErrNotTLS {
		t.Fatalf("the header from an untrusted peer must be treated as garbage: %v", err)
	}
}

func TestNoTrustedProxiesMeansNoHeaderIsEverRead(t *testing.T) {
	accepted, dial := acceptOne(t, nil)
	client := dial()
	if _, err := client.Write([]byte("\x16\x03\x01")); err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "\x16\x03\x01" {
		t.Fatalf("%q %v", buf, err)
	}
}

func TestASilentTrustedPeerDoesNotDelayAnotherConnection(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	relayed := make(chan string, 1)
	router := &Router{
		HelloTimeout:    3 * time.Second,
		MaxPending:      8,
		MaxPendingPerIP: 8,
		Classify: func(name string) (Kind, string) {
			if label, ok := stripSuffix(name, ".r.test"); ok {
				return Relay, label
			}
			return Other, ""
		},
		OnRelay: func(conn net.Conn, label string, _ []byte, _ time.Time) {
			relayed <- conn.RemoteAddr().String()
			_ = conn.Close()
		},
		OnOther: func(conn net.Conn) { _ = conn.Close() },
	}
	go func() { _ = router.Serve(TrustProxyHeaders(raw, trusting(t, "127.0.0.1"), 3*time.Second)) }()

	silent, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond)

	started := time.Now()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	header := proxyproto.HeaderProxyFromAddrs(2, tcp("203.0.113.9:51000"), tcp("192.0.2.1:443"))
	if _, err := header.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(clientHello(t, "abc.r.test")); err != nil {
		t.Fatal(err)
	}
	select {
	case remote := <-relayed:
		if remote != "203.0.113.9:51000" {
			t.Fatalf("remote %s", remote)
		}
		if waited := time.Since(started); waited > time.Second {
			t.Fatalf("a silent trusted peer held up the next connection for %s", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second connection was never routed")
	}
}
