package sni

import (
	"io"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func acceptOne(t *testing.T, trusted []string) (accepted chan net.Conn, dial func() net.Conn) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	ln, err := TrustProxyHeaders(raw, trusted, time.Second)
	if err != nil {
		t.Fatal(err)
	}
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

func TestBadTrustedProxyEntryIsRefused(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := TrustProxyHeaders(raw, []string{"nonsense"}, time.Second); err == nil {
		t.Fatal("a bad entry must not silently trust nothing")
	}
}
