package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/aurigax-ai/ostia-server/internal/config"
)

type certSet struct {
	pairs []config.CertPair
	certs atomic.Pointer[[]tls.Certificate]
}

func newCertSet(pairs []config.CertPair) (*certSet, error) {
	c := &certSet{pairs: pairs}
	return c, c.Reload()
}

func (c *certSet) Reload() error {
	loaded := make([]tls.Certificate, 0, len(c.pairs))
	for _, pair := range c.pairs {
		cert, err := tls.LoadX509KeyPair(pair.Cert, pair.Key)
		if err != nil {
			return fmt.Errorf("certificate %s: %w", pair.Cert, err)
		}
		loaded = append(loaded, cert)
	}
	c.certs.Store(&loaded)
	return nil
}

func (c *certSet) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certs := *c.certs.Load()
	for i := range certs {
		if hello.SupportsCertificate(&certs[i]) == nil {
			return &certs[i], nil
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate loaded")
	}
	return &certs[0], nil
}

func (c *certSet) config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: c.get,
	}
}

type connListener struct {
	conns  chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{conns: make(chan net.Conn), addr: addr, closed: make(chan struct{})}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

func (l *connListener) push(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		_ = c.Close()
	}
}
