package sni

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/netkey"
)

type Kind int

const (
	Other Kind = iota
	Relay
)

type Router struct {
	HelloTimeout    time.Duration
	MaxPending      int
	MaxPendingPerIP int
	Classify        func(serverName string) (Kind, string)
	OnRelay         func(conn net.Conn, label string, hello []byte, deadline time.Time)
	OnOther         func(conn net.Conn)

	pending chan struct{}
	mu      sync.Mutex
	perIP   map[string]int
}

func addressOf(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return netkey.Of(conn.RemoteAddr().String())
	}
	return netkey.Of(host)
}

func (r *Router) admit(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.perIP[ip] >= max(r.MaxPendingPerIP, 1) {
		return false
	}
	select {
	case r.pending <- struct{}{}:
		r.perIP[ip]++
		return true
	default:
		return false
	}
}

func (r *Router) release(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	<-r.pending
	if r.perIP[ip]--; r.perIP[ip] <= 0 {
		delete(r.perIP, ip)
	}
}

func (r *Router) underPressure() bool {
	return len(r.pending) > cap(r.pending)*3/4
}

func (r *Router) Serve(ln net.Listener) error {
	r.pending = make(chan struct{}, max(r.MaxPending, 1))
	r.perIP = map[string]int{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ip := addressOf(conn)
		if !r.admit(ip) {
			_ = conn.Close()
			continue
		}
		go r.handle(conn, ip)
	}
}

func (r *Router) handle(conn net.Conn, ip string) {
	deadline := time.Now().Add(r.HelloTimeout)
	_ = conn.SetReadDeadline(deadline)
	name, hello, err := Peek(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if (errors.Is(err, ErrNotTLS) || errors.Is(err, ErrNotClientHello) || errors.Is(err, ErrMalformed)) && !r.underPressure() {
			time.Sleep(time.Until(deadline))
		}
		_ = conn.Close()
		r.release(ip)
		return
	}
	kind, label := r.Classify(name)
	r.release(ip)
	switch kind {
	case Relay:
		r.OnRelay(conn, label, hello, deadline)
	default:
		r.OnOther(NewPrefixConn(conn, hello))
	}
}
