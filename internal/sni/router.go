package sni

import (
	"errors"
	"log/slog"
	"net"
	"time"
)

type Kind int

const (
	Other Kind = iota
	Relay
)

type Router struct {
	HelloTimeout time.Duration
	MaxPending   int
	Classify     func(serverName string) (Kind, string)
	OnRelay      func(conn net.Conn, label string, hello []byte, deadline time.Time)
	OnOther      func(conn net.Conn)

	pending chan struct{}
}

func (r *Router) Serve(ln net.Listener) error {
	r.pending = make(chan struct{}, max(r.MaxPending, 1))
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
		select {
		case r.pending <- struct{}{}:
			go r.handle(conn)
		default:
			_ = conn.Close()
		}
	}
}

func (r *Router) handle(conn net.Conn) {
	deadline := time.Now().Add(r.HelloTimeout)
	_ = conn.SetReadDeadline(deadline)
	name, hello, err := Peek(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, ErrNotTLS) || errors.Is(err, ErrNotClientHello) || errors.Is(err, ErrMalformed) {
			time.Sleep(time.Until(deadline))
		}
		_ = conn.Close()
		<-r.pending
		return
	}
	kind, label := r.Classify(name)
	<-r.pending
	switch kind {
	case Relay:
		r.OnRelay(conn, label, hello, deadline)
	default:
		r.OnOther(NewPrefixConn(conn, hello))
	}
}

func LogServeError(err error) {
	if err != nil {
		slog.Error("sni router stopped", "err", err)
	}
}
