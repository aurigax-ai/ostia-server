package relay

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
)

const unconfirmedByteLimit = 256 << 10

type meteredConn struct {
	net.Conn
	touch func(n int)
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch(n)
	}
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch(n)
	}
	return n, err
}

func (h *Hub) splice(p *pendingStream, desktopConn net.Conn, principal auth.Principal) {
	owner := p.listener
	s := &stream{id: p.id, deviceID: principal.DeviceID, listener: owner}
	var lastActive atomic.Int64
	lastActive.Store(h.Now().UnixNano())
	touch := func(n int) {
		lastActive.Store(h.Now().UnixNano())
		if s.confirmed.Load() {
			h.meters.add(owner.accountID, owner.label, int64(n))
			return
		}
		if s.unconfirmedBytes.Add(int64(n)) > unconfirmedByteLimit {
			s.close()
		}
	}
	s.phone = &meteredConn{Conn: p.conn, touch: touch}
	s.desktop = &meteredConn{Conn: desktopConn, touch: touch}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		owner.finish(s.id)
		s.close()
		return
	}
	h.streams[s] = struct{}{}
	h.byID[s.id] = s
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.streams, s)
		delete(h.byID, s.id)
		h.mu.Unlock()
		owner.finish(s.id)
		s.close()
	}()

	if _, err := s.desktop.Write(p.hello); err != nil {
		return
	}
	finished := make(chan error, 2)
	go func() { finished <- copyAll(s.desktop, s.phone) }()
	go func() { finished <- copyAll(s.phone, s.desktop) }()

	tick := max(h.Cfg.IdleTimeout.Std()/4, 5*time.Millisecond)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	confirmBy := time.NewTimer(h.Cfg.UnconfirmedTimeout.Std())
	defer confirmBy.Stop()
	for {
		select {
		case err := <-finished:
			logSpliceEnd(owner.label, err)
			return
		case <-confirmBy.C:
			if !s.confirmed.Load() {
				return
			}
		case <-ticker.C:
			idle := time.Duration(h.Now().UnixNano() - lastActive.Load())
			if idle > h.Cfg.IdleTimeout.Std() || (s.confirmed.Load() && h.meters.over(owner.accountID, h.Cfg.MonthlyBytesPerAccount)) {
				return
			}
		}
	}
}

func copyAll(dst, src net.Conn) error {
	buf := make([]byte, copyBufferBytes)
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, buf)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
