package relay

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
)

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
	defer owner.streams.Add(-1)
	var lastActive atomic.Int64
	lastActive.Store(h.Now().UnixNano())
	touch := func(n int) {
		lastActive.Store(h.Now().UnixNano())
		h.meters.add(owner.accountID, owner.label, int64(n))
	}
	phone := &meteredConn{Conn: p.conn, touch: touch}
	desktop := &meteredConn{Conn: desktopConn, touch: touch}
	s := &stream{deviceID: principal.DeviceID, phone: phone, desktop: desktop}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		s.close()
		return
	}
	h.streams[s] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.streams, s)
		h.mu.Unlock()
		s.close()
	}()

	if _, err := desktop.Write(p.hello); err != nil {
		return
	}
	finished := make(chan error, 2)
	go func() { finished <- copyAll(desktop, phone) }()
	go func() { finished <- copyAll(phone, desktop) }()

	tick := max(h.Cfg.IdleTimeout.Std()/4, 5*time.Millisecond)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case err := <-finished:
			logSpliceEnd(owner.label, err)
			return
		case <-ticker.C:
			idle := time.Duration(h.Now().UnixNano() - lastActive.Load())
			if idle > h.Cfg.IdleTimeout.Std() || h.meters.over(owner.accountID, h.Cfg.MonthlyBytesPerAccount) {
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
