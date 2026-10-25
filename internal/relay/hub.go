package relay

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/netkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	controlReadLimit = 4 << 10
	controlWriteWait = 5 * time.Second
	flushInterval    = 10 * time.Second
	copyBufferBytes  = 32 << 10
)

type Hub struct {
	DB     *store.DB
	Auth   *auth.Service
	Cfg    config.Relay
	Domain string
	Port   int
	Now    func() time.Time

	byIP    *limit.Limiter
	byLabel *limit.Limiter
	opens   *limit.Limiter
	opensBy *limit.Limiter
	holds   chan struct{}
	meters  *meters

	mu        sync.Mutex
	listeners map[string]*listener
	pending   map[string]*pendingStream
	streams   map[*stream]struct{}
	byID      map[string]*stream
	closed    bool
}

type controlMessage struct {
	Type   string `json:"t"`
	Stream string `json:"stream,omitzero"`
	Peer   string `json:"peer,omitzero"`
	Family int    `json:"family,omitzero"`
}

type listener struct {
	label     string
	deviceID  string
	accountID string
	ws        *websocket.Conn
	tokenHash []byte
	mu        sync.Mutex
	unconf    map[string]unconfirmedEntry
	conf      map[string]struct{}
	seq       uint64
	lastSeen  atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

type unconfirmedEntry struct {
	seq  uint64
	kill func()
}

func (l *listener) admit(id string, limit int, kill func()) (evict func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.unconf) >= max(limit, 1) {
		oldest, oldestSeq := "", uint64(0)
		for other, entry := range l.unconf {
			if oldest == "" || entry.seq < oldestSeq {
				oldest, oldestSeq = other, entry.seq
			}
		}
		evict = l.unconf[oldest].kill
		delete(l.unconf, oldest)
	}
	l.seq++
	l.unconf[id] = unconfirmedEntry{seq: l.seq, kill: kill}
	return evict
}

func (l *listener) promote(id string, limit int) (found, within bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.unconf[id]; !ok {
		return false, false
	}
	delete(l.unconf, id)
	l.conf[id] = struct{}{}
	return true, len(l.conf) <= limit
}

func (l *listener) finish(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.unconf, id)
	delete(l.conf, id)
}

func (l *listener) close(code websocket.StatusCode, reason string) {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.ws.Close(code, reason)
	})
}

func (l *listener) send(msg controlMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), controlWriteWait)
	defer cancel()
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return l.ws.Write(ctx, websocket.MessageText, raw)
}

type pendingStream struct {
	id       string
	conn     net.Conn
	hello    []byte
	listener *listener
	timer    *time.Timer
}

type stream struct {
	id               string
	deviceID         string
	listener         *listener
	phone            net.Conn
	desktop          net.Conn
	confirmed        atomic.Bool
	unconfirmedBytes atomic.Int64
}

func (s *stream) close() {
	_ = s.phone.Close()
	_ = s.desktop.Close()
}

func New(db *store.DB, authSvc *auth.Service, cfg config.Relay, domain string, port int, now func() time.Time) *Hub {
	h := &Hub{
		DB: db, Auth: authSvc, Cfg: cfg, Domain: domain, Port: port, Now: now,
		byIP:      limit.New(limit.Rule{Every: time.Minute / time.Duration(max(cfg.ConnectionsPerMinutePerIP, 1)), Burst: max(cfg.ConnectionsPerMinutePerIP, 1)}, now),
		byLabel:   limit.New(limit.Rule{Every: time.Minute / time.Duration(max(cfg.ConnectionsPerMinute, 1)), Burst: max(cfg.ConnectionsPerMinute, 1)}, now),
		opens:     limit.New(limit.Rule{Every: time.Minute / time.Duration(max(cfg.UnconfirmedOpensPerMinute, 1)), Burst: max(cfg.UnconfirmedOpensPerMinute, 1)}, now),
		opensBy:   limit.New(limit.Rule{Every: time.Minute / time.Duration(max(cfg.UnconfirmedOpensPerMinutePerAddress, 1)), Burst: max(cfg.UnconfirmedOpensPerMinutePerAddress, 1)}, now),
		holds:     make(chan struct{}, max(cfg.MaxPendingHellos, 1)),
		meters:    newMeters(db, now),
		listeners: map[string]*listener{},
		pending:   map[string]*pendingStream{},
		streams:   map[*stream]struct{}{},
		byID:      map[string]*stream{},
	}
	return h
}

func (h *Hub) Mount(mux *httpx.Mux) {
	mux.Handle("POST /v1/relay/label", h.Auth.Authed(h.label))
	mux.Handle("GET /v1/relay/listen", h.Auth.Authed(h.serveListen))
	mux.Handle("GET /v1/relay/accept/{stream}", h.Auth.Authed(h.serveAccept))
}

func (h *Hub) Host(label string) string { return label + "." + h.Domain }

func (h *Hub) Classify(serverName string) (string, bool) {
	label, ok := strings.CutSuffix(serverName, "."+h.Domain)
	if !ok || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}

func (h *Hub) label(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	label, err := h.DB.LabelFor(r.Context(), p.DeviceID, p.AccountID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"label": label, "host": h.Host(label), "port": h.Port})
	return nil
}

func (h *Hub) hold(conn net.Conn, deadline time.Time) {
	if len(h.holds) > cap(h.holds)*3/4 {
		_ = conn.Close()
		return
	}
	select {
	case h.holds <- struct{}{}:
		time.Sleep(time.Until(deadline))
		<-h.holds
	default:
	}
	_ = conn.Close()
}

func peerOf(conn net.Conn) (peer string, family int, ip string) {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return conn.RemoteAddr().String(), 4, conn.RemoteAddr().String()
	}
	family = 6
	if addr.IP.To4() != nil {
		family = 4
	}
	return addr.String(), family, addr.IP.String()
}

func (h *Hub) HandlePhone(conn net.Conn, label string, hello []byte, deadline time.Time) {
	peer, family, ip := peerOf(conn)
	if !h.byIP.Allow(netkey.Of(ip)) {
		_ = conn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	owner, err := h.DB.LabelOwner(ctx, label)
	cancel()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.hold(conn, deadline)
			return
		}
		_ = conn.Close()
		return
	}
	if !h.opensBy.Allow(label+"|"+netkey.Of(ip)) || !h.opens.Allow(label) || h.meters.over(owner.AccountID, h.Cfg.MonthlyBytesPerAccount) {
		_ = conn.Close()
		return
	}
	l := h.listenerFor(label)
	if l == nil {
		_ = conn.Close()
		return
	}
	p := &pendingStream{id: ids.New(), conn: conn, hello: hello, listener: l}
	p.timer = time.AfterFunc(h.Cfg.AcceptTimeout.Std(), func() { h.dropPending(p.id) })
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		p.timer.Stop()
		_ = conn.Close()
		return
	}
	h.pending[p.id] = p
	h.mu.Unlock()
	if evict := l.admit(p.id, h.Cfg.MaxUnconfirmedPerLabel, func() { h.kill(p.id) }); evict != nil {
		evict()
	}
	if err := l.send(controlMessage{Type: "incoming", Stream: p.id, Peer: peer, Family: family}); err != nil {
		h.dropPending(p.id)
	}
}

func (h *Hub) listenerFor(label string) *listener {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.listeners[label]
}

func (h *Hub) takePending(id string) *pendingStream {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pending[id]
	delete(h.pending, id)
	if p != nil {
		p.timer.Stop()
	}
	return p
}

func (h *Hub) dropPending(id string) {
	if p := h.takePending(id); p != nil {
		_ = p.conn.Close()
		p.listener.finish(id)
	}
}

func (h *Hub) kill(id string) {
	h.dropPending(id)
	h.mu.Lock()
	s := h.byID[id]
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
}

func (h *Hub) serveListen(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	label, err := h.DB.LabelFor(r.Context(), p.DeviceID, p.AccountID)
	if err != nil {
		return err
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil
	}
	ws.SetReadLimit(controlReadLimit)
	l := &listener{label: label, deviceID: p.DeviceID, accountID: p.AccountID, tokenHash: p.TokenHash, ws: ws, done: make(chan struct{}), unconf: map[string]unconfirmedEntry{}, conf: map[string]struct{}{}}
	l.lastSeen.Store(h.Now().UnixNano())
	if !h.register(l) {
		l.close(websocket.StatusGoingAway, "server shutting down")
		return nil
	}
	defer h.unregister(l)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-l.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	go h.keepAlive(ctx, l)
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			l.close(websocket.StatusNormalClosure, "")
			return nil
		}
		var msg controlMessage
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "pong":
			l.lastSeen.Store(h.Now().UnixNano())
		case "confirm":
			h.confirm(l, msg.Stream)
		}
	}
}

func (h *Hub) confirm(l *listener, streamID string) {
	h.mu.Lock()
	s := h.byID[streamID]
	h.mu.Unlock()
	if s == nil || s.listener != l || s.confirmed.Load() {
		return
	}
	if !h.byLabel.Allow(l.label) {
		s.close()
		return
	}
	found, within := l.promote(streamID, h.Cfg.MaxStreamsPerLabel)
	if !found {
		return
	}
	s.confirmed.Store(true)
	if !within {
		s.close()
	}
}

func (h *Hub) keepAlive(ctx context.Context, l *listener) {
	ticker := time.NewTicker(h.Cfg.PingInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Duration(h.Now().UnixNano()-l.lastSeen.Load()) > 2*h.Cfg.PingInterval.Std()+h.Cfg.PingInterval.Std()/2 {
				l.close(websocket.StatusPolicyViolation, "no pong")
				return
			}
			if _, err := h.DB.LabelOwner(ctx, l.label); errors.Is(err, store.ErrNotFound) {
				l.close(websocket.StatusPolicyViolation, "device removed")
				return
			}
			if _, err := h.DB.SessionDevice(ctx, l.tokenHash); err != nil {
				l.close(websocket.StatusPolicyViolation, "session ended")
				return
			}
			if err := l.send(controlMessage{Type: "ping"}); err != nil {
				l.close(websocket.StatusInternalError, "ping failed")
				return
			}
		}
	}
}

func (h *Hub) register(l *listener) bool {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return false
	}
	old := h.listeners[l.label]
	h.listeners[l.label] = l
	h.mu.Unlock()
	if old != nil {
		old.close(websocket.StatusPolicyViolation, "replaced by a newer connection")
	}
	return true
}

func (h *Hub) unregister(l *listener) {
	h.mu.Lock()
	if h.listeners[l.label] == l {
		delete(h.listeners, l.label)
	}
	var orphaned []string
	for id, p := range h.pending {
		if p.listener == l {
			orphaned = append(orphaned, id)
		}
	}
	h.mu.Unlock()
	for _, id := range orphaned {
		h.dropPending(id)
	}
	l.close(websocket.StatusNormalClosure, "")
}

func (h *Hub) serveAccept(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	id := r.PathValue("stream")
	h.mu.Lock()
	candidate := h.pending[id]
	h.mu.Unlock()
	if candidate == nil || candidate.listener.deviceID != p.DeviceID {
		return httpx.ErrNotFound
	}
	pending := h.takePending(id)
	if pending == nil {
		return httpx.ErrNotFound
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		_ = pending.conn.Close()
		pending.listener.finish(pending.id)
		return nil
	}
	ws.SetReadLimit(-1)
	desktop := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	h.splice(pending, desktop, p)
	return nil
}

func (h *Hub) KickSession(tokenHash []byte) {
	h.mu.Lock()
	var ls []*listener
	for _, l := range h.listeners {
		if ids.Equal(l.tokenHash, tokenHash) {
			ls = append(ls, l)
		}
	}
	h.mu.Unlock()
	for _, l := range ls {
		l.close(websocket.StatusPolicyViolation, "session ended")
	}
}

func (h *Hub) KickDevice(deviceID string) {
	h.mu.Lock()
	var ls []*listener
	for _, l := range h.listeners {
		if l.deviceID == deviceID {
			ls = append(ls, l)
		}
	}
	var ss []*stream
	for s := range h.streams {
		if s.deviceID == deviceID {
			ss = append(ss, s)
		}
	}
	h.mu.Unlock()
	for _, l := range ls {
		l.close(websocket.StatusPolicyViolation, "device removed")
	}
	for _, s := range ss {
		s.close()
	}
}

func (h *Hub) KickDevices(deviceIDs []string) {
	for _, id := range deviceIDs {
		h.KickDevice(id)
	}
}

func (h *Hub) Run(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.meters.flush(context.Background())
			return
		case <-ticker.C:
			h.byIP.Sweep()
			h.byLabel.Sweep()
			h.meters.flush(ctx)
		}
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	var ls []*listener
	for _, l := range h.listeners {
		ls = append(ls, l)
	}
	var ss []*stream
	for s := range h.streams {
		ss = append(ss, s)
	}
	var ps []string
	for id := range h.pending {
		ps = append(ps, id)
	}
	h.mu.Unlock()
	for _, id := range ps {
		h.dropPending(id)
	}
	for _, l := range ls {
		l.close(websocket.StatusGoingAway, "server shutting down")
	}
	for _, s := range ss {
		s.close()
	}
	h.meters.flush(context.Background())
}

func logSpliceEnd(label string, err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Debug("relay stream ended", "label", label, "err", err)
	}
}
