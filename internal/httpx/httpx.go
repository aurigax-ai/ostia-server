package httpx

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/netkey"
)

type Error struct {
	Status  int
	Code    string
	Message string
	Header  http.Header
}

func (e *Error) Error() string { return e.Code }

func Err(status int, code string) *Error { return &Error{Status: status, Code: code} }

func Errf(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

var (
	ErrUnauthorized = Err(http.StatusUnauthorized, "unauthorized")
	ErrForbidden    = Err(http.StatusForbidden, "forbidden")
	ErrNotFound     = Err(http.StatusNotFound, "not-found")
	ErrBadRequest   = Err(http.StatusBadRequest, "bad-request")
	ErrConflict     = Err(http.StatusConflict, "conflict")
	ErrTooLarge     = Err(http.StatusRequestEntityTooLarge, "too-large")
	ErrQuota        = Err(http.StatusInsufficientStorage, "quota-exceeded")
	ErrRateLimited  = Err(http.StatusTooManyRequests, "rate-limited")
	ErrGone         = Err(http.StatusGone, "gone")
)

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

func Handle(fn HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			WriteError(w, r, err)
		}
	})
}

func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr, ok := errors.AsType[*Error](err)
	if !ok {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			apiErr = ErrTooLarge
		} else {
			slog.Error("request failed", "method", r.Method, "pattern", r.Pattern, "err", err)
			apiErr = Err(http.StatusInternalServerError, "internal")
		}
	}
	for k, v := range apiErr.Header {
		w.Header()[k] = v
	}
	body := struct {
		Error   string `json:"error"`
		Message string `json:"message,omitempty"`
	}{apiErr.Code, apiErr.Message}
	WriteJSON(w, apiErr.Status, body)
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		slog.Error("encode response", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func ReadBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, ErrTooLarge
		}
		return nil, Errf(http.StatusBadRequest, "bad-request", "unreadable body")
	}
	return body, nil
}

func DecodeJSON(body []byte, v any) error {
	if len(body) == 0 {
		return Errf(http.StatusBadRequest, "bad-request", "empty body")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return Errf(http.StatusBadRequest, "bad-request", "invalid JSON body")
	}
	return nil
}

func ReadJSON(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	body, err := ReadBody(w, r, max)
	if err != nil {
		return err
	}
	return DecodeJSON(body, v)
}

type Proxies struct {
	prefixes []netip.Prefix
	header   string
}

func ParseProxies(entries []string, header string) (*Proxies, error) {
	p := &Proxies{header: header}
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return nil, fmt.Errorf("trusted proxy %q is neither an address nor a CIDR range", entry)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		p.prefixes = append(p.prefixes, prefix.Masked())
	}
	return p, nil
}

func (p *Proxies) trusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *Proxies) Trusts(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || p == nil {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	return ok && p.trusted(ip)
}

func (p *Proxies) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if p == nil || len(p.prefixes) == 0 || p.header == "" || !p.trusted(remote) {
		return remote.Unmap().String()
	}
	values := r.Header.Values(p.header)
	if len(values) == 0 {
		return remote.Unmap().String()
	}
	last := values[len(values)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return remote.Unmap().String()
	}
	return addr.Unmap().String()
}

type Guard struct {
	IP  func(*http.Request) string
	Now func() time.Time

	mu      sync.Mutex
	classes map[string]*limit.Limiter
}

func (g *Guard) limiter(class string, rule limit.Rule) *limit.Limiter {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.classes == nil {
		g.classes = map[string]*limit.Limiter{}
	}
	l, ok := g.classes[class]
	if !ok {
		l = limit.New(rule, g.Now)
		g.classes[class] = l
	}
	return l
}

func (g *Guard) PerIP(class string, rule limit.Rule, next http.Handler) http.Handler {
	l := g.limiter(class, rule)
	retry := strconv.Itoa(max(1, int(rule.Every/time.Second)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(netkey.Of(g.IP(r))) {
			w.Header().Set("Retry-After", retry)
			WriteError(w, r, ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Guard) Sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.classes {
		l.Sweep()
	}
}

type B64 []byte

func (b B64) MarshalText() ([]byte, error) {
	return []byte(encoding.EncodeToString(b)), nil
}

func (b *B64) UnmarshalText(text []byte) error {
	raw, err := encoding.DecodeString(strings.TrimRight(string(text), "="))
	if err != nil {
		return err
	}
	*b = raw
	return nil
}

const (
	JSONWait = time.Minute
	BulkWait = 5 * time.Minute
)

func Deadlines(read, write time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		now := time.Now()
		_ = rc.SetReadDeadline(now.Add(read))
		_ = rc.SetWriteDeadline(now.Add(write))
		next.ServeHTTP(w, r)
	})
}

type Mux struct {
	*http.ServeMux
	patterns []string
	bulk     []string
	jsonWait time.Duration
	bulkWait time.Duration
}

func NewMux() *Mux {
	return &Mux{ServeMux: http.NewServeMux(), jsonWait: JSONWait, bulkWait: BulkWait}
}

func (m *Mux) Handle(pattern string, handler http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, Deadlines(m.jsonWait, m.jsonWait, handler))
}

func (m *Mux) HandleBulk(pattern string, handler http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.bulk = append(m.bulk, pattern)
	m.ServeMux.Handle(pattern, Deadlines(m.bulkWait, m.bulkWait, handler))
}

func (m *Mux) Patterns() []string { return append([]string(nil), m.patterns...) }

func (m *Mux) BulkPatterns() []string { return append([]string(nil), m.bulk...) }
