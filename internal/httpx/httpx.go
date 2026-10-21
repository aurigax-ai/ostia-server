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

func ReadJSON(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	body := http.MaxBytesReader(w, r.Body, max)
	if err := json.UnmarshalRead(body, v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return ErrTooLarge
		}
		if errors.Is(err, io.EOF) {
			return Errf(http.StatusBadRequest, "bad-request", "empty body")
		}
		return Errf(http.StatusBadRequest, "bad-request", "invalid JSON body")
	}
	return nil
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
	var hops []string
	for _, value := range r.Header.Values(p.header) {
		for hop := range strings.SplitSeq(value, ",") {
			hops = append(hops, strings.TrimSpace(hop))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			return remote.Unmap().String()
		}
		if !p.trusted(addr) {
			return addr.Unmap().String()
		}
	}
	return remote.Unmap().String()
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
		if !l.Allow(g.IP(r)) {
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

type Mux struct {
	*http.ServeMux
	patterns []string
}

func NewMux() *Mux { return &Mux{ServeMux: http.NewServeMux()} }

func (m *Mux) Handle(pattern string, handler http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, handler)
}

func (m *Mux) Patterns() []string { return append([]string(nil), m.patterns...) }
