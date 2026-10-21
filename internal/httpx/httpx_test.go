package httpx

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/limit"
)

func TestB64RoundTripAcceptsPadding(t *testing.T) {
	type payload struct {
		Key B64 `json:"key"`
	}
	out, err := json.Marshal(payload{Key: B64{0xfb, 0xff, 0x01}})
	if err != nil || string(out) != `{"key":"-_8B"}` {
		t.Fatalf("encode: %s %v", out, err)
	}
	var got payload
	for _, in := range []string{`{"key":"-_8B"}`, `{"key":"-_8B=="}`} {
		if err := json.Unmarshal([]byte(in), &got); err != nil || len(got.Key) != 3 || got.Key[0] != 0xfb {
			t.Fatalf("decode %s: %v %v", in, got, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"key":"not base64!"}`), &got); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestHandleMapsErrors(t *testing.T) {
	h := Handle(func(w http.ResponseWriter, r *http.Request) error { return Errf(http.StatusConflict, "stale", "x") })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"error":"stale"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	h = Handle(func(w http.ResponseWriter, r *http.Request) error { return http.ErrAbortHandler })
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "Abort") {
		t.Fatalf("internal errors must not leak: %d %s", rec.Code, rec.Body)
	}
}

func TestReadJSONRejectsOversizeAndGarbage(t *testing.T) {
	var v struct{ A string }
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"A":"`+strings.Repeat("x", 100)+`"}`))
	if err := ReadJSON(rec, r, &v, 20); err != ErrTooLarge {
		t.Fatalf("oversize: %v", err)
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`nope`))
	if err := ReadJSON(rec, r, &v, 20); err == nil || err == ErrTooLarge {
		t.Fatalf("garbage: %v", err)
	}
}

func request(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for _, v := range forwarded {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func proxies(t *testing.T, header string, trusted ...string) *Proxies {
	t.Helper()
	p, err := ParseProxies(trusted, header)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientIPIgnoresHeadersFromUntrustedPeers(t *testing.T) {
	p := proxies(t, "X-Forwarded-For", "10.0.0.0/8")
	if ip := p.ClientIP(request("203.0.113.5:4000", "198.51.100.1")); ip != "203.0.113.5" {
		t.Fatalf("an untrusted peer chose its own address: %s", ip)
	}
	var none *Proxies
	if ip := none.ClientIP(request("203.0.113.5:4000", "198.51.100.1")); ip != "203.0.113.5" {
		t.Fatalf("no configured proxies must mean no header is trusted: %s", ip)
	}
	if ip := proxies(t, "X-Forwarded-For").ClientIP(request("10.0.0.1:1", "198.51.100.1")); ip != "10.0.0.1" {
		t.Fatalf("an empty trust list trusted a header: %s", ip)
	}
}

func TestClientIPTakesTheRightmostUntrustedHop(t *testing.T) {
	p := proxies(t, "X-Forwarded-For", "10.0.0.0/8", "192.0.2.7")
	cases := []struct {
		name      string
		forwarded []string
		want      string
	}{
		{"single client", []string{"198.51.100.9"}, "198.51.100.9"},
		{"forged leftmost entry", []string{"1.2.3.4, 198.51.100.9"}, "198.51.100.9"},
		{"forged entry in another header line", []string{"1.2.3.4", "198.51.100.9"}, "198.51.100.9"},
		{"trusted hops on the right are skipped", []string{"198.51.100.9, 10.1.1.1, 192.0.2.7"}, "198.51.100.9"},
		{"forged entry behind an inner proxy", []string{"6.6.6.6, 198.51.100.9, 10.1.1.1"}, "198.51.100.9"},
		{"garbage falls back to the peer", []string{"not-an-ip"}, "10.0.0.1"},
		{"garbage on the right falls back to the peer", []string{"198.51.100.9, junk"}, "10.0.0.1"},
		{"all hops trusted falls back to the peer", []string{"10.2.2.2, 10.3.3.3"}, "10.0.0.1"},
		{"no header", nil, "10.0.0.1"},
	}
	for _, c := range cases {
		if got := p.ClientIP(request("10.0.0.1:5000", c.forwarded...)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestClientIPHandlesIPv6AndMappedAddresses(t *testing.T) {
	p := proxies(t, "X-Forwarded-For", "::1", "10.0.0.0/8")
	if ip := p.ClientIP(request("[::1]:80", "2001:db8::5")); ip != "2001:db8::5" {
		t.Fatalf("%s", ip)
	}
	if ip := p.ClientIP(request("[::ffff:10.0.0.9]:80", "198.51.100.1")); ip != "198.51.100.1" {
		t.Fatalf("a mapped IPv4 proxy address must match its IPv4 rule: %s", ip)
	}
}

func TestParseProxiesRejectsGarbage(t *testing.T) {
	if _, err := ParseProxies([]string{"10.0.0.0/8", "nope"}, "X-Forwarded-For"); err == nil {
		t.Fatal("accepted a non-address")
	}
}

func TestSpoofedHeadersDoNotMoveABucketOrShareOne(t *testing.T) {
	now := time.Unix(1000, 0)
	p := proxies(t, "X-Forwarded-For", "10.0.0.1")
	g := &Guard{IP: p.ClientIP, Now: func() time.Time { return now }}
	h := g.PerIP("test", limit.Rule{Every: time.Hour, Burst: 2}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	call := func(remote string, forwarded string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request(remote, forwarded))
		return rec.Code
	}
	call("203.0.113.5:1", "1.1.1.1")
	call("203.0.113.5:2", "2.2.2.2")
	if code := call("203.0.113.5:3", "3.3.3.3"); code != http.StatusTooManyRequests {
		t.Fatalf("an attacker rotating forged headers escaped its limit: %d", code)
	}
	call("10.0.0.1:1", "198.51.100.1")
	call("10.0.0.1:2", "198.51.100.1")
	if code := call("10.0.0.1:3", "198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("a client behind the proxy is not limited: %d", code)
	}
	if code := call("10.0.0.1:4", "198.51.100.2"); code != http.StatusOK {
		t.Fatalf("one client behind the proxy locked out the others: %d", code)
	}
}

func TestGuardLimitsPerIPAndSetsRetryAfter(t *testing.T) {
	now := time.Unix(1000, 0)
	g := &Guard{IP: (*Proxies)(nil).ClientIP, Now: func() time.Time { return now }}
	h := g.PerIP("test", limit.Rule{Every: time.Minute, Burst: 2}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	call := func(addr string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		h.ServeHTTP(rec, r)
		return rec
	}
	call("1.1.1.1:1")
	call("1.1.1.1:2")
	rec := call("1.1.1.1:3")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if call("2.2.2.2:1").Code != 200 {
		t.Fatal("limit shared across addresses")
	}
}
