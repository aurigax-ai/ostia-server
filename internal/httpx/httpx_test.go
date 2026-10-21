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

func TestClientIPUsesHeaderOnlyWhenConfigured(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if ip := ClientIP(r, ""); ip != "10.0.0.1" {
		t.Fatalf("header trusted without config: %s", ip)
	}
	if ip := ClientIP(r, "X-Forwarded-For"); ip != "203.0.113.9" {
		t.Fatalf("configured header ignored: %s", ip)
	}
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if ip := ClientIP(r, "X-Forwarded-For"); ip != "10.0.0.1" {
		t.Fatalf("garbage header used: %s", ip)
	}
}

func TestGuardLimitsPerIPAndSetsRetryAfter(t *testing.T) {
	now := time.Unix(1000, 0)
	g := &Guard{IP: func(r *http.Request) string { return ClientIP(r, "") }, Now: func() time.Time { return now }}
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
