package httpx

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func slowBodyServer(t *testing.T, mux *Mux) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ReadTimeout = time.Minute
	srv.Config.WriteTimeout = time.Minute
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func trickle(addr, path string, total int, gap time.Duration) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Length: " + strconv.Itoa(total) + "\r\n\r\n"))
	for range total {
		time.Sleep(gap)
		if _, err := conn.Write([]byte("a")); err != nil {
			return
		}
	}
	time.Sleep(time.Second)
}

func TestSlowBodiesAreCutOffOnJSONRoutesButAllowedOnBulkRoutes(t *testing.T) {
	mux := NewMux()
	mux.jsonWait = 150 * time.Millisecond
	mux.bulkWait = 3 * time.Second
	results := make(chan error, 2)
	read := func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		results <- err
	}
	mux.Handle("POST /json", http.HandlerFunc(read))
	mux.HandleBulk("POST /bulk", http.HandlerFunc(read))
	addr := slowBodyServer(t, mux)

	go trickle(addr, "/json", 20, 30*time.Millisecond)
	select {
	case err := <-results:
		if err == nil {
			t.Fatal("a body that trickles for 600ms finished on a route with a 150ms deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the slow body was not cut off")
	}

	go trickle(addr, "/bulk", 20, 30*time.Millisecond)
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("a bulk route refused a body inside its longer deadline: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bulk body never finished")
	}
}

func TestResponseWritesToAStalledReaderTimeOut(t *testing.T) {
	mux := NewMux()
	mux.jsonWait = 200 * time.Millisecond
	done := make(chan error, 1)
	mux.Handle("GET /big", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range 256 {
			if _, err := w.Write(chunk); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}))
	addr := slowBodyServer(t, mux)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, _ = conn.Write([]byte("GET /big HTTP/1.1\r\nHost: x\r\n\r\n"))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("256 MiB was written to a client that never reads")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the write never timed out")
	}
}

func TestMuxDefaultsAreShortForJSONAndLongerForBulk(t *testing.T) {
	m := NewMux()
	if m.jsonWait != JSONWait || m.bulkWait != BulkWait || m.jsonWait >= m.bulkWait {
		t.Fatalf("defaults: %v %v", m.jsonWait, m.bulkWait)
	}
}
