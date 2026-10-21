package testkit

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type FakeGitHub struct {
	Server *httptest.Server

	mu      sync.Mutex
	pending int
	userID  int64
	Polls   int
}

func NewFakeGitHub(t testing.TB, userID int64) *FakeGitHub {
	t.Helper()
	f := &FakeGitHub{userID: userID}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "test-client" {
			http.Error(w, "unknown client", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"device_code": "device-code", "user_code": "WXYZ-9876", "verification_uri": "https://github.test/login/device", "expires_in": 900, "interval": 1})
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.Polls++
		wait := f.pending > 0
		if wait {
			f.pending--
		}
		f.mu.Unlock()
		if wait {
			writeJSON(w, map[string]any{"error": "authorization_pending"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "gho_fake", "token_type": "bearer"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_fake" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		id := f.userID
		f.mu.Unlock()
		writeJSON(w, map[string]any{"id": id, "login": "someone"})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	raw, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (f *FakeGitHub) PendingPolls(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = n
}

func (f *FakeGitHub) SetUser(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userID = id
}
