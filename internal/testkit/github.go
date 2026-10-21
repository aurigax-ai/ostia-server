package testkit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

const (
	WebClientID     = "admin-client"
	WebClientSecret = "admin-secret"
)

type webGrant struct {
	userID    int64
	login     string
	challenge string
	redirect  string
}

type FakeGitHub struct {
	Server *httptest.Server

	mu      sync.Mutex
	pending int
	userID  int64
	Polls   int
	grants  map[string]webGrant
	tokens  map[string]webGrant
	issued  int

	Revoked      []string
	RevokeStatus int
}

func NewFakeGitHub(t testing.TB, userID int64) *FakeGitHub {
	t.Helper()
	f := &FakeGitHub{userID: userID, grants: map[string]webGrant{}, tokens: map[string]webGrant{}}
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
		if r.Form.Get("code") != "" {
			f.exchange(w, r)
			return
		}
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
		f.mu.Lock()
		grant, web := f.tokens[r.Header.Get("Authorization")]
		id := f.userID
		f.mu.Unlock()
		if web {
			writeJSON(w, map[string]any{"id": grant.userID, "login": grant.login})
			return
		}
		if r.Header.Get("Authorization") != "Bearer gho_fake" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"id": id, "login": "someone"})
	})
	mux.HandleFunc("DELETE /applications/{client}/token", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AccessToken string `json:"access_token"`
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != WebClientID || pass != WebClientSecret || r.PathValue("client") != WebClientID || json.UnmarshalRead(r.Body, &body) != nil {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.RevokeStatus != 0 {
			w.WriteHeader(f.RevokeStatus)
			return
		}
		f.Revoked = append(f.Revoked, body.AccessToken)
		delete(f.tokens, "Bearer "+body.AccessToken)
		w.WriteHeader(http.StatusNoContent)
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

func (f *FakeGitHub) exchange(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	grant, ok := f.grants[r.Form.Get("code")]
	delete(f.grants, r.Form.Get("code"))
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	switch {
	case r.Form.Get("client_id") != WebClientID || r.Form.Get("client_secret") != WebClientSecret:
		writeJSON(w, map[string]any{"error": "incorrect_client_credentials"})
	case !ok:
		writeJSON(w, map[string]any{"error": "bad_verification_code"})
	case r.Form.Get("redirect_uri") != grant.redirect:
		writeJSON(w, map[string]any{"error": "redirect_uri_mismatch"})
	case base64.RawURLEncoding.EncodeToString(sum[:]) != grant.challenge:
		writeJSON(w, map[string]any{"error": "bad_verification_code"})
	default:
		f.issued++
		token := fmt.Sprintf("gho_web_%d", f.issued)
		f.tokens["Bearer "+token] = grant
		writeJSON(w, map[string]any{"access_token": token, "token_type": "bearer"})
	}
}

func (f *FakeGitHub) Authorize(t testing.TB, authorizeURL string, userID int64, login string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Path != "/login/oauth/authorize" || q.Get("client_id") != WebClientID || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("not a web authorize request: %s", authorizeURL)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued++
	code := fmt.Sprintf("code-%d", f.issued)
	f.grants[code] = webGrant{userID: userID, login: login, challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	return q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}
