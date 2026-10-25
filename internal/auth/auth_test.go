package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

type env struct {
	svc      *Service
	srv      *httptest.Server
	clock    *time.Time
	gh       *fakeGitHub
	owners   map[string]*device
	unsigned map[string]bool
	stamp    int64
}

func (e *env) deviceHeaders(method, path, token string) map[string]string {
	d := e.owners[token]
	if d == nil || e.unsigned[token] || method != "POST" || path != signedPath {
		return nil
	}
	e.stamp = max(e.clock.UnixMilli(), e.stamp+1)
	return map[string]string{timestampHeader: strconv.FormatInt(e.stamp, 10), signatureHeader: httpx.EncodeB64(ed25519.Sign(d.sign, signedMessage(d.id, e.stamp)))}
}

const (
	signedPath    = "/test/signed"
	signedContext = "ostia-server/test/v1"
)

func signedMessage(deviceID string, stamp int64) []byte {
	return StampedMessage(signedContext, deviceID, stamp)
}

type fakeGitHub struct {
	srv      *httptest.Server
	pending  atomic.Int32
	userID   atomic.Int64
	polls    atomic.Int32
	slowDown atomic.Bool
}

func newFakeGitHub() *fakeGitHub {
	f := &fakeGitHub{}
	f.userID.Store(4242)
	mux := httpx.NewMux()
	mux.HandleFunc("POST /login/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "client-1" {
			http.Error(w, "bad client", http.StatusBadRequest)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"device_code": "dev-code", "user_code": "ABCD-1234", "verification_uri": "https://github.test/login/device", "expires_in": 900, "interval": 5})
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.polls.Add(1)
		if r.Form.Get("device_code") != "dev-code" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			httpx.WriteJSON(w, 200, map[string]any{"error": "bad_verification_code"})
			return
		}
		if f.slowDown.CompareAndSwap(true, false) {
			httpx.WriteJSON(w, 200, map[string]any{"error": "slow_down"})
			return
		}
		if f.pending.Add(-1) >= 0 {
			httpx.WriteJSON(w, 200, map[string]any{"error": "authorization_pending"})
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"access_token": "gho_token"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"id": f.userID.Load(), "login": "someone"})
	})
	f.srv = httptest.NewServer(mux)
	return f
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	e := &env{clock: &now, gh: newFakeGitHub(), owners: map[string]*device{}, unsigned: map[string]bool{}}
	t.Cleanup(e.gh.srv.Close)
	clock := func() time.Time { return *e.clock }
	db, err := store.Open(filepath.Join(t.TempDir(), "db"), store.JournalWAL, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs, _ := blob.NewDisk(t.TempDir())
	cfg := config.Default().Auth
	e.svc = &Service{
		DB: db, Blobs: blobs, Key: serverkey.New(make([]byte, 32)), Cfg: cfg, Now: clock,
		GitHub: &GitHub{ClientID: "client-1", BaseURL: e.gh.srv.URL, APIURL: e.gh.srv.URL, Client: http.DefaultClient},
		Guard:  &httpx.Guard{IP: func(r *http.Request) string { return "1.1.1.1" }, Now: clock},
	}
	mux := httpx.NewMux()
	e.svc.Mount(mux)
	mux.Handle("POST "+signedPath, e.svc.Authed(func(w http.ResponseWriter, r *http.Request, p Principal) error {
		if err := e.svc.RequireSignedTimestamp(r, p, signedContext); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

type device struct {
	sign ed25519.PrivateKey
	box  []byte
	name string
	id   string
}

func newDevice(name string) *device {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	box := make([]byte, 32)
	_, _ = rand.Read(box)
	return &device{sign: priv, box: box, name: name}
}

func (d *device) registration() map[string]any {
	pub := d.sign.Public().(ed25519.PublicKey)
	return map[string]any{
		"name":    d.name,
		"signPub": httpx.EncodeB64(pub),
		"boxPub":  httpx.EncodeB64(d.box),
		"proof":   httpx.EncodeB64(ed25519.Sign(d.sign, registrationMessage(pub, d.box))),
	}
}

func (e *env) post(t *testing.T, path, token string, body any) (int, map[string]any) {
	t.Helper()
	return e.call(t, "POST", path, token, body)
}

func (e *env) call(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range e.deviceHeaders(method, path, token) {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.UnmarshalRead(res.Body, &out)
	return res.StatusCode, out
}

func (e *env) invite(t *testing.T) string {
	t.Helper()
	code, _, err := e.svc.CreateInvite(t.Context(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (e *env) alive(t *testing.T, token string) int {
	t.Helper()
	status, _ := e.call(t, "POST", "/v1/devices/heartbeat", token, nil)
	return status
}

func (e *env) signIn(t *testing.T, d *device, code string) {
	t.Helper()
	body := d.registration()
	body["code"] = code
	status, out := e.post(t, "/v1/auth/invite", "", body)
	if status != 201 {
		t.Fatalf("register %d %v", status, out)
	}
	d.id = out["deviceId"].(string)
}

func (e *env) session(t *testing.T, d *device) string {
	t.Helper()
	status, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	if status != 200 {
		t.Fatalf("challenge %d", status)
	}
	nonce := out["nonce"].(string)
	sig := ed25519.Sign(d.sign, ChallengeMessage(d.id, nonce))
	status, out = e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": d.id, "nonce": nonce, "sig": httpx.EncodeB64(sig)})
	if status != 200 {
		t.Fatalf("verify %d %v", status, out)
	}
	token := out["token"].(string)
	e.owners[token] = d
	return token
}

func TestInviteRegistrationThenKeySession(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	if status := e.alive(t, e.session(t, d)); status != 204 {
		t.Fatalf("a fresh session must work: %d", status)
	}
}

func TestDeviceTrustRoutesAreGone(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)
	for _, route := range [][2]string{
		{"GET", "/v1/devices"},
		{"POST", "/v1/devices/invite"},
		{"DELETE", "/v1/devices/" + d.id},
		{"DELETE", "/v1/account"},
		{"GET", "/v1/auth/elevation"},
		{"POST", "/v1/auth/elevation/approval"},
		{"POST", "/v1/auth/elevation/github"},
		{"POST", "/v1/auth/elevation/github/poll"},
		{"GET", "/v1/auth/approvals"},
		{"GET", "/v1/auth/approvals/x"},
		{"POST", "/v1/auth/approvals/x/approve"},
		{"DELETE", "/v1/auth/approvals/x"},
	} {
		if status, _ := e.call(t, route[0], route[1], token, nil); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("%s %s answers %d", route[0], route[1], status)
		}
	}
	if status := e.alive(t, token); status != 204 {
		t.Fatalf("the device must still be signed in: %d", status)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	body := d.registration()
	body["code"] = "nope"
	if status, out := e.post(t, "/v1/auth/invite", "", body); status != 403 || out["error"] != "invalid-invite" {
		t.Fatalf("unknown code: %d %v", status, out)
	}
	code := e.invite(t)
	body = d.registration()
	body["code"] = code
	body["proof"] = httpx.EncodeB64(make([]byte, 64))
	if status, out := e.post(t, "/v1/auth/invite", "", body); status != 400 || out["error"] != "bad-proof" {
		t.Fatalf("forged proof: %d %v", status, out)
	}
	body = d.registration()
	body["code"] = code
	body["name"] = "\x07bell"
	if status, _ := e.post(t, "/v1/auth/invite", "", body); status != 400 {
		t.Fatalf("control characters in name: %d", status)
	}
	body = d.registration()
	body["code"] = strings.ToUpper(code)
	if status, _ := e.post(t, "/v1/auth/invite", "", body); status != 201 {
		t.Fatalf("code is typed by humans and must match regardless of case: %d", status)
	}
	if status, _ := e.post(t, "/v1/auth/invite", "", body); status != 403 {
		t.Fatalf("invite reused: %d", status)
	}
}

func TestChallengeIsSingleUseAndBoundToTheDevice(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	other := newDevice("other")
	e.signIn(t, other, e.invite(t))

	_, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	nonce := out["nonce"].(string)
	sig := httpx.EncodeB64(ed25519.Sign(d.sign, ChallengeMessage(d.id, nonce)))
	verify := map[string]string{"deviceId": d.id, "nonce": nonce, "sig": sig}
	if status, _ := e.post(t, "/v1/auth/verify", "", verify); status != 200 {
		t.Fatal("first verify failed")
	}
	if status, _ := e.post(t, "/v1/auth/verify", "", verify); status != 401 {
		t.Fatalf("nonce replayed: %d", status)
	}

	_, out = e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	nonce = out["nonce"].(string)
	forged := httpx.EncodeB64(ed25519.Sign(other.sign, ChallengeMessage(d.id, nonce)))
	if status, _ := e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": d.id, "nonce": nonce, "sig": forged}); status != 401 {
		t.Fatalf("signature of another key accepted: %d", status)
	}

	_, out = e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	nonce = out["nonce"].(string)
	sig = httpx.EncodeB64(ed25519.Sign(d.sign, ChallengeMessage(d.id, nonce)))
	*e.clock = e.clock.Add(2 * time.Minute)
	if status, _ := e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": d.id, "nonce": nonce, "sig": sig}); status != 401 {
		t.Fatalf("expired nonce accepted: %d", status)
	}
}

func TestUnknownDeviceGetsAChallengeButNeverASession(t *testing.T) {
	e := newEnv(t)
	status, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": "doesnotexist"})
	if status != 200 || out["nonce"] == "" {
		t.Fatalf("challenge must not reveal whether a device exists: %d %v", status, out)
	}
}

func TestSessionExpiresAndRoutesNeedBearer(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)
	for _, route := range [][2]string{{"POST", "/v1/devices/heartbeat"}, {"DELETE", "/v1/auth/session"}} {
		if status, _ := e.call(t, route[0], route[1], "", nil); status != 401 {
			t.Errorf("%s %s without a bearer: %d", route[0], route[1], status)
		}
		if status, _ := e.call(t, route[0], route[1], "wrong", nil); status != 401 {
			t.Errorf("%s %s with a wrong bearer: %d", route[0], route[1], status)
		}
	}
	*e.clock = e.clock.Add(2 * time.Hour)
	if status := e.alive(t, token); status != 401 {
		t.Fatalf("expired session: %d", status)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)
	if status, _ := e.call(t, "DELETE", "/v1/auth/session", token, nil); status != 204 {
		t.Fatalf("logout %d", status)
	}
	if status := e.alive(t, token); status != 401 {
		t.Fatalf("session survived logout: %d", status)
	}
}

func TestDeviceLimit(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.MaxDevices = 1
	e.gh.pending.Store(0)
	signIn := func(name string) (int, map[string]any) {
		_, out := e.post(t, "/v1/auth/github/device", "", nil)
		*e.clock = e.clock.Add(6 * time.Second)
		body := newDevice(name).registration()
		body["flowId"] = out["flowId"]
		return e.post(t, "/v1/auth/github/poll", "", body)
	}
	if status, out := signIn("a"); status != 201 {
		t.Fatalf("first device: %d %v", status, out)
	}
	if status, out := signIn("b"); status != 409 || out["error"] != "device-limit" {
		t.Fatalf("device limit: %d %v", status, out)
	}
}

func TestGitHubDeviceFlowSignsInAndReusesTheAccount(t *testing.T) {
	e := newEnv(t)
	e.gh.pending.Store(1)
	status, out := e.post(t, "/v1/auth/github/device", "", nil)
	if status != 200 || out["userCode"] != "ABCD-1234" || out["verificationUri"] == "" {
		t.Fatalf("start %d %v", status, out)
	}
	flowID := out["flowId"].(string)
	d := newDevice("laptop")
	poll := func() (int, map[string]any) {
		body := d.registration()
		body["flowId"] = flowID
		return e.post(t, "/v1/auth/github/poll", "", body)
	}

	if status, out := poll(); status != 202 || out["status"] != "pending" {
		t.Fatalf("polling before the interval must stay pending: %d %v", status, out)
	}
	if e.gh.polls.Load() != 0 {
		t.Fatal("GitHub was polled before the interval elapsed")
	}
	*e.clock = e.clock.Add(6 * time.Second)
	if status, _ := poll(); status != 202 {
		t.Fatalf("authorization_pending: %d", status)
	}
	*e.clock = e.clock.Add(6 * time.Second)
	status, out = poll()
	if status != 201 || out["provider"] != "github" {
		t.Fatalf("done: %d %v", status, out)
	}
	d.id = out["deviceId"].(string)
	first := out["accountId"].(string)
	if status, _ := poll(); status != 404 {
		t.Fatalf("flow reusable after success: %d", status)
	}

	e.gh.pending.Store(0)
	_, out = e.post(t, "/v1/auth/github/device", "", nil)
	flowID = out["flowId"].(string)
	second := newDevice("phone")
	*e.clock = e.clock.Add(6 * time.Second)
	body := second.registration()
	body["flowId"] = flowID
	status, out = e.post(t, "/v1/auth/github/poll", "", body)
	if status != 201 || out["accountId"] != first {
		t.Fatalf("same GitHub user must land in the same account: %d %v vs %s", status, out, first)
	}

	e.gh.userID.Store(777)
	_, out = e.post(t, "/v1/auth/github/device", "", nil)
	flowID = out["flowId"].(string)
	third := newDevice("stranger")
	*e.clock = e.clock.Add(6 * time.Second)
	body = third.registration()
	body["flowId"] = flowID
	status, out = e.post(t, "/v1/auth/github/poll", "", body)
	if status != 201 || out["accountId"] == first {
		t.Fatalf("different GitHub user shares an account: %d %v", status, out)
	}
}

func TestGitHubSlowDownRaisesTheInterval(t *testing.T) {
	e := newEnv(t)
	e.gh.slowDown.Store(true)
	e.gh.pending.Store(100)
	_, out := e.post(t, "/v1/auth/github/device", "", nil)
	flowID := out["flowId"].(string)
	d := newDevice("laptop")
	*e.clock = e.clock.Add(6 * time.Second)
	body := d.registration()
	body["flowId"] = flowID
	status, out := e.post(t, "/v1/auth/github/poll", "", body)
	if status != 202 || out["interval"].(float64) != 10 {
		t.Fatalf("slow_down: %d %v", status, out)
	}
}

func TestGitHubPollRejectsUnknownFlowAndBadProof(t *testing.T) {
	e := newEnv(t)
	d := newDevice("laptop")
	body := d.registration()
	body["flowId"] = "nope"
	if status, _ := e.post(t, "/v1/auth/github/poll", "", body); status != 404 {
		t.Fatalf("unknown flow: %d", status)
	}
	body["proof"] = httpx.EncodeB64(make([]byte, 64))
	if status, _ := e.post(t, "/v1/auth/github/poll", "", body); status != 400 {
		t.Fatalf("bad proof: %d", status)
	}
}

func TestGitHubRoutesAbsentWhenNotConfigured(t *testing.T) {
	e := newEnv(t)
	e.svc.GitHub = nil
	mux := httpx.NewMux()
	e.svc.Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/auth/github/device", nil))
	if rec.Code != 404 && rec.Code != 405 {
		t.Fatalf("github route mounted without a client id: %d", rec.Code)
	}
}

func TestChallengesAreOnlyKeptForRegisteredDevicesAndCappedPerDevice(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	for i := range 3 * maxChallengesPerDevice {
		*e.clock = e.clock.Add(time.Second)
		status, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": "ghost-" + string(rune('a'+i%26)) + strings.Repeat("x", i)})
		if status != 200 || out["nonce"] == "" {
			t.Fatalf("unknown devices still get an indistinguishable answer: %d", status)
		}
	}
	e.svc.mu.Lock()
	stored := len(e.svc.challenges)
	e.svc.mu.Unlock()
	if stored != 0 {
		t.Fatalf("challenges for unknown devices were kept: %d", stored)
	}
	var first string
	for i := range 2 * maxChallengesPerDevice {
		*e.clock = e.clock.Add(time.Second)
		status, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
		if status != 200 {
			t.Fatalf("challenge %d: %d", i, status)
		}
		if i == 0 {
			first = out["nonce"].(string)
		}
	}
	e.svc.mu.Lock()
	stored = len(e.svc.challenges)
	e.svc.mu.Unlock()
	if stored != maxChallengesPerDevice {
		t.Fatalf("a device may hold %d open challenges, found %d", maxChallengesPerDevice, stored)
	}
	sig := httpx.EncodeB64(ed25519.Sign(d.sign, ChallengeMessage(d.id, first)))
	if status, _ := e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": d.id, "nonce": first, "sig": sig}); status != 401 {
		t.Fatalf("the oldest challenge should have been dropped: %d", status)
	}
}

func TestExpiredChallengesAreSwept(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	*e.clock = e.clock.Add(2 * time.Minute)
	e.svc.SweepChallenges()
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	if len(e.svc.challenges) != 0 || len(e.svc.challengesOf) != 0 {
		t.Fatal("expired challenges survived the sweep")
	}
}

func TestOneAddressCannotHoldManyGitHubFlows(t *testing.T) {
	e := newEnv(t)
	for i := range maxFlowsPerIP {
		if status, out := e.post(t, "/v1/auth/github/device", "", nil); status != 200 {
			t.Fatalf("flow %d: %d %v", i, status, out)
		}
	}
	if status, _ := e.post(t, "/v1/auth/github/device", "", nil); status != 429 {
		t.Fatalf("an address kept opening flows: %d", status)
	}
}

func TestChallengesOfOneAddressCannotEvictAnotherAddressesChallenge(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	*e.clock = e.clock.Add(time.Second)
	_, out := e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	real := out["nonce"].(string)
	e.svc.Guard.IP = func(*http.Request) string { return "198.51.100.77" }
	for range 3 * maxChallengesPerDevice {
		*e.clock = e.clock.Add(time.Second)
		e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": d.id})
	}
	sig := httpx.EncodeB64(ed25519.Sign(d.sign, ChallengeMessage(d.id, real)))
	if status, _ := e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": d.id, "nonce": real, "sig": sig}); status != 200 {
		t.Fatalf("an attacker who knows the device id evicted the owner's challenge: %d", status)
	}
}

func TestLogoutNotifiesTheHookWithTheSessionToken(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)
	var ended [][]byte
	e.svc.Hooks.SessionEnded = func(hash []byte) { ended = append(ended, hash) }
	e.call(t, "DELETE", "/v1/auth/session", token, nil)
	if len(ended) != 1 || !ids.Equal(ended[0], ids.Hash(token)) {
		t.Fatalf("hook: %v", ended)
	}
}

func TestSignedActionsRefuseBareTokensStaleTimestampsAndReplays(t *testing.T) {
	e := newEnv(t)
	d := newDevice("laptop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)

	e.unsigned[token] = true
	if status, out := e.call(t, "POST", signedPath, token, nil); status != 403 || out["error"] != "device-signature-required" {
		t.Fatalf("a bare token passed a signed action: %d %v", status, out)
	}
	delete(e.unsigned, token)

	send := func(stamp int64) (int, map[string]any) {
		req, _ := http.NewRequest("POST", e.srv.URL+signedPath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(timestampHeader, strconv.FormatInt(stamp, 10))
		req.Header.Set(signatureHeader, httpx.EncodeB64(ed25519.Sign(d.sign, signedMessage(d.id, stamp))))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.UnmarshalRead(res.Body, &out)
		return res.StatusCode, out
	}
	now := e.clock.UnixMilli()
	if status, out := send(now - int64(10*time.Minute/time.Millisecond)); status != 403 || out["error"] != "stale-signature" {
		t.Fatalf("an old timestamp: %d %v", status, out)
	}
	if status, _ := send(now); status != 204 {
		t.Fatalf("a fresh signature: %d", status)
	}
	if status, out := send(now); status != 403 || out["error"] != "stale-signature" {
		t.Fatalf("a replayed signature: %d %v", status, out)
	}
}
