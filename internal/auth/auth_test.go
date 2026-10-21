package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	svc   *Service
	srv   *httptest.Server
	clock *time.Time
	gh    *fakeGitHub
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
	e := &env{clock: &now, gh: newFakeGitHub()}
	t.Cleanup(e.gh.srv.Close)
	clock := func() time.Time { return *e.clock }
	db, err := store.Open(filepath.Join(t.TempDir(), "db"), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs, _ := blob.NewDisk(t.TempDir())
	cfg := config.Default().Auth
	cfg.ApproverMinAge = 0
	e.svc = &Service{
		DB: db, Blobs: blobs, Key: serverkey.New(make([]byte, 32)), Cfg: cfg, Now: clock,
		GitHub: &GitHub{ClientID: "client-1", BaseURL: e.gh.srv.URL, APIURL: e.gh.srv.URL, Client: http.DefaultClient},
		Guard:  &httpx.Guard{IP: func(r *http.Request) string { return "1.1.1.1" }, Now: clock},
	}
	mux := httpx.NewMux()
	e.svc.Mount(mux)
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
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.UnmarshalRead(res.Body, &out)
	return res.StatusCode, out
}

func (e *env) elevate(t *testing.T, requesterToken, approverToken string) {
	t.Helper()
	status, out := e.post(t, "/v1/auth/elevation/approval", requesterToken, nil)
	if status != 201 {
		t.Fatalf("request approval %d %v", status, out)
	}
	id := out["approvalId"].(string)
	if status, _ := e.call(t, "POST", "/v1/auth/approvals/"+id+"/approve", approverToken, nil); status != 204 {
		t.Fatalf("approve %d", status)
	}
}

func (e *env) invite(t *testing.T, accountID string) string {
	t.Helper()
	code, _, err := e.svc.CreateInvite(t.Context(), accountID, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	return code
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
	return out["token"].(string)
}

func TestInviteRegistrationThenKeySession(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	status, out := e.call(t, "GET", "/v1/devices", token, nil)
	list, _ := out["devices"].([]any)
	if status != 200 || len(list) != 1 || list[0].(map[string]any)["current"] != true {
		t.Fatalf("devices %d %v", status, out)
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
	code := e.invite(t, "")
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
	e.signIn(t, d, e.invite(t, ""))
	other := newDevice("other")
	e.signIn(t, other, e.invite(t, ""))

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
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	for _, route := range [][2]string{{"GET", "/v1/devices"}, {"POST", "/v1/devices/invite"}, {"DELETE", "/v1/devices/x"}, {"DELETE", "/v1/account"}, {"DELETE", "/v1/auth/session"}} {
		if status, _ := e.call(t, route[0], route[1], "", nil); status != 401 {
			t.Errorf("%s %s without a bearer: %d", route[0], route[1], status)
		}
		if status, _ := e.call(t, route[0], route[1], "wrong", nil); status != 401 {
			t.Errorf("%s %s with a wrong bearer: %d", route[0], route[1], status)
		}
	}
	*e.clock = e.clock.Add(2 * time.Hour)
	if status, _ := e.call(t, "GET", "/v1/devices", token, nil); status != 401 {
		t.Fatalf("expired session: %d", status)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	if status, _ := e.call(t, "DELETE", "/v1/auth/session", token, nil); status != 204 {
		t.Fatalf("logout %d", status)
	}
	if status, _ := e.call(t, "GET", "/v1/devices", token, nil); status != 401 {
		t.Fatalf("session survived logout: %d", status)
	}
}

func TestDeviceInviteJoinsTheSameAccountAndRevokeKicksIt(t *testing.T) {
	e := newEnv(t)
	laptop := newDevice("laptop")
	e.signIn(t, laptop, e.invite(t, ""))
	token := e.session(t, laptop)

	status, out := e.post(t, "/v1/devices/invite", token, nil)
	if status != 201 {
		t.Fatalf("device invite %d %v", status, out)
	}
	phone := newDevice("desktop-2")
	e.signIn(t, phone, out["code"].(string))
	phoneToken := e.session(t, phone)

	_, list := e.call(t, "GET", "/v1/devices", token, nil)
	if len(list["devices"].([]any)) != 2 {
		t.Fatalf("both devices must share an account: %v", list)
	}

	var revoked []string
	e.svc.Hooks.DeviceRevoked = func(id string) { revoked = append(revoked, id) }
	if status, out := e.call(t, "DELETE", "/v1/devices/"+phone.id, token, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("revoking another device needs a second device's approval: %d %v", status, out)
	}
	e.elevate(t, token, phoneToken)
	if status, _ := e.call(t, "DELETE", "/v1/devices/"+phone.id, token, nil); status != 204 {
		t.Fatalf("revoke %d", status)
	}
	if len(revoked) != 1 || revoked[0] != phone.id {
		t.Fatalf("hook: %v", revoked)
	}
	if status, _ := e.call(t, "GET", "/v1/devices", phoneToken, nil); status != 401 {
		t.Fatalf("revoked device keeps its session: %d", status)
	}
	_, out = e.post(t, "/v1/auth/challenge", "", map[string]string{"deviceId": phone.id})
	sig := httpx.EncodeB64(ed25519.Sign(phone.sign, ChallengeMessage(phone.id, out["nonce"].(string))))
	if status, _ := e.post(t, "/v1/auth/verify", "", map[string]string{"deviceId": phone.id, "nonce": out["nonce"].(string), "sig": sig}); status != 401 {
		t.Fatalf("revoked device signs in again: %d", status)
	}
	if status, _ := e.call(t, "DELETE", "/v1/devices/"+phone.id, token, nil); status != 404 {
		t.Fatalf("second revoke %d", status)
	}
}

func TestDeviceCannotRevokeAnotherAccountsDevice(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("a"), newDevice("b")
	e.signIn(t, a, e.invite(t, ""))
	e.signIn(t, b, e.invite(t, ""))
	tokenA := e.session(t, a)
	if status, _ := e.call(t, "DELETE", "/v1/devices/"+b.id, tokenA, nil); status != 403 {
		t.Fatalf("cross-account revoke: %d", status)
	}
	if status, _ := e.call(t, "GET", "/v1/devices", e.session(t, b), nil); status != 200 {
		t.Fatal("victim device lost access")
	}
}

func TestDeleteAccountRemovesEverythingAndNotifies(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	second := newDevice("phone")
	_, out := e.post(t, "/v1/devices/invite", token, nil)
	e.signIn(t, second, out["code"].(string))
	secondToken := e.session(t, second)
	var gone []string
	e.svc.Hooks.AccountDeleted = func(ids []string) { gone = ids }
	if status, out := e.call(t, "DELETE", "/v1/account", token, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("deleting an account needs approval: %d %v", status, out)
	}
	e.elevate(t, token, secondToken)
	if status, _ := e.call(t, "DELETE", "/v1/account", token, nil); status != 204 {
		t.Fatalf("delete %d", status)
	}
	if len(gone) != 2 {
		t.Fatalf("hook: %v", gone)
	}
	if status, _ := e.call(t, "GET", "/v1/devices", token, nil); status != 401 {
		t.Fatalf("session of a deleted account works: %d", status)
	}
}

func TestDeviceLimit(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.MaxDevices = 1
	a := newDevice("a")
	e.signIn(t, a, e.invite(t, ""))
	token := e.session(t, a)
	_, out := e.post(t, "/v1/devices/invite", token, nil)
	b := newDevice("b")
	body := b.registration()
	body["code"] = out["code"]
	if status, out := e.post(t, "/v1/auth/invite", "", body); status != 409 || out["error"] != "device-limit" {
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
	e.signIn(t, d, e.invite(t, ""))
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
	e.signIn(t, d, e.invite(t, ""))
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

func TestElevationRules(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("laptop"), newDevice("phone")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	if status, out := e.post(t, "/v1/auth/elevation/approval", tokenA, nil); status != 409 || out["error"] != "no-second-device" {
		t.Fatalf("a single-device account cannot be approved by anyone: %d %v", status, out)
	}
	_, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	e.signIn(t, b, out["code"].(string))
	tokenB := e.session(t, b)

	_, out = e.post(t, "/v1/auth/elevation/approval", tokenA, nil)
	id := out["approvalId"].(string)
	if status, _ := e.call(t, "POST", "/v1/auth/approvals/"+id+"/approve", tokenA, nil); status != 403 {
		t.Fatalf("self approval: %d", status)
	}
	if _, list := e.call(t, "GET", "/v1/auth/approvals", tokenA, nil); len(list["approvals"].([]any)) != 0 {
		t.Fatalf("the requester sees its own request: %v", list)
	}
	_, list := e.call(t, "GET", "/v1/auth/approvals", tokenB, nil)
	if len(list["approvals"].([]any)) != 1 || list["approvals"].([]any)[0].(map[string]any)["deviceName"] != "laptop" {
		t.Fatalf("the other device must see who asks: %v", list)
	}
	if _, st := e.call(t, "GET", "/v1/auth/approvals/"+id, tokenA, nil); st["status"] != "pending" {
		t.Fatalf("status: %v", st)
	}
	if status, _ := e.call(t, "GET", "/v1/auth/approvals/"+id, tokenB, nil); status != 404 {
		t.Fatalf("another session read the request status: %d", status)
	}
	if status, _ := e.call(t, "POST", "/v1/auth/approvals/"+id+"/approve", tokenB, nil); status != 204 {
		t.Fatalf("approve: %d", status)
	}
	if _, el := e.call(t, "GET", "/v1/auth/elevation", tokenA, nil); el["elevatedUntil"].(float64) == 0 {
		t.Fatalf("elevation: %v", el)
	}
	if _, el := e.call(t, "GET", "/v1/auth/elevation", tokenB, nil); el["elevatedUntil"].(float64) != 0 {
		t.Fatalf("the approver was elevated too: %v", el)
	}
	newToken := e.session(t, a)
	if _, el := e.call(t, "GET", "/v1/auth/elevation", newToken, nil); el["elevatedUntil"].(float64) != 0 {
		t.Fatalf("a fresh session of the same device must start unelevated: %v", el)
	}
}

func TestElevationExpires(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("laptop"), newDevice("phone")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	_, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	e.signIn(t, b, out["code"].(string))
	tokenB := e.session(t, b)
	e.elevate(t, tokenA, tokenB)
	*e.clock = e.clock.Add(6 * time.Minute)
	if status, out := e.call(t, "DELETE", "/v1/devices/"+b.id, tokenA, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("elevation outlived its lifetime: %d %v", status, out)
	}
}

func TestExpiredApprovalsCannotBeApproved(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("laptop"), newDevice("phone")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	_, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	e.signIn(t, b, out["code"].(string))
	tokenB := e.session(t, b)
	_, out = e.post(t, "/v1/auth/elevation/approval", tokenA, nil)
	*e.clock = e.clock.Add(6 * time.Minute)
	if status, _ := e.call(t, "POST", "/v1/auth/approvals/"+out["approvalId"].(string)+"/approve", tokenB, nil); status != 404 {
		t.Fatalf("approving a stale request: %d", status)
	}
}

func TestGitHubElevationRequiresTheSameGitHubUser(t *testing.T) {
	e := newEnv(t)
	e.gh.pending.Store(0)
	signIn := func(name string) (string, string) {
		_, out := e.post(t, "/v1/auth/github/device", "", nil)
		flowID := out["flowId"].(string)
		*e.clock = e.clock.Add(6 * time.Second)
		d := newDevice(name)
		body := d.registration()
		body["flowId"] = flowID
		status, out := e.post(t, "/v1/auth/github/poll", "", body)
		if status != 201 {
			t.Fatalf("sign-in %d %v", status, out)
		}
		d.id = out["deviceId"].(string)
		return e.session(t, d), out["accountId"].(string)
	}
	token, _ := signIn("laptop")
	startElevation := func() string {
		status, out := e.post(t, "/v1/auth/elevation/github", token, nil)
		if status != 200 {
			t.Fatalf("start %d %v", status, out)
		}
		*e.clock = e.clock.Add(6 * time.Second)
		return out["flowId"].(string)
	}
	e.gh.userID.Store(999)
	flow := startElevation()
	if status, out := e.post(t, "/v1/auth/elevation/github/poll", token, map[string]string{"flowId": flow}); status != 403 || out["error"] != "wrong-account" {
		t.Fatalf("a different GitHub user elevated the session: %d %v", status, out)
	}
	e.gh.userID.Store(4242)
	flow = startElevation()
	if status, out := e.post(t, "/v1/auth/elevation/github/poll", token, map[string]string{"flowId": flow}); status != 200 || out["elevatedUntil"].(float64) == 0 {
		t.Fatalf("elevation with the right user: %d %v", status, out)
	}
	other, _ := signIn("phone")
	flow = startElevation()
	if status, _ := e.post(t, "/v1/auth/elevation/github/poll", other, map[string]string{"flowId": flow}); status != 404 {
		t.Fatalf("another session used the flow: %d", status)
	}
}

func TestInviteAccountsCannotElevateWithGitHub(t *testing.T) {
	e := newEnv(t)
	d := newDevice("laptop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	if status, out := e.post(t, "/v1/auth/elevation/github", token, nil); status != 409 || out["error"] != "not-a-github-account" {
		t.Fatalf("%d %v", status, out)
	}
}

func TestDeviceInvitesNeedElevationOnceTheAccountHasTwoDevices(t *testing.T) {
	e := newEnv(t)
	a := newDevice("laptop")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	b := newDevice("phone")
	status, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	if status != 201 {
		t.Fatalf("the first extra device needs no approval: %d", status)
	}
	e.signIn(t, b, out["code"].(string))
	tokenB := e.session(t, b)
	if status, out := e.post(t, "/v1/devices/invite", tokenA, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("a third device needs approval: %d %v", status, out)
	}
	e.elevate(t, tokenA, tokenB)
	if status, _ := e.post(t, "/v1/devices/invite", tokenA, nil); status != 201 {
		t.Fatalf("after approval: %d", status)
	}
}

func TestStolenTokenCannotElevateItselfWithADeviceItJustAdded(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.ApproverMinAge = config.Duration(24 * time.Hour)
	owner := newDevice("laptop")
	e.signIn(t, owner, e.invite(t, ""))
	stolen := e.session(t, owner)

	_, out := e.post(t, "/v1/devices/invite", stolen, nil)
	attacker := newDevice("attacker")
	e.signIn(t, attacker, out["code"].(string))
	attackerToken := e.session(t, attacker)

	_, out = e.post(t, "/v1/auth/elevation/approval", stolen, nil)
	id := out["approvalId"].(string)
	status, out := e.call(t, "POST", "/v1/auth/approvals/"+id+"/approve", attackerToken, nil)
	if status != 403 || out["error"] != "device-too-new" {
		t.Fatalf("a device that has just joined must not approve: %d %v", status, out)
	}
	if status, out := e.call(t, "DELETE", "/v1/account", stolen, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("the stolen token destroyed the account: %d %v", status, out)
	}
	*e.clock = e.clock.Add(25 * time.Hour)
	stolen = e.session(t, owner)
	attackerToken = e.session(t, attacker)
	_, out = e.post(t, "/v1/auth/elevation/approval", stolen, nil)
	if status, _ := e.call(t, "POST", "/v1/auth/approvals/"+out["approvalId"].(string)+"/approve", attackerToken, nil); status != 204 {
		t.Fatalf("an established device may approve: %d", status)
	}
}

func TestApprovalListShowsHowLongTheRequesterHasBeenAround(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("laptop"), newDevice("phone")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	_, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	e.signIn(t, b, out["code"].(string))
	tokenB := e.session(t, b)
	e.post(t, "/v1/auth/elevation/approval", tokenA, nil)
	_, list := e.call(t, "GET", "/v1/auth/approvals", tokenB, nil)
	entry := list["approvals"].([]any)[0].(map[string]any)
	if entry["deviceCreatedAt"].(float64) == 0 {
		t.Fatalf("the approval card needs the requester's age: %v", entry)
	}
}

func TestChallengesOfOneAddressCannotEvictAnotherAddressesChallenge(t *testing.T) {
	e := newEnv(t)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
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
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	var ended [][]byte
	e.svc.Hooks.SessionEnded = func(hash []byte) { ended = append(ended, hash) }
	e.call(t, "DELETE", "/v1/auth/session", token, nil)
	if len(ended) != 1 || !ids.Equal(ended[0], ids.Hash(token)) {
		t.Fatalf("hook: %v", ended)
	}
}

func TestLiveInvitesCountTowardsTheTwoDeviceRule(t *testing.T) {
	e := newEnv(t)
	d := newDevice("laptop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	if status, _ := e.post(t, "/v1/devices/invite", token, nil); status != 201 {
		t.Fatalf("first invite: %d", status)
	}
	if status, out := e.post(t, "/v1/devices/invite", token, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("a second live invite would let a stolen token add two devices at once: %d %v", status, out)
	}
}

func TestInviteMintedAtOneDeviceDiesIfTheAccountGrowsFirst(t *testing.T) {
	e := newEnv(t)
	a := newDevice("laptop")
	e.signIn(t, a, e.invite(t, ""))
	token := e.session(t, a)
	_, out := e.post(t, "/v1/devices/invite", token, nil)
	stale := out["code"].(string)
	for _, name := range []string{"phone", "tablet"} {
		if _, err := e.svc.DB.AddDevice(t.Context(), a.accountID(e, t), store.NewDevice{Name: name, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10); err != nil {
			t.Fatal(err)
		}
	}
	d := newDevice("late")
	body := d.registration()
	body["code"] = stale
	if status, out := e.post(t, "/v1/auth/invite", "", body); status != 403 || out["error"] != "invalid-invite" {
		t.Fatalf("%d %v", status, out)
	}
}

func (d *device) accountID(e *env, t *testing.T) string {
	t.Helper()
	dev, err := e.svc.DB.Device(t.Context(), d.id)
	if err != nil {
		t.Fatal(err)
	}
	return dev.AccountID
}

func TestRevokingRulesDuringProbation(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.ApproverMinAge = config.Duration(24 * time.Hour)
	owner := newDevice("laptop")
	e.signIn(t, owner, e.invite(t, ""))
	*e.clock = e.clock.Add(25 * time.Hour)
	ownerToken := e.session(t, owner)
	_, out := e.post(t, "/v1/devices/invite", ownerToken, nil)
	intruder := newDevice("intruder")
	e.signIn(t, intruder, out["code"].(string))
	intruderToken := e.session(t, intruder)

	if status, out := e.call(t, "DELETE", "/v1/devices/"+owner.id, intruderToken, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("a young device must not revoke the established one: %d %v", status, out)
	}
	if status, out := e.call(t, "DELETE", "/v1/devices/"+owner.id, ownerToken, nil); status != 403 || out["error"] != "elevation-required" {
		t.Fatalf("revoking the last established device, even as itself, needs elevation: %d %v", status, out)
	}
	if status, _ := e.call(t, "DELETE", "/v1/auth/session", e.session(t, owner), nil); status != 204 {
		t.Fatalf("logging out stays free: %d", status)
	}
	ownerToken = e.session(t, owner)
	if status, _ := e.call(t, "DELETE", "/v1/devices/"+intruder.id, ownerToken, nil); status != 204 {
		t.Fatalf("an established device removes an intruder still on probation: %d", status)
	}
}

func TestADeviceMayRevokeItselfOnlyWhileAnOlderDeviceRemains(t *testing.T) {
	for _, minAge := range []time.Duration{0, 24 * time.Hour} {
		e := newEnv(t)
		e.svc.Cfg.ApproverMinAge = config.Duration(minAge)
		older, younger := newDevice("laptop"), newDevice("phone")
		e.signIn(t, older, e.invite(t, ""))
		tokenOlder := e.session(t, older)
		_, out := e.post(t, "/v1/devices/invite", tokenOlder, nil)
		*e.clock = e.clock.Add(time.Second)
		e.signIn(t, younger, out["code"].(string))
		*e.clock = e.clock.Add(25 * time.Hour)
		tokenOlder, tokenYounger := e.session(t, older), e.session(t, younger)
		if status, out := e.call(t, "DELETE", "/v1/devices/"+older.id, tokenOlder, nil); status != 403 || out["error"] != "elevation-required" {
			t.Fatalf("min age %v: the oldest device has nobody older to fall back on: %d %v", minAge, status, out)
		}
		if status, _ := e.call(t, "DELETE", "/v1/devices/"+younger.id, tokenYounger, nil); status != 204 {
			t.Fatalf("min age %v: a device with an older one remaining may leave: %d", minAge, status)
		}
	}
}

func TestAFreshSingleDeviceCannotBeRevokedByItsToken(t *testing.T) {
	for _, minAge := range []time.Duration{0, 24 * time.Hour} {
		e := newEnv(t)
		e.svc.Cfg.ApproverMinAge = config.Duration(minAge)
		d := newDevice("laptop")
		e.signIn(t, d, e.invite(t, ""))
		token := e.session(t, d)
		if status, out := e.call(t, "DELETE", "/v1/devices/"+d.id, token, nil); status != 403 || out["error"] != "elevation-required" {
			t.Fatalf("min age %v: a stolen token removed the account's only device: %d %v", minAge, status, out)
		}
		if status, _ := e.call(t, "DELETE", "/v1/auth/session", token, nil); status != 204 {
			t.Fatalf("logout stays free: %d", status)
		}
	}
}

func TestNewDevicesAreAnnouncedAndFlaggedUntilSeen(t *testing.T) {
	e := newEnv(t)
	a, b := newDevice("laptop"), newDevice("phone")
	e.signIn(t, a, e.invite(t, ""))
	tokenA := e.session(t, a)
	var announced []string
	e.svc.Hooks.DeviceAdded = func(accountID string, dev store.Device) { announced = append(announced, dev.Name) }
	_, out := e.post(t, "/v1/devices/invite", tokenA, nil)
	e.signIn(t, b, out["code"].(string))
	if len(announced) != 1 || announced[0] != "phone" {
		t.Fatalf("hook: %v", announced)
	}
	_, list := e.call(t, "GET", "/v1/devices", tokenA, nil)
	flagged := ""
	for _, raw := range list["devices"].([]any) {
		entry := raw.(map[string]any)
		if entry["new"] == true {
			flagged = entry["name"].(string)
		}
	}
	if flagged != "phone" {
		t.Fatalf("the other device must be flagged as new: %v", list)
	}
	sign := func(key ed25519.PrivateKey, viewer, target string) map[string]string {
		return map[string]string{"sig": httpx.EncodeB64(ed25519.Sign(key, SeenMessage(viewer, target)))}
	}
	if status, out := e.call(t, "POST", "/v1/devices/"+b.id+"/seen", tokenA, nil); status == 204 {
		t.Fatalf("a session token alone acknowledged a device: %v", out)
	}
	if status, out := e.call(t, "POST", "/v1/devices/"+b.id+"/seen", tokenA, sign(b.sign, a.id, b.id)); status != 403 || out["error"] != "bad-signature" {
		t.Fatalf("a signature from another key acknowledged a device: %d %v", status, out)
	}
	if status, _ := e.call(t, "POST", "/v1/devices/"+b.id+"/seen", tokenA, sign(a.sign, a.id, b.id)); status != 204 {
		t.Fatalf("mark seen: %d", status)
	}
	_, list = e.call(t, "GET", "/v1/devices", tokenA, nil)
	for _, raw := range list["devices"].([]any) {
		if raw.(map[string]any)["new"] == true {
			t.Fatalf("still flagged: %v", list)
		}
	}
	if status, _ := e.call(t, "POST", "/v1/devices/"+strings.Repeat("a", 26)+"/seen", tokenA, sign(a.sign, a.id, strings.Repeat("a", 26))); status != 404 {
		t.Fatalf("unknown device: %d", status)
	}
}
