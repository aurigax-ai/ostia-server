package e2e

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

type pushFixture struct {
	env     *env
	fake    *testkit.FakePush
	desktop *testkit.API
}

func newPushFixture(t *testing.T, extra string) *pushFixture {
	t.Helper()
	fake := testkit.NewFakePush(t)
	account, p8 := fake.WriteCredentials(t, t.TempDir())
	e := newEnvModules(t, "relay = true\npublish = true\nsync = true\npush = true\n", fake.ConfigTOML(account, p8)+testkit.WithKey(extra, "[push]", "ticket_burst", "1000"))
	return &pushFixture{env: e, fake: fake, desktop: e.user(t, "desktop")}
}

func ticketFor(t *testing.T, desktop *testkit.API) string {
	t.Helper()
	return desktop.Must(t, http.StatusCreated, "POST", "/v1/push/tickets", nil).Map(t)["ticket"].(string)
}

func registerPhone(t *testing.T, e *env, desktop *testkit.API, platform, token string) string {
	t.Helper()
	phone := e.anonymous()
	res := phone.Must(t, http.StatusCreated, "POST", "/v1/push/register", map[string]string{"platform": platform, "token": token, "ticket": ticketFor(t, desktop)})
	handle := res.Map(t)["handle"].(string)
	if len(handle) != 32 || strings.Contains(handle, token) {
		t.Fatalf("handle must be opaque: %q", handle)
	}
	return handle
}

func TestPhoneRegistersWithATicketAndDesktopPingsAndroidWithAnEmptyBody(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "fcm-device-token-123")
	f.desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)

	sent := f.fake.FCMRequests()
	if len(sent) != 1 || !sent[0].TokenOK {
		t.Fatalf("FCM requests: %+v", sent)
	}
	var message map[string]any
	if err := json.Unmarshal(sent[0].Body, &message); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"message": map[string]any{
		"token":   "fcm-device-token-123",
		"data":    map[string]any{"v": "1"},
		"android": map[string]any{"priority": "HIGH"},
	}}
	gotJSON, _ := json.Marshal(message, json.Deterministic(true))
	wantJSON, _ := json.Marshal(want, json.Deterministic(true))
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("a push must carry no content, only {v:1}:\n got %s\nwant %s", gotJSON, wantJSON)
	}
	if f.fake.Exchanges() != 1 {
		t.Fatalf("service account token exchanges: %d", f.fake.Exchanges())
	}
}

func TestIOSPingIsAFixedAlertWithMutableContent(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "apns", "abcdef0123456789")
	f.desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)

	sent := f.fake.APNsRequests()
	if len(sent) != 1 || !sent[0].TokenOK {
		t.Fatalf("APNs requests: %+v", sent)
	}
	req := sent[0]
	if req.Path != "/3/device/abcdef0123456789" || req.Header.Get("apns-topic") != testkit.APNsTopic ||
		req.Header.Get("apns-push-type") != "alert" || req.Header.Get("apns-priority") != "10" {
		t.Fatalf("APNs request: %s %v", req.Path, req.Header)
	}
	if string(req.Body) != `{"aps":{"alert":{"loc-key":"DESKTOP_NEEDS_YOU"},"mutable-content":1}}` {
		t.Fatalf("payload: %s", req.Body)
	}
}

func TestRegistrationNeedsAValidSingleUseTicket(t *testing.T) {
	f := newPushFixture(t, "[push]\nticket_ttl = \"1s\"\n")
	phone := f.env.anonymous()
	body := func(ticket string) map[string]string {
		return map[string]string{"platform": "fcm", "token": "tok", "ticket": ticket}
	}
	for name, ticket := range map[string]string{"missing": "", "invented": "not-a-ticket"} {
		if res := phone.Do(t, "POST", "/v1/push/register", body(ticket)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "invalid-ticket" {
			t.Errorf("%s ticket: %s", name, res)
		}
	}
	ticket := ticketFor(t, f.desktop)
	phone.Must(t, http.StatusCreated, "POST", "/v1/push/register", body(ticket))
	if res := phone.Do(t, "POST", "/v1/push/register", body(ticket)); res.Status != http.StatusForbidden {
		t.Fatalf("a ticket worked twice: %s", res)
	}
	stale := ticketFor(t, f.desktop)
	time.Sleep(1200 * time.Millisecond)
	if res := phone.Do(t, "POST", "/v1/push/register", body(stale)); res.Status != http.StatusForbidden {
		t.Fatalf("an expired ticket worked: %s", res)
	}
}

func TestTicketsRequireASessionAndAreCapped(t *testing.T) {
	f := newPushFixture(t, "")
	if res := f.env.anonymous().Do(t, "POST", "/v1/push/tickets", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("anonymous ticket: %s", res)
	}
	limited := false
	for range 30 {
		if f.desktop.Do(t, "POST", "/v1/push/tickets", nil).Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("an account can mint unlimited tickets")
	}
}

func TestOnlyTheOwningAccountsSessionCanPingOrDeleteAHandle(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "tok")
	if res := f.env.anonymous().Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("a handle alone must not allow a ping: %s", res)
	}
	stranger := f.env.user(t, "stranger")
	if res := stranger.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("another account's ping: %s", res)
	}
	if res := stranger.Do(t, "DELETE", "/v1/push/"+handle, nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's delete: %s", res)
	}
	if len(f.fake.FCMRequests()) != 0 {
		t.Fatal("a refused ping reached FCM")
	}
	f.desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)
}

func TestPingRefusesABodyAndIsRateLimitedPerHandle(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "tok")
	if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, map[string]string{"title": "secret agent output"}); res.Status != http.StatusBadRequest {
		t.Fatalf("a ping with content: %s", res)
	}
	if len(f.fake.FCMRequests()) != 0 {
		t.Fatal("a refused ping reached FCM")
	}
	f.desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)
	res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil)
	if res.Status != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "30" {
		t.Fatalf("second ping within 30 s: %s %v", res, res.Header)
	}
	if len(f.fake.FCMRequests()) != 1 {
		t.Fatalf("FCM requests: %d", len(f.fake.FCMRequests()))
	}
	other := registerPhone(t, f.env, f.desktop, "fcm", "tok2")
	f.desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+other, nil)
}

func TestTokensAreSealedAtRest(t *testing.T) {
	f := newPushFixture(t, "")
	token := "fcm-token-that-must-not-be-readable-9876"
	registerPhone(t, f.env, f.desktop, "fcm", token)
	f.env.proc.Stop(t)
	_ = filepath.WalkDir(f.env.proc.DataDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			raw, _ := os.ReadFile(path)
			if bytes.Contains(raw, []byte(token)) {
				t.Errorf("%s holds the push token in the clear", path)
			}
		}
		return nil
	})
}

func TestDeletedHandleStopsWorking(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "tok")
	f.desktop.Must(t, http.StatusNoContent, "DELETE", "/v1/push/"+handle, nil)
	if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("ping after delete: %s", res)
	}
	if res := f.desktop.Do(t, "DELETE", "/v1/push/"+handle, nil); res.Status != http.StatusNotFound {
		t.Fatalf("second delete: %s", res)
	}
	if len(f.fake.FCMRequests()) != 0 {
		t.Fatal("a deleted handle reached FCM")
	}
}

func TestPlatformRejectedTokenDropsTheHandle(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "stale-token")
	f.fake.FailFCM(http.StatusNotFound, `{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`)
	if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("unregistered token: %s", res)
	}
	f.fake.FailFCM(http.StatusOK, "")
	if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("handle must be gone after the platform rejected its token: %s", res)
	}
	apnsHandle := registerPhone(t, f.env, f.desktop, "apns", "deadbeef")
	f.fake.FailAPNs(http.StatusGone, `{"reason":"Unregistered"}`)
	if res := f.desktop.Do(t, "POST", "/v1/push/"+apnsHandle, nil); res.Status != http.StatusGone {
		t.Fatalf("APNs unregistered: %s", res)
	}
}

func TestPlatformOutageIsReportedAsBadGateway(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "tok")
	f.fake.FailFCM(http.StatusServiceUnavailable, "")
	if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusBadGateway {
		t.Fatalf("platform outage: %s", res)
	}
}

func TestRegistrationValidatesInputAndCapsHandlesPerAccount(t *testing.T) {
	f := newPushFixture(t, "[push]\nmax_handles_per_account = 2\n")
	phone := f.env.anonymous()
	for name, body := range map[string]map[string]string{
		"unknown platform": {"platform": "wns", "token": "x"},
		"empty token":      {"platform": "fcm", "token": ""},
		"huge token":       {"platform": "fcm", "token": strings.Repeat("x", 5000)},
	} {
		body["ticket"] = ticketFor(t, f.desktop)
		if res := phone.Do(t, "POST", "/v1/push/register", body); res.Status != http.StatusBadRequest {
			t.Errorf("%s: %s", name, res)
		}
	}
	oldest := registerPhone(t, f.env, f.desktop, "fcm", "one")
	registerPhone(t, f.env, f.desktop, "fcm", "two")
	registerPhone(t, f.env, f.desktop, "fcm", "three")
	if res := f.desktop.Do(t, "POST", "/v1/push/"+oldest, nil); res.Status != http.StatusGone {
		t.Fatalf("at the per-account cap the oldest handle is replaced, so abandoned handles end by themselves: %s", res)
	}
	other := f.env.user(t, "someone else")
	registerPhone(t, f.env, other, "fcm", "theirs")
}

func TestRegistrationIsRateLimitedPerSourceAddress(t *testing.T) {
	f := newPushFixture(t, "")
	phone := f.env.anonymous()
	limited := false
	for range 30 {
		res := phone.Do(t, "POST", "/v1/push/register", map[string]string{"platform": "fcm", "token": "t", "ticket": "guess"})
		if res.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("guessing tickets is not rate limited")
	}
}

func TestUnknownHandlesAreGone(t *testing.T) {
	f := newPushFixture(t, "")
	for _, handle := range []string{strings.Repeat("a", 32), "short", strings.Repeat("A", 32)} {
		if res := f.desktop.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
			t.Errorf("%s: %s", handle, res)
		}
	}
}

func TestDeletingTheAccountDeletesItsHandles(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env, f.desktop, "fcm", "tok")
	second := f.env.device(t, f.desktop, "second desktop")
	f.desktop.ElevateByApproval(t, second)
	f.desktop.Must(t, http.StatusNoContent, "DELETE", "/v1/account", nil)
	if res := second.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("session of a deleted account: %s", res)
	}
	fresh := f.env.user(t, "fresh")
	if res := fresh.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("the handle outlived its account: %s", res)
	}
}

func TestPushModuleOffByDefault(t *testing.T) {
	e := newEnv(t, "")
	api := e.anonymous()
	if res := api.Do(t, "POST", "/v1/push/register", map[string]string{"platform": "fcm", "token": "x"}); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("push route exists although push is off: %s", res)
	}
	info := api.Must(t, http.StatusOK, "GET", "/v1/info", nil).Map(t)
	if info["modules"].(map[string]any)["push"] != false {
		t.Fatalf("info: %v", info)
	}
}

func TestTicketsAreRateLimitedPerAccount(t *testing.T) {
	f := newPushFixture(t, "[push]\nticket_burst = 2\n")
	f.desktop.Must(t, http.StatusCreated, "POST", "/v1/push/tickets", nil)
	f.desktop.Must(t, http.StatusCreated, "POST", "/v1/push/tickets", nil)
	res := f.desktop.Do(t, "POST", "/v1/push/tickets", nil)
	if res.Status != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "600" {
		t.Fatalf("a token must not be able to cycle an account's handles: %s %v", res, res.Header)
	}
	other := f.env.user(t, "someone else")
	other.Must(t, http.StatusCreated, "POST", "/v1/push/tickets", nil)
}
