package e2e

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

type pushFixture struct {
	env  *env
	fake *testkit.FakePush
}

func newPushFixture(t *testing.T, extra string) *pushFixture {
	t.Helper()
	fake := testkit.NewFakePush(t)
	account, p8 := fake.WriteCredentials(t, t.TempDir())
	e := newEnvModules(t, "relay = true\npublish = true\nsync = true\npush = true\n", fake.ConfigTOML(account, p8)+extra)
	return &pushFixture{env: e, fake: fake}
}

func registerPhone(t *testing.T, api *testkit.API, platform, token string) string {
	t.Helper()
	res := api.Must(t, http.StatusCreated, "POST", "/v1/push/register", map[string]string{"platform": platform, "token": token})
	handle := res.Map(t)["handle"].(string)
	if len(handle) != 32 || strings.Contains(handle, token) {
		t.Fatalf("handle must be opaque: %q", handle)
	}
	return handle
}

func TestPhoneRegistersAndDesktopPingsAndroidWithAnEmptyBody(t *testing.T) {
	f := newPushFixture(t, "")
	phone := f.env.anonymous()
	handle := registerPhone(t, phone, "fcm", "fcm-device-token-123")

	desktop := f.env.user(t, "desktop")
	desktop.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)

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
	handle := registerPhone(t, f.env.anonymous(), "apns", "abcdef0123456789")
	f.env.anonymous().Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)

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

func TestPingRefusesABodyAndIsRateLimitedPerHandle(t *testing.T) {
	f := newPushFixture(t, "")
	handle := registerPhone(t, f.env.anonymous(), "fcm", "tok")
	api := f.env.anonymous()
	if res := api.Do(t, "POST", "/v1/push/"+handle, map[string]string{"title": "secret agent output"}); res.Status != http.StatusBadRequest {
		t.Fatalf("a ping with content: %s", res)
	}
	if len(f.fake.FCMRequests()) != 0 {
		t.Fatal("a refused ping reached FCM")
	}
	api.Must(t, http.StatusNoContent, "POST", "/v1/push/"+handle, nil)
	res := api.Do(t, "POST", "/v1/push/"+handle, nil)
	if res.Status != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "30" {
		t.Fatalf("second ping within 30 s: %s %v", res, res.Header)
	}
	if len(f.fake.FCMRequests()) != 1 {
		t.Fatalf("FCM requests: %d", len(f.fake.FCMRequests()))
	}
	other := registerPhone(t, f.env.anonymous(), "fcm", "tok2")
	api.Must(t, http.StatusNoContent, "POST", "/v1/push/"+other, nil)
}

func TestTokensAreSealedAtRest(t *testing.T) {
	f := newPushFixture(t, "")
	token := "fcm-token-that-must-not-be-readable-9876"
	registerPhone(t, f.env.anonymous(), "fcm", token)
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

func TestRevokedHandleStopsWorking(t *testing.T) {
	f := newPushFixture(t, "")
	api := f.env.anonymous()
	handle := registerPhone(t, api, "fcm", "tok")
	api.Must(t, http.StatusNoContent, "DELETE", "/v1/push/"+handle, nil)
	if res := api.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("ping after delete: %s", res)
	}
	if res := api.Do(t, "DELETE", "/v1/push/"+handle, nil); res.Status != http.StatusNotFound {
		t.Fatalf("second delete: %s", res)
	}
	if len(f.fake.FCMRequests()) != 0 {
		t.Fatal("a deleted handle reached FCM")
	}
}

func TestPlatformRejectedTokenDropsTheHandle(t *testing.T) {
	f := newPushFixture(t, "")
	api := f.env.anonymous()
	handle := registerPhone(t, api, "fcm", "stale-token")
	f.fake.FailFCM(http.StatusNotFound, `{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`)
	if res := api.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("unregistered token: %s", res)
	}
	f.fake.FailFCM(http.StatusOK, "")
	if res := api.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
		t.Fatalf("handle must be gone after the platform rejected its token: %s", res)
	}
	apnsHandle := registerPhone(t, api, "apns", "deadbeef")
	f.fake.FailAPNs(http.StatusGone, `{"reason":"Unregistered"}`)
	if res := api.Do(t, "POST", "/v1/push/"+apnsHandle, nil); res.Status != http.StatusGone {
		t.Fatalf("APNs unregistered: %s", res)
	}
}

func TestPlatformOutageIsReportedAsBadGateway(t *testing.T) {
	f := newPushFixture(t, "")
	api := f.env.anonymous()
	handle := registerPhone(t, api, "fcm", "tok")
	f.fake.FailFCM(http.StatusServiceUnavailable, "")
	if res := api.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusBadGateway {
		t.Fatalf("platform outage: %s", res)
	}
}

func TestRegistrationValidatesAndRateLimits(t *testing.T) {
	f := newPushFixture(t, "[push]\nmax_handles = 3\n")
	api := f.env.anonymous()
	for name, body := range map[string]map[string]string{
		"unknown platform": {"platform": "wns", "token": "x"},
		"empty token":      {"platform": "fcm", "token": ""},
		"huge token":       {"platform": "fcm", "token": strings.Repeat("x", 5000)},
	} {
		if res := api.Do(t, "POST", "/v1/push/register", body); res.Status != http.StatusBadRequest {
			t.Errorf("%s: %s", name, res)
		}
	}
	for range 3 {
		registerPhone(t, api, "fcm", "tok")
	}
	if res := api.Do(t, "POST", "/v1/push/register", map[string]string{"platform": "fcm", "token": "one too many"}); res.Status != http.StatusServiceUnavailable {
		t.Fatalf("handle cap: %s", res)
	}
}

func TestRegistrationIsRateLimitedPerSourceAddress(t *testing.T) {
	f := newPushFixture(t, "")
	api := f.env.anonymous()
	limited := false
	for range 30 {
		if api.Do(t, "POST", "/v1/push/register", map[string]string{"platform": "fcm", "token": "t"}).Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("registration is not rate limited")
	}
}

func TestUnknownOrMalformedHandlesAreGone(t *testing.T) {
	f := newPushFixture(t, "")
	api := f.env.anonymous()
	for _, handle := range []string{strings.Repeat("a", 32), "short", strings.Repeat("A", 32)} {
		if res := api.Do(t, "POST", "/v1/push/"+handle, nil); res.Status != http.StatusGone {
			t.Errorf("%s: %s", handle, res)
		}
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
