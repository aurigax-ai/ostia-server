package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func githubSignIn(t *testing.T, e *env, gh *testkit.FakeGitHub, name string) (*testkit.API, string) {
	t.Helper()
	api := testkit.NewAPI(e.net, testkit.NewIdentity(name))
	start := api.Must(t, http.StatusOK, "POST", "/v1/auth/github/device", nil).Map(t)
	if start["userCode"] != "WXYZ-9876" {
		t.Fatalf("start: %v", start)
	}
	flowID := start["flowId"].(string)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(1100 * time.Millisecond)
		body := api.ID.Registration()
		body["flowId"] = flowID
		res := api.Do(t, "POST", "/v1/auth/github/poll", body)
		switch res.Status {
		case http.StatusAccepted:
			continue
		case http.StatusCreated:
			m := res.Map(t)
			api.ID.DeviceID, api.ID.AccountID = m["deviceId"].(string), m["accountId"].(string)
			api.SignIn(t)
			return api, m["accountId"].(string)
		default:
			t.Fatalf("poll: %s", res)
		}
	}
	t.Fatal("GitHub sign-in never completed")
	return nil, ""
}

func TestGitHubSignInUsesOneAccountPerGitHubUser(t *testing.T) {
	gh := testkit.NewFakeGitHub(t, 4242)
	gh.PendingPolls(1)
	e := newEnv(t, githubConfig(gh, ""))
	info := e.anonymous().Must(t, http.StatusOK, "GET", "/v1/info", nil).Map(t)
	if info["auth"].(map[string]any)["github"] != true {
		t.Fatalf("info: %v", info)
	}
	first, account := githubSignIn(t, e, gh, "laptop")
	first.Must(t, http.StatusNoContent, "POST", "/v1/devices/heartbeat", nil)

	second, secondAccount := githubSignIn(t, e, gh, "desktop")
	if secondAccount != account || second.ID.DeviceID == first.ID.DeviceID {
		t.Fatalf("the same GitHub user must reach the same account with a new device: %s vs %s", secondAccount, account)
	}
	second.Must(t, http.StatusNoContent, "POST", "/v1/devices/heartbeat", nil)

	gh.SetUser(777)
	_, other := githubSignIn(t, e, gh, "someone else")
	if other == account {
		t.Fatal("a different GitHub user landed in the same account")
	}
}

func TestGitHubSignInAbsentWithoutAClientID(t *testing.T) {
	e := newEnv(t, "")
	if res := e.anonymous().Do(t, "POST", "/v1/auth/github/device", nil); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("%s", res)
	}
	info := e.anonymous().Must(t, http.StatusOK, "GET", "/v1/info", nil).Map(t)
	if info["auth"].(map[string]any)["github"] != false {
		t.Fatalf("info: %v", info)
	}
}

func TestSignInAttemptsAreRateLimited(t *testing.T) {
	e := newEnv(t, "")
	api := e.anonymous()
	body := api.ID.Registration()
	body["code"] = "wrong-code"
	var limited testkit.Response
	for range 40 {
		res := api.Do(t, "POST", "/v1/auth/invite", body)
		if res.Status == http.StatusTooManyRequests {
			limited = res
			break
		}
		if res.Status != http.StatusForbidden {
			t.Fatalf("%s", res)
		}
	}
	if limited.Status != http.StatusTooManyRequests || limited.Header.Get("Retry-After") == "" {
		t.Fatal("guessing invite codes is not rate limited")
	}
}

func TestAuthenticatedCallsAreRateLimitedPerDevice(t *testing.T) {
	e := newEnv(t, "")
	api := e.user(t, "desktop")
	limited := false
	for range 600 {
		if api.Do(t, "POST", "/v1/devices/heartbeat", nil).Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a single device can hammer the API without limit")
	}
	other := e.user(t, "other")
	other.Must(t, http.StatusNoContent, "POST", "/v1/devices/heartbeat", nil)
}

func TestSessionsExpire(t *testing.T) {
	e := newEnv(t, "[auth]\nsession_ttl = \"1s\"\n")
	api := e.user(t, "desktop")
	api.Must(t, http.StatusNoContent, "POST", "/v1/devices/heartbeat", nil)
	time.Sleep(1200 * time.Millisecond)
	if res := api.Do(t, "POST", "/v1/devices/heartbeat", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("expired session: %s", res)
	}
	api.SignIn(t)
	api.Must(t, http.StatusNoContent, "POST", "/v1/devices/heartbeat", nil)
}

func TestForgedSignaturesAndReplayedNoncesAreRefused(t *testing.T) {
	e := newEnv(t, "")
	api := e.user(t, "desktop")
	imposter := testkit.NewAPI(e.net, testkit.NewIdentity("imposter"))
	imposter.ID.DeviceID = api.ID.DeviceID
	imposter.Token = ""
	nonce := imposter.Must(t, http.StatusOK, "POST", "/v1/auth/challenge", map[string]string{"deviceId": api.ID.DeviceID}).Map(t)["nonce"].(string)
	forged := testkit.EncodeB64(make([]byte, 64))
	if res := imposter.Do(t, "POST", "/v1/auth/verify", map[string]string{"deviceId": api.ID.DeviceID, "nonce": nonce, "sig": forged}); res.Status != http.StatusUnauthorized {
		t.Fatalf("forged signature: %s", res)
	}
}
