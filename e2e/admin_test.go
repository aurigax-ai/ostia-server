package e2e

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func adminRequest(t *testing.T, e *env, method, path string, form url.Values, cookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	client := e.net.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, e.net.URL(path), body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res, string(raw)
}

var continueLink = regexp.MustCompile(`<a class="btn" href="([^"]+)">Continue</a>`)

func nextStep(t *testing.T, body string) string {
	t.Helper()
	m := continueLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no way on in the page: %s", body)
	}
	return html.UnescapeString(m[1])
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func adminEnv(t *testing.T) (*env, *testkit.FakeGitHub) {
	t.Helper()
	gh := testkit.NewFakeGitHub(t, 0)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(testkit.WebClientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return newEnv(t, fmt.Sprintf("[auth]\ngithub_base_url = %q\ngithub_api_url = %q\n[admin]\nenabled = true\ngithub_client_id = %q\ngithub_client_secret_file = %q\n", gh.Server.URL, gh.Server.URL, testkit.WebClientID, secret)), gh
}

func setupCode(t *testing.T, e *env) string {
	t.Helper()
	code, _, _ := strings.Cut(e.proc.Admin(t, "setup"), "\n")
	return code
}

func gitHubSignIn(t *testing.T, e *env, gh *testkit.FakeGitHub, code string, id int64, login string) (*http.Response, string) {
	t.Helper()
	res, body := adminRequest(t, e, "POST", "/admin/github/start", url.Values{"code": {code}}, nil)
	state := cookieNamed(res, "__Host-ostia_admin_oauth")
	if res.StatusCode != http.StatusOK || state == nil || !state.Secure || !state.HttpOnly || state.SameSite != http.SameSiteStrictMode {
		t.Fatalf("start: %d %v %s", res.StatusCode, res.Header, body)
	}
	callback, err := url.Parse(gh.Authorize(t, nextStep(t, body), id, login))
	if err != nil {
		t.Fatal(err)
	}
	res, body = adminRequest(t, e, "GET", callback.RequestURI(), nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d %s", res.StatusCode, body)
	}
	return adminRequest(t, e, "GET", nextStep(t, body), nil, state)
}

func TestAdminSetupAndGitHubSignInToTheWebUI(t *testing.T) {
	e, gh := adminEnv(t)
	out := e.proc.Admin(t, "setup")
	code, rest, _ := strings.Cut(out, "\n")
	if !strings.Contains(rest, "https://"+apiHost+"/admin/") {
		t.Fatalf("the command must say where to continue: %q", out)
	}
	if _, body := adminRequest(t, e, "GET", "/admin/", nil, nil); !strings.Contains(body, "Set up admin") || strings.Contains(body, "kubectl") {
		t.Fatalf("a fresh server offers setup: %s", body)
	}
	if res, _ := adminRequest(t, e, "GET", "/admin/invites", nil, nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", res.StatusCode)
	}
	if res, _ := adminRequest(t, e, "POST", "/admin/github/start", url.Values{"code": {"WRONG-CODE"}}, nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong code started a setup: %d", res.StatusCode)
	}

	res, _ := gitHubSignIn(t, e, gh, code, 4242, "octocat")
	session := cookieNamed(res, "__Host-ostia_admin")
	if res.StatusCode != http.StatusSeeOther || session == nil || !session.Secure || !session.HttpOnly {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	if _, body := adminRequest(t, e, "GET", "/admin/", nil, nil); !strings.Contains(body, "Sign in with GitHub") || strings.Contains(body, `name="code"`) {
		t.Fatalf("after setup the page offers GitHub only: %s", body)
	}
	if res, _ := adminRequest(t, e, "POST", "/admin/github/start", url.Values{"code": {code}}, nil); res.StatusCode != http.StatusConflict {
		t.Fatalf("setup was open with an admin present: %d", res.StatusCode)
	}
	if res, _ := adminRequest(t, e, "POST", "/admin/login", url.Values{"code": {code}}, nil); res.StatusCode == http.StatusSeeOther {
		t.Fatalf("a code signed in: %d", res.StatusCode)
	}

	account := e.user(t, "laptop").ID.AccountID
	if res, body := adminRequest(t, e, "GET", "/admin/accounts/"+account, nil, session); res.StatusCode != http.StatusOK || !strings.Contains(body, "laptop") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}

	if res, body := gitHubSignIn(t, e, gh, "", 9, "mallory"); res.StatusCode != http.StatusForbidden || cookieNamed(res, "__Host-ostia_admin") != nil {
		t.Fatalf("a GitHub user that is not the admin: %d %s", res.StatusCode, body)
	}
	again, _ := gitHubSignIn(t, e, gh, "", 4242, "octocat")
	if again.StatusCode != http.StatusSeeOther || cookieNamed(again, "__Host-ostia_admin") == nil {
		t.Fatalf("the admin could not sign in again: %d", again.StatusCode)
	}

	audit := e.proc.Admin(t, "audit")
	for _, want := range []string{"cli\tsetup-code", "github:4242\tsetup\toctocat", "github:4242\tlogin\toctocat", "anonymous\trefused\tsetup-code", "anonymous\trefused\tnot-admin 9"} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit lacks %q:\n%s", want, audit)
		}
	}
	if _, err := exec.Command(e.proc.Binary, "admin", "-config", e.proc.ConfigPath, "setup").CombinedOutput(); err == nil {
		t.Fatal("setup printed a code while an admin exists")
	}
	if got := e.proc.Admin(t, "logout-all"); !strings.Contains(got, "ended 2 admin sessions") {
		t.Fatalf("logout-all: %q", got)
	}
	if res, _ := adminRequest(t, e, "GET", "/admin/invites", nil, session); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session survived logout-all: %d", res.StatusCode)
	}
}

func TestAdminResetReturnsTheServerToSetup(t *testing.T) {
	e, gh := adminEnv(t)
	res, _ := gitHubSignIn(t, e, gh, setupCode(t, e), 4242, "octocat")
	session := cookieNamed(res, "__Host-ostia_admin")
	if session == nil {
		t.Fatalf("%d", res.StatusCode)
	}
	if got := e.proc.Admin(t, "reset"); !strings.Contains(got, "removed 1 admins and ended 1 admin sessions") {
		t.Fatalf("reset: %q", got)
	}
	if res, _ := adminRequest(t, e, "GET", "/admin/invites", nil, session); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session survived the reset: %d", res.StatusCode)
	}
	if _, body := adminRequest(t, e, "GET", "/admin/", nil, nil); !strings.Contains(body, "Set up admin") {
		t.Fatalf("after a reset the page offers setup: %s", body)
	}
	if res, _ := gitHubSignIn(t, e, gh, setupCode(t, e), 7, "newcomer"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup after a reset: %d", res.StatusCode)
	}
	if audit := e.proc.Admin(t, "audit"); !strings.Contains(audit, "cli\treset\t1 admins, 1 sessions") {
		t.Fatalf("audit:\n%s", audit)
	}
	if out, err := exec.Command(e.proc.Binary, "admin", "-config", e.proc.ConfigPath, "login").CombinedOutput(); err == nil || !strings.Contains(string(out), "unknown admin command") {
		t.Fatalf("the code sign-in command is gone: %v %s", err, out)
	}
}

func TestAdminWebUIIsOffByDefault(t *testing.T) {
	e := newEnv(t, "")
	res, _ := adminRequest(t, e, "GET", "/admin/", nil, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("%d", res.StatusCode)
	}
	out, err := exec.Command(e.proc.Binary, "admin", "-config", e.proc.ConfigPath, "setup").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "admin.enabled") {
		t.Fatalf("setup must say why it is refused: %v %s", err, out)
	}
}
