package e2e

import (
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
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

func TestAdminLoginCodeFromTheCommandLineSignsInToTheWebUI(t *testing.T) {
	e := newEnv(t, "[admin]\nenabled = true\n")
	out := e.proc.Admin(t, "login")
	code, rest, _ := strings.Cut(out, "\n")
	if !strings.Contains(rest, "https://"+apiHost) || !strings.Contains(rest, "/admin/") {
		t.Fatalf("the command must say where to sign in: %q", out)
	}

	res, _ := adminRequest(t, e, "GET", "/admin/invites", nil, nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", res.StatusCode)
	}
	res, _ = adminRequest(t, e, "POST", "/admin/login", url.Values{"code": {code}}, nil)
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		cookie = c
	}
	if res.StatusCode != http.StatusSeeOther || cookie == nil || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	res, _ = adminRequest(t, e, "POST", "/admin/login", url.Values{"code": {code}}, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the code worked twice: %d", res.StatusCode)
	}

	account := e.user(t, "laptop").ID.AccountID
	res, body := adminRequest(t, e, "GET", "/admin/accounts/"+account, nil, cookie)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "laptop") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if got := e.proc.Admin(t, "audit"); !strings.Contains(got, "login-code") || !strings.Contains(got, "\tlogin\t") || !strings.Contains(got, "\tcode:") {
		t.Fatalf("audit: %q", got)
	}
	if got := e.proc.Admin(t, "logout-all"); !strings.Contains(got, "ended 1 admin sessions") {
		t.Fatalf("logout-all: %q", got)
	}
	if res, _ := adminRequest(t, e, "GET", "/admin/invites", nil, cookie); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session survived logout-all: %d", res.StatusCode)
	}
	if got := e.proc.Admin(t, "audit"); !strings.Contains(got, "logout-all") {
		t.Fatalf("audit: %q", got)
	}
}

func TestAdminWebUIIsOffByDefault(t *testing.T) {
	e := newEnv(t, "")
	res, _ := adminRequest(t, e, "GET", "/admin/", nil, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("%d", res.StatusCode)
	}
	out, err := exec.Command(e.proc.Binary, "admin", "-config", e.proc.ConfigPath, "login").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "admin.enabled") {
		t.Fatalf("login must say why it is refused: %v %s", err, out)
	}
}
