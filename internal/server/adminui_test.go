package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/adminui"
	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

type adminEnv struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	now     time.Time
	ip      int
}

func newAdminEnv(t *testing.T, tune func(*config.Config), opts Options) *adminEnv {
	t.Helper()
	e := &adminEnv{t: t, now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API, cfg.Domains.Share, cfg.Domains.Relay = "api.test", "shares.test", "r.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Admin.Enabled = true
	if tune != nil {
		tune(&cfg)
	}
	opts.Now = func() time.Time { return e.now }
	srv, err := New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	e.srv, e.handler = srv, srv.Handler()
	return e
}

type reply struct {
	*httptest.ResponseRecorder
}

func (r reply) cookie() *http.Cookie {
	for _, c := range r.Result().Cookies() {
		if c.Name == "ostia_admin" {
			return c
		}
	}
	return nil
}

func (e *adminEnv) send(method, host, path string, form url.Values, cookie *http.Cookie) reply {
	e.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.Host = host
	e.ip++
	req.RemoteAddr = fmt.Sprintf("192.0.2.%d:4000", 1+e.ip%250)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return reply{rec}
}

func (e *adminEnv) from(ip, method, path string, form url.Values) reply {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Host = "api.test"
	req.RemoteAddr = ip + ":4000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return reply{rec}
}

func (e *adminEnv) get(path string, cookie *http.Cookie) reply {
	return e.send("GET", "api.test", path, nil, cookie)
}

func (e *adminEnv) post(path string, form url.Values, cookie *http.Cookie) reply {
	return e.send("POST", "api.test", path, form, cookie)
}

func (e *adminEnv) code() string {
	e.t.Helper()
	code, err := adminui.IssueCode(e.t.Context(), e.srv.DB)
	if err != nil {
		e.t.Fatal(err)
	}
	return code
}

type signedIn struct {
	cookie *http.Cookie
	csrf   string
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (e *adminEnv) signIn() signedIn {
	e.t.Helper()
	res := e.post("/admin/login", url.Values{"code": {e.code()}}, nil)
	if res.Code != http.StatusSeeOther || res.cookie() == nil {
		e.t.Fatalf("sign-in failed: %d %s", res.Code, res.Body)
	}
	cookie := res.cookie()
	page := e.get("/admin/invites", cookie)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		e.t.Fatalf("no csrf token on the invites page: %s", page.Body)
	}
	return signedIn{cookie: cookie, csrf: m[1]}
}

func (e *adminEnv) act(s signedIn, path string, form url.Values) reply {
	e.t.Helper()
	form.Set("csrf", s.csrf)
	return e.post(path, form, s.cookie)
}

func (e *adminEnv) account(name string) (store.Account, store.Device) {
	e.t.Helper()
	acct, dev, err := e.srv.DB.RegisterProvider(e.t.Context(), "github", ids.New(), store.NewDevice{Name: name, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		e.t.Fatal(err)
	}
	return acct, dev
}

func (e *adminEnv) putBlob(accountID, blobID string, size int) string {
	e.t.Helper()
	key := store.SyncBlobKey(accountID, blobID)
	up, err := e.srv.Blobs.Put(e.t.Context(), key, strings.NewReader(strings.Repeat("x", size)), int64(size))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := up.Commit(); err != nil {
		e.t.Fatal(err)
	}
	sum := up.Sum()
	if err := e.srv.DB.AddSyncBlob(e.t.Context(), accountID, store.SyncBlob{ID: blobID, Size: int64(size), Sum: sum[:]}, 0); err != nil {
		e.t.Fatal(err)
	}
	return key
}

func (e *adminEnv) blobExists(key string) bool {
	rc, _, err := e.srv.Blobs.Open(e.t.Context(), key)
	if err != nil {
		return false
	}
	_ = rc.Close()
	return true
}

func TestAdminRoutesAreOffUnlessEnabled(t *testing.T) {
	e := newAdminEnv(t, func(c *config.Config) { c.Admin.Enabled = false }, Options{})
	for _, path := range []string{"/admin", "/admin/", "/admin/invites", "/admin/accounts", "/admin/assets/admin.css"} {
		if res := e.get(path, nil); res.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d with admin.enabled off", path, res.Code)
		}
	}
	if res := e.post("/admin/login", url.Values{"code": {"x"}}, nil); res.Code != http.StatusNotFound && res.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /admin/login answered %d with admin.enabled off", res.Code)
	}
}

func TestAdminIsNeverServedOnTheShareDomain(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	for _, host := range []string{"abcdefghijklmnopqrstuvwxyz.shares.test", "shares.test", "r.test", "other.test"} {
		for _, path := range []string{"/admin/", "/admin/invites", "/admin/accounts"} {
			res := e.send("GET", host, path, nil, s.cookie)
			if res.Code == http.StatusOK || strings.Contains(res.Body.String(), "Ostia server") {
				t.Errorf("GET %s%s answered %d: the admin UI must live on the API host only", host, path, res.Code)
			}
		}
	}
}

func TestUnauthenticatedAdminRoutesAreRefused(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	acct, _ := e.account("laptop")
	for _, path := range []string{"/admin/invites", "/admin/accounts", "/admin/accounts/" + acct.ID, "/admin/accounts/" + acct.ID + "/delete"} {
		res := e.get(path, nil)
		if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/" {
			t.Errorf("GET %s answered %d %q without a session", path, res.Code, res.Header().Get("Location"))
		}
		if strings.Contains(res.Body.String(), acct.ID) {
			t.Errorf("GET %s leaked account data without a session", path)
		}
	}
	for _, path := range []string{"/admin/logout", "/admin/invites", "/admin/invites/revoke", "/admin/accounts/" + acct.ID + "/delete"} {
		res := e.post(path, url.Values{"ttl": {"1h"}, "id": {strings.Repeat("0", 64)}}, nil)
		if res.Code != http.StatusUnauthorized {
			t.Errorf("POST %s answered %d without a session", path, res.Code)
		}
	}
	if _, err := e.srv.DB.Account(t.Context(), acct.ID); err != nil {
		t.Fatalf("an unauthenticated delete removed the account: %v", err)
	}
	forged := &http.Cookie{Name: "ostia_admin", Value: ids.Token()}
	if res := e.get("/admin/accounts", forged); res.Code != http.StatusSeeOther {
		t.Errorf("a made-up session cookie answered %d", res.Code)
	}
}

func TestSignInPageIsServedWithoutASession(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	res := e.get("/admin/", nil)
	body := res.Body.String()
	if res.Code != http.StatusOK || !strings.Contains(body, "Ostia server · admin") || !strings.Contains(body, "api.test") {
		t.Fatalf("%d %s", res.Code, body)
	}
	if strings.Contains(body, "Sign in with GitHub") {
		t.Fatal("the GitHub button must be hidden while GitHub sign-in is off")
	}
	if res := e.get("/admin", nil); res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/" {
		t.Fatalf("/admin must lead to /admin/: %d", res.Code)
	}
}

func TestLoginCodeWorksOnceAndSetsAStrictCookie(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.code()
	res := e.post("/admin/login", url.Values{"code": {strings.ToLower(code)}}, nil)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/invites" {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	c := res.cookie()
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/admin" || c.MaxAge != int(adminui.SessionTTL/time.Second) {
		t.Fatalf("cookie %+v", c)
	}
	if res := e.get("/admin/invites", c); res.Code != http.StatusOK {
		t.Fatalf("the new session must work: %d", res.Code)
	}
	again := e.post("/admin/login", url.Values{"code": {code}}, nil)
	if again.Code != http.StatusUnauthorized || again.cookie() != nil {
		t.Fatalf("a used code signed in again: %d", again.Code)
	}
	if strings.Contains(again.Body.String(), code) {
		t.Fatal("the refusal page must not echo the code")
	}
}

func TestLoginCodeExpiresAndUnknownCodesAreRefused(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.code()
	e.now = e.now.Add(adminui.CodeTTL + time.Second)
	if res := e.post("/admin/login", url.Values{"code": {code}}, nil); res.Code != http.StatusUnauthorized || res.cookie() != nil {
		t.Fatalf("an expired code signed in: %d", res.Code)
	}
	for _, guess := range []string{"", "AAAAA-BBBBB-CCCCC-DDDDD", "' OR 1=1 --"} {
		if res := e.post("/admin/login", url.Values{"code": {guess}}, nil); res.Code != http.StatusUnauthorized || res.cookie() != nil {
			t.Errorf("code %q answered %d", guess, res.Code)
		}
	}
}

func TestLoginCodeIsHashedAtRest(t *testing.T) {
	d, err := store.Open(t.TempDir()+"/db.sqlite", config.Default().Storage.SQLiteJournal, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	code, err := adminui.IssueCode(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ConsumeAdminCode(t.Context(), []byte(code)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the plain code must not be what is stored: %v", err)
	}
	hint, err := d.ConsumeAdminCode(t.Context(), ids.Hash(auth.NormalizeCode(code)))
	if err != nil || hint != strings.ToUpper(auth.NormalizeCode(code)[:4]) {
		t.Fatalf("%q %v", hint, err)
	}
}

func TestLoginIsRateLimitedPerAddressAndOverall(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.code()
	limited := false
	for range 20 {
		res := e.from("198.51.100.7", "POST", "/admin/login", url.Values{"code": {"WRONG-WRONG-WRONG"}})
		if res.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("repeated bad codes from one address were never limited")
	}
	if res := e.from("198.51.100.7", "POST", "/admin/login", url.Values{"code": {code}}); res.Code != http.StatusTooManyRequests {
		t.Fatalf("a limited address must be refused even with a valid code: %d", res.Code)
	}
	if res := e.from("198.51.100.8", "POST", "/admin/login", url.Values{"code": {code}}); res.Code != http.StatusSeeOther {
		t.Fatalf("another address must not be affected: %d", res.Code)
	}

	e = newAdminEnv(t, nil, Options{})
	refused := 0
	for i := range 200 {
		res := e.from(fmt.Sprintf("203.0.113.%d", i+1), "POST", "/admin/login", url.Values{"code": {"WRONG"}})
		if res.Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("a spread-out guessing run was never limited overall")
	}
	res := e.from("203.0.113.250", "POST", "/admin/login", url.Values{"code": {"WRONG"}})
	if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After must match the refill of the overall limit: %d %q", res.Code, res.Header().Get("Retry-After"))
	}
	if res := e.from("203.0.113.251", "POST", "/admin/login", url.Values{"code": {e.code()}}); res.Code != http.StatusSeeOther || res.cookie() == nil {
		t.Fatalf("a valid code must get in while the overall limit is exhausted: %d", res.Code)
	}
}

func TestValidLoginsDoNotSpendTheOverallLimit(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	for i := range 100 {
		if res := e.from(fmt.Sprintf("203.0.114.%d", i+1), "POST", "/admin/login", url.Values{"code": {e.code()}}); res.Code != http.StatusSeeOther {
			t.Fatalf("sign-in %d answered %d", i, res.Code)
		}
	}
}

func TestFailedLoginsAreLoggedWithoutTheCode(t *testing.T) {
	var log strings.Builder
	restore := captureLog(&log)
	defer restore()
	e := newAdminEnv(t, nil, Options{})
	e.post("/admin/login", url.Values{"code": {"SECRET-GUESS-VALUE-XYZ"}}, nil)
	out := log.String()
	if !strings.Contains(out, "admin sign-in refused") {
		t.Fatalf("a failed attempt must be logged: %q", out)
	}
	if strings.Contains(strings.ToLower(out), "secret-guess") {
		t.Fatalf("the log contains the code: %q", out)
	}
}

func TestStateChangingRoutesNeedTheCSRFToken(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	other := e.signIn()
	acct, _ := e.account("laptop")
	code, _, err := e.srv.Auth.CreateInvite(t.Context(), "", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	open, _, _ := e.srv.DB.AdminInvites(t.Context())
	if len(open) != 1 {
		t.Fatalf("%d open invites after minting %s", len(open), code)
	}
	routes := map[string]url.Values{
		"/admin/invites":                         {"ttl": {"1h"}},
		"/admin/invites/revoke":                  {"id": {open[0].ID}},
		"/admin/accounts/" + acct.ID + "/delete": {},
		"/admin/logout":                          {},
	}
	for path, form := range routes {
		for name, token := range map[string]string{"missing": "", "wrong": strings.Repeat("0", 64), "another session's": other.csrf} {
			f := url.Values{}
			for k, v := range form {
				f[k] = v
			}
			if token != "" {
				f.Set("csrf", token)
			}
			if res := e.post(path, f, s.cookie); res.Code != http.StatusForbidden {
				t.Errorf("POST %s with a %s token answered %d", path, name, res.Code)
			}
		}
	}
	if after, _, _ := e.srv.DB.AdminInvites(t.Context()); len(after) != 1 {
		t.Fatal("a request without a valid token changed the invites")
	}
	if _, err := e.srv.DB.Account(t.Context(), acct.ID); err != nil {
		t.Fatalf("a request without a valid token deleted the account: %v", err)
	}
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusOK {
		t.Fatalf("a refused logout must not end the session: %d", res.Code)
	}
}

func TestResponsesCarryStrictHeadersAndNoCORS(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	for _, path := range []string{"/admin/", "/admin/invites", "/admin/accounts", "/admin/assets/admin.css", "/admin/assets/admin.js"} {
		res := e.get(path, s.cookie)
		h := res.Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s CSP %q", path, csp)
		}
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s headers %v", path, h)
		}
		for name := range h {
			if strings.HasPrefix(name, "Access-Control-") {
				t.Errorf("%s sets %s", path, name)
			}
		}
	}
	for _, path := range []string{"/admin/invites", "/admin/accounts"} {
		body := e.get(path, s.cookie).Body.String()
		inlineScript := false
		for _, tag := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(body, -1) {
			inlineScript = inlineScript || !strings.Contains(tag, " src=")
		}
		if inlineScript || regexp.MustCompile(`(?i)\son\w+=`).MatchString(body) || strings.Contains(body, "style=") {
			t.Errorf("%s has inline script or style", path)
		}
	}
	req := httptest.NewRequest("OPTIONS", "/admin/invites", nil)
	req.Host = "api.test"
	req.Header.Set("Origin", "https://evil.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("a preflight answered %d %v", rec.Code, rec.Header())
	}
	if res := e.get("/admin/assets/base.html", s.cookie); res.Code != http.StatusNotFound {
		t.Fatalf("only the stylesheet and script are served as assets: %d", res.Code)
	}
}

func TestSessionEndsAfterEightHoursAndOnSignOut(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	e.now = e.now.Add(adminui.SessionTTL - time.Minute)
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusOK {
		t.Fatalf("%d", res.Code)
	}
	e.now = e.now.Add(2 * time.Minute)
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("an expired session answered %d", res.Code)
	}

	s = e.signIn()
	out := e.act(s, "/admin/logout", url.Values{})
	if out.Code != http.StatusSeeOther || out.cookie() == nil || out.cookie().MaxAge >= 0 {
		t.Fatalf("sign-out must clear the cookie: %d %+v", out.Code, out.cookie())
	}
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("a signed-out session still works: %d", res.Code)
	}
}

func TestInvitesCanBeCreatedListedAndRevoked(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	res := e.act(s, "/admin/invites", url.Values{"ttl": {"7d"}})
	if res.Code != http.StatusOK {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	shown := regexp.MustCompile(`class="mono bigcode">([A-Z0-9-]+)<`).FindStringSubmatch(res.Body.String())
	if shown == nil || !strings.Contains(res.Body.String(), "shown once") {
		t.Fatalf("the new code must be shown once: %s", res.Body)
	}
	code := shown[1]
	list := e.get("/admin/invites", s.cookie).Body.String()
	if strings.Contains(list, code) || strings.Contains(list, "shown once") {
		t.Fatal("the full code must not be shown again")
	}
	hint := code[:4] + "-…-" + code[len(code)-4:]
	if !strings.Contains(list, hint) || !strings.Contains(list, "expires in 7 days") {
		t.Fatalf("the open list must show the code's hint and expiry: %s", list)
	}
	if _, _, err := e.srv.DB.RegisterWithInvite(t.Context(), ids.Hash(auth.NormalizeCode(code)), store.NewDevice{Name: "laptop", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10); err != nil {
		t.Fatalf("the code must work as a normal invite: %v", err)
	}

	e.act(s, "/admin/invites", url.Values{"ttl": {"1h"}})
	open, used, err := e.srv.DB.AdminInvites(t.Context())
	if err != nil || len(open) != 1 || len(used) != 1 {
		t.Fatalf("open %d used %d %v", len(open), len(used), err)
	}
	usedPage := e.get("/admin/invites", s.cookie).Body.String()
	if !strings.Contains(usedPage, "by account") || !strings.Contains(usedPage, used[0].CreatedAccount[:4]) {
		t.Fatalf("a used code must name the account it created: %s", usedPage)
	}
	if res := e.act(s, "/admin/invites/revoke", url.Values{"id": {open[0].ID}}); res.Code != http.StatusSeeOther {
		t.Fatalf("%d", res.Code)
	}
	if open, _, _ = e.srv.DB.AdminInvites(t.Context()); len(open) != 0 {
		t.Fatal("the revoked code is still open")
	}
	if res := e.act(s, "/admin/invites/revoke", url.Values{"id": {used[0].ID}}); res.Code != http.StatusNotFound {
		t.Fatalf("a used code cannot be revoked: %d", res.Code)
	}
	if res := e.act(s, "/admin/invites/revoke", url.Values{"id": {"nonsense"}}); res.Code != http.StatusBadRequest {
		t.Fatalf("%d", res.Code)
	}
	if res := e.act(s, "/admin/invites", url.Values{"ttl": {"9999d"}}); res.Code != http.StatusBadRequest {
		t.Fatalf("an unknown expiry answered %d", res.Code)
	}
}

func TestRevokedInviteCannotRegisterAnymore(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	res := e.act(s, "/admin/invites", url.Values{"ttl": {"1d"}})
	code := regexp.MustCompile(`class="mono bigcode">([A-Z0-9-]+)<`).FindStringSubmatch(res.Body.String())[1]
	open, _, _ := e.srv.DB.AdminInvites(t.Context())
	e.act(s, "/admin/invites/revoke", url.Values{"id": {open[0].ID}})
	_, _, err := e.srv.DB.RegisterWithInvite(t.Context(), ids.Hash(auth.NormalizeCode(code)), store.NewDevice{Name: "x", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a revoked code registered an account: %v", err)
	}
}

func TestAccountPagesShowMetadataOnly(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	a, _ := e.account("calm-otter")
	b, _ := e.account("brisk-heron")
	e.putBlob(a.ID, "blob-aaaaaaaaaaaaaaaaaaaa", 38_000_000/1000)
	if _, err := e.srv.DB.AddDevice(t.Context(), a.ID, store.NewDevice{Name: "quiet-maple (phone)", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10); err != nil {
		t.Fatal(err)
	}
	list := e.get("/admin/accounts", s.cookie).Body.String()
	for _, want := range []string{"2 accounts", "2 devices", "1 device", a.ID[:4] + "…" + a.ID[len(a.ID)-4:], "Select an account."} {
		if !strings.Contains(list, want) {
			t.Errorf("the list lacks %q: %s", want, list)
		}
	}
	detail := e.get("/admin/accounts/"+a.ID, s.cookie).Body.String()
	for _, want := range []string{"calm-otter", "quiet-maple (phone)", "38 KB", "Delete account…", "/admin/accounts/" + a.ID + "/delete"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the detail lacks %q: %s", want, detail)
		}
	}
	if strings.Contains(detail, "brisk-heron") {
		t.Error("the detail shows another account's device")
	}
	confirm := e.get("/admin/accounts/"+b.ID+"/delete", s.cookie).Body.String()
	if !strings.Contains(confirm, "cannot be undone") || !strings.Contains(confirm, `action="/admin/accounts/`+b.ID+`/delete"`) {
		t.Fatalf("the confirm step must name the account: %s", confirm)
	}
	for _, path := range []string{"/admin/accounts/" + ids.New(), "/admin/accounts/not-an-id", "/admin/accounts/" + ids.New() + "/delete"} {
		if res := e.get(path, s.cookie); res.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d", path, res.Code)
		}
	}
	if res := e.act(s, "/admin/accounts/"+ids.New()+"/delete", url.Values{}); res.Code != http.StatusNotFound {
		t.Errorf("deleting an unknown account answered %d", res.Code)
	}
}

func TestDeletingAnAccountRemovesEverythingItStored(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	a, dev := e.account("laptop")
	keep, keepDev := e.account("other")
	second, err := e.srv.DB.AddDevice(t.Context(), a.ID, store.NewDevice{Name: "phone", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	blobKey := e.putBlob(a.ID, "blob-aaaaaaaaaaaaaaaaaaaa", 10)
	keepKey := e.putBlob(keep.ID, "blob-bbbbbbbbbbbbbbbbbbbb", 10)
	if err := e.srv.DB.PutWrap(t.Context(), a.ID, "passphrase", []byte("wrap")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.DB.CreateSession(t.Context(), ids.Hash("tok"), dev.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.DB.CreateSession(t.Context(), ids.Hash("tok2"), second.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.DB.CreateSession(t.Context(), ids.Hash("keep"), keepDev.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.DB.CreatePushTicket(t.Context(), ids.Hash("ticket"), a.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.DB.RegisterPushHandle(t.Context(), ids.Hash("ticket"), store.PushHandle{Handle: "h-aaaaaaaa", Platform: "fcm", TokenSealed: []byte("t")}, 5, 0); err != nil {
		t.Fatal(err)
	}
	shareID := ids.New()
	if err := e.srv.DB.CreateShare(t.Context(), store.Share{ID: shareID, AccountID: a.ID, Mode: "link", Size: 5, ExpiresAt: e.now.Add(time.Hour).UnixMilli(), DeleteTokenHash: ids.Hash("d")}, store.ShareQuota{}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.DB.MarkUploaded(t.Context(), shareID); err != nil {
		t.Fatal(err)
	}
	up, err := e.srv.Blobs.Put(t.Context(), store.ShareBlobKey(shareID), strings.NewReader("hello"), 5)
	if err != nil {
		t.Fatal(err)
	}
	_ = up.Commit()

	res := e.act(s, "/admin/accounts/"+a.ID+"/delete", url.Values{})
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/accounts" {
		t.Fatalf("%d %s", res.Code, res.Body)
	}

	ctx := t.Context()
	if _, err := e.srv.DB.Account(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the account survived: %v", err)
	}
	if devs, _ := e.srv.DB.DevicesOf(ctx, a.ID); len(devs) != 0 {
		t.Errorf("devices survived: %v", devs)
	}
	for _, tok := range []string{"tok", "tok2"} {
		if _, err := e.srv.DB.SessionDevice(ctx, ids.Hash(tok)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session %s survived: %v", tok, err)
		}
	}
	if wraps, _ := e.srv.DB.Wraps(ctx, a.ID); len(wraps) != 0 {
		t.Errorf("wraps survived: %v", wraps)
	}
	if _, err := e.srv.DB.PushHandle(ctx, "h-aaaaaaaa"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the push handle survived: %v", err)
	}
	if _, err := e.srv.DB.Share(ctx, shareID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the share survived: %v", err)
	}
	if n, _, _ := e.srv.DB.SyncUsage(ctx, a.ID); n != 0 {
		t.Errorf("sync blob rows survived: %d", n)
	}
	if e.blobExists(blobKey) || e.blobExists(store.ShareBlobKey(shareID)) {
		t.Error("blob files survived")
	}
	if _, err := e.srv.DB.Account(ctx, keep.ID); err != nil || !e.blobExists(keepKey) {
		t.Error("another account lost data")
	}
	if _, err := e.srv.DB.SessionDevice(ctx, ids.Hash("keep")); err != nil {
		t.Errorf("another account's session was removed: %v", err)
	}
	if e.get("/admin/accounts/"+a.ID, s.cookie).Code != http.StatusNotFound {
		t.Error("the deleted account's page still renders")
	}
}

func TestEveryAdminActionIsAudited(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	a, _ := e.account("laptop")
	code := e.code()
	hint := strings.ToUpper(auth.NormalizeCode(code)[:4])
	res := e.post("/admin/login", url.Values{"code": {code}}, nil)
	page := e.get("/admin/invites", res.cookie())
	s := signedIn{cookie: res.cookie(), csrf: csrfField.FindStringSubmatch(page.Body.String())[1]}
	e.act(s, "/admin/invites", url.Values{"ttl": {"1h"}})
	open, _, _ := e.srv.DB.AdminInvites(t.Context())
	e.act(s, "/admin/invites/revoke", url.Values{"id": {open[0].ID}})
	e.act(s, "/admin/accounts/"+a.ID+"/delete", url.Values{})
	e.act(s, "/admin/logout", url.Values{})

	entries, err := e.srv.DB.Audit(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(entries) - 1; i >= 0; i-- {
		got = append(got, entries[i].Admin+" "+entries[i].Action+" "+entries[i].Target)
		if entries[i].At != e.now.UnixMilli() {
			t.Errorf("entry %+v lacks the time", entries[i])
		}
	}
	who := "code:" + hint
	want := []string{
		"cli login-code " + hint,
		who + " login ",
		who + " invite.create " + open[0].Hint,
		who + " invite.revoke " + open[0].Hint,
		who + " account.delete " + a.ID,
		who + " logout ",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit\n got %q\nwant %q", got, want)
	}
}

func TestLogoutAllEndsEverySessionAndIsAudited(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	one, two := e.signIn(), e.signIn()
	admin, err := OpenAdmin(e.srv.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := admin.LogoutAll(t.Context())
	_ = admin.Close()
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	for _, s := range []signedIn{one, two} {
		if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
			t.Fatalf("a session survived logout-all: %d", res.Code)
		}
	}
	entries, _ := e.srv.DB.Audit(t.Context(), 1)
	if len(entries) != 1 || entries[0].Action != "logout-all" || entries[0].Admin != "cli" || entries[0].Target != "2" {
		t.Fatalf("%+v", entries)
	}
}

func TestAdminSessionsEndWhenTheServerRestarts(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	restarted, err := New(e.srv.Cfg, Options{Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.DB.Close() })
	e.handler = restarted.Handler()
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("a session survived a restart: %d", res.Code)
	}
}

func TestOnlyASessionCookieThatMatchesALiveSessionCounts(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	planted := &http.Cookie{Name: "ostia_admin", Value: "planted"}
	for name, order := range map[string][]*http.Cookie{"planted first": {planted, s.cookie}, "planted last": {s.cookie, planted}} {
		req := httptest.NewRequest("GET", "/admin/invites", nil)
		req.Host = "api.test"
		for _, c := range order {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: a planted cookie signed the admin out: %d", name, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/admin/invites", nil)
	req.Host = "api.test"
	req.AddCookie(planted)
	req.AddCookie(&http.Cookie{Name: "ostia_admin", Value: "another"})
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("two cookies without a live session answered %d", rec.Code)
	}
}

func TestAdminDoesNotChangeTheClientRoutes(t *testing.T) {
	on := newAdminEnv(t, nil, Options{})
	off := newAdminEnv(t, func(c *config.Config) { c.Admin.Enabled = false }, Options{})
	if strings.Join(on.srv.Routes(), "|") != strings.Join(off.srv.Routes(), "|") {
		t.Fatal("the admin routes must not appear among the documented API routes")
	}
}

func TestInviteLifetimesStayWithinAuthInviteTTL(t *testing.T) {
	e := newAdminEnv(t, func(c *config.Config) { c.Auth.InviteTTL = config.Duration(36 * time.Hour) }, Options{})
	s := e.signIn()
	page := e.get("/admin/invites", s.cookie).Body.String()
	if strings.Contains(page, `value="7d"`) || !strings.Contains(page, `value="1d"`) || !strings.Contains(page, `value="1h"`) {
		t.Fatalf("only lifetimes within auth.invite_ttl may be offered: %s", page)
	}
	if res := e.act(s, "/admin/invites", url.Values{"ttl": {"7d"}}); res.Code != http.StatusBadRequest {
		t.Fatalf("a lifetime above auth.invite_ttl answered %d", res.Code)
	}
	if res := e.act(s, "/admin/invites", url.Values{"ttl": {"1d"}}); res.Code != http.StatusOK {
		t.Fatalf("%d", res.Code)
	}

	e = newAdminEnv(t, func(c *config.Config) { c.Auth.InviteTTL = config.Duration(30 * time.Minute) }, Options{})
	s = e.signIn()
	if res := e.act(s, "/admin/invites", url.Values{"ttl": {"max"}}); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "shown once") {
		t.Fatalf("a short auth.invite_ttl must still allow an invite: %d", res.Code)
	}
}
