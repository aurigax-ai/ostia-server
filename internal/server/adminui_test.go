package server

import (
	"errors"
	"fmt"
	"html"
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
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

const (
	oauthCookieName = "__Host-ostia_admin_oauth"
	adminGitHubID   = 1000
	adminLogin      = "octocat"
)

type adminEnv struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	now     time.Time
	ip      int
	gh      *testkit.FakeGitHub
}

func newAdminEnv(t *testing.T, tune func(*config.Config), opts Options) *adminEnv {
	t.Helper()
	e := &adminEnv{t: t, now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), gh: testkit.NewFakeGitHub(t, 0)}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API, cfg.Domains.Share, cfg.Domains.Relay = "api.test", "shares.test", "r.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Domains.Port = 443
	cfg.Admin.Enabled = true
	cfg.Admin.GitHubClientID, cfg.Admin.GitHubClientSecret = testkit.WebClientID, testkit.WebClientSecret
	cfg.Auth.GitHubBaseURL, cfg.Auth.GitHubAPIURL = e.gh.Server.URL, e.gh.Server.URL
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

func (r reply) named(name string) *http.Cookie {
	for _, c := range r.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (r reply) cookie() *http.Cookie {
	return r.named("ostia_admin")
}

var nextLink = regexp.MustCompile(`<a class="btn" href="([^"]+)">Continue</a>`)

func (r reply) next() string {
	if m := nextLink.FindStringSubmatch(r.Body.String()); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
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

func (e *adminEnv) isAdmin(id int64, login string) bool {
	e.t.Helper()
	err := e.srv.DB.SignInAdmin(e.t.Context(), id, login, ids.Hash(ids.Token()), time.Hour)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		e.t.Fatal(err)
	}
	return err == nil
}

func (e *adminEnv) setupCode() string {
	e.t.Helper()
	code, err := adminui.IssueSetupCode(e.t.Context(), e.srv.DB)
	if err != nil {
		e.t.Fatal(err)
	}
	return code
}

type flow struct {
	cookie       *http.Cookie
	authorizeURL string
	state        string
}

func (e *adminEnv) begin(code string) flow {
	e.t.Helper()
	res := e.post("/admin/github/start", url.Values{"code": {code}}, nil)
	cookie, next := res.named(oauthCookieName), res.next()
	if res.Code != http.StatusOK || cookie == nil || next == "" {
		e.t.Fatalf("start failed: %d %s", res.Code, res.Body)
	}
	u, err := url.Parse(next)
	if err != nil {
		e.t.Fatal(err)
	}
	return flow{cookie: cookie, authorizeURL: next, state: u.Query().Get("state")}
}

func (e *adminEnv) authorize(f flow, id int64, login string) string {
	e.t.Helper()
	u, err := url.Parse(e.gh.Authorize(e.t, f.authorizeURL, id, login))
	if err != nil {
		e.t.Fatal(err)
	}
	return u.RequestURI()
}

func (e *adminEnv) land(callback string, cookie *http.Cookie) reply {
	e.t.Helper()
	hop := e.get(callback, nil)
	if next := hop.next(); hop.Code == http.StatusOK && next != "" {
		return e.get(next, cookie)
	}
	return hop
}

func (e *adminEnv) complete(f flow, id int64, login string) reply {
	e.t.Helper()
	return e.land(e.authorize(f, id, login), f.cookie)
}

type signedIn struct {
	cookie *http.Cookie
	csrf   string
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (e *adminEnv) signIn() signedIn {
	e.t.Helper()
	code := ""
	if has, err := e.srv.DB.HasAdmin(e.t.Context()); err != nil {
		e.t.Fatal(err)
	} else if !has {
		code = e.setupCode()
	}
	res := e.complete(e.begin(code), adminGitHubID, adminLogin)
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
	for _, path := range []string{"/admin", "/admin/", "/admin/invites", "/admin/accounts", "/admin/assets/admin.css", "/admin/github/callback?code=x&state=y", "/admin/github/finish?code=x&state=y"} {
		if res := e.get(path, nil); res.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d with admin.enabled off", path, res.Code)
		}
	}
	if res := e.post("/admin/github/start", url.Values{"code": {"x"}}, nil); res.Code != http.StatusNotFound && res.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /admin/github/start answered %d with admin.enabled off", res.Code)
	}
}

func TestAdminIsNeverServedOnTheShareDomain(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	for _, host := range []string{"abcdefghijklmnopqrstuvwxyz.shares.test", "shares.test", "r.test", "other.test"} {
		for _, path := range []string{"/admin/", "/admin/invites", "/admin/accounts", "/admin/github/callback?code=x&state=y"} {
			res := e.send("GET", host, path, nil, s.cookie)
			if res.Code == http.StatusOK || strings.Contains(res.Body.String(), "Ostia server") {
				t.Errorf("GET %s%s answered %d: the admin UI must live on the API host only", host, path, res.Code)
			}
		}
		if res := e.send("POST", host, "/admin/github/start", url.Values{}, nil); res.Code == http.StatusOK {
			t.Errorf("POST %s/admin/github/start answered %d", host, res.Code)
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
	f := e.begin(e.setupCode())
	if res := e.get("/admin/invites", f.cookie); res.Code != http.StatusSeeOther {
		t.Errorf("the sign-in state cookie opened a page: %d", res.Code)
	}
}

func TestSetupPageAsksForTheCodeAndSignInPageOnlyForGitHub(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	setup := e.get("/admin/", nil)
	body := setup.Body.String()
	if setup.Code != http.StatusOK || !strings.Contains(body, "Set up admin") || !strings.Contains(body, `name="code"`) || !strings.Contains(body, "Continue with GitHub") || !strings.Contains(body, "api.test") || !strings.Contains(body, `action="/admin/github/start"`) {
		t.Fatalf("%d %s", setup.Code, body)
	}
	e.signIn()
	signIn := e.get("/admin/", nil).Body.String()
	if !strings.Contains(signIn, "Sign in with GitHub") || strings.Contains(signIn, `name="code"`) || strings.Contains(signIn, "Set up admin") || !strings.Contains(signIn, `action="/admin/github/start"`) {
		t.Fatalf("with an admin the page offers GitHub only: %s", signIn)
	}
	for _, page := range []string{body, signIn} {
		for _, banned := range []string{"kubectl", "ostia-server admin", "one-time code", "/admin/login"} {
			if strings.Contains(page, banned) {
				t.Errorf("the page mentions %q", banned)
			}
		}
	}
	if res := e.get("/admin", nil); res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/" {
		t.Fatalf("/admin must lead to /admin/: %d", res.Code)
	}
}

func TestThereIsNoCodeSignIn(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.setupCode()
	for _, method := range []string{"POST", "GET"} {
		res := e.send(method, "api.test", "/admin/login", url.Values{"code": {code}}, nil)
		if res.Code != http.StatusNotFound && res.Code != http.StatusMethodNotAllowed || res.cookie() != nil {
			t.Errorf("%s /admin/login answered %d", method, res.Code)
		}
	}
	if has, _ := e.srv.DB.HasAdmin(t.Context()); has {
		t.Fatal("a code alone created an admin")
	}
}

func TestSetupWithTheCodeMakesTheGitHubUserTheAdminAndSpendsTheCode(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.setupCode()
	f := e.begin(strings.ToLower(code))
	c := f.cookie
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 {
		t.Fatalf("state cookie %+v", c)
	}
	u, err := url.Parse(f.authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != strings.TrimPrefix(e.gh.Server.URL, "http://") || u.Path != "/login/oauth/authorize" || q.Get("client_id") != testkit.WebClientID ||
		q.Get("redirect_uri") != "https://api.test/admin/github/callback" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 ||
		q.Get("state") != f.state || c.Value != f.state || q.Get("client_secret") != "" || strings.Contains(f.authorizeURL, testkit.WebClientSecret) {
		t.Fatalf("authorize request %s", f.authorizeURL)
	}
	res := e.complete(f, 4242, "octocat")
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/invites" {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	session := res.cookie()
	if session == nil || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode || session.Path != "/admin" || session.MaxAge != int(adminui.SessionTTL/time.Second) {
		t.Fatalf("session cookie %+v", session)
	}
	if cleared := res.named(oauthCookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("the state cookie must be cleared: %+v", cleared)
	}
	if page := e.get("/admin/invites", session); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "<span>octocat ·</span>") {
		t.Fatalf("the new session must work: %d", page.Code)
	}
	if !e.isAdmin(4242, "octocat") {
		t.Fatal("the GitHub id was not stored as an admin")
	}
	if e.isAdmin(4243, "octocat") {
		t.Fatal("a login match must not make an admin")
	}
	if len(e.gh.Revoked) != 1 {
		t.Fatalf("the GitHub access token must be revoked after /user: %v", e.gh.Revoked)
	}
	if err := e.srv.DB.SetupCodeValid(t.Context(), ids.Hash(auth.NormalizeCode(code))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the code survived the setup: %v", err)
	}
	if e.gh.Polls != 0 {
		t.Fatal("the admin sign-in must use the web redirect flow, never the device flow")
	}
	if page := e.get("/admin/", nil).Body.String(); strings.Contains(page, "Set up admin") {
		t.Fatalf("setup is still offered: %s", page)
	}
}

func TestSetupRefusesAWrongUsedOrExpiredCode(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	good := e.setupCode()
	for name, guess := range map[string]string{"empty": "", "unknown": "AAAAA-BBBBB-CCCCC-DDDDD", "injection": "' OR 1=1 --"} {
		res := e.post("/admin/github/start", url.Values{"code": {guess}}, nil)
		if res.Code != http.StatusUnauthorized || res.named(oauthCookieName) != nil || res.Header().Get("Location") != "" || !strings.Contains(res.Body.String(), "Set up admin") {
			t.Errorf("%s code answered %d", name, res.Code)
		}
		if strings.Contains(res.Body.String(), "OR 1=1") {
			t.Errorf("%s: the refusal page echoes the code", name)
		}
	}

	if res := e.complete(e.begin(good), 1, "first"); res.Code != http.StatusSeeOther {
		t.Fatalf("%d", res.Code)
	}
	if _, _, err := e.srv.DB.ResetAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if res := e.post("/admin/github/start", url.Values{"code": {good}}, nil); res.Code != http.StatusUnauthorized || res.named(oauthCookieName) != nil {
		t.Fatalf("a used code started a setup: %d", res.Code)
	}

	late := e.setupCode()
	e.now = e.now.Add(adminui.CodeTTL + time.Second)
	if res := e.post("/admin/github/start", url.Values{"code": {late}}, nil); res.Code != http.StatusUnauthorized || res.named(oauthCookieName) != nil {
		t.Fatalf("an expired code started a setup: %d", res.Code)
	}
	if has, _ := e.srv.DB.HasAdmin(t.Context()); has {
		t.Fatal("a refused setup left an admin behind")
	}
}

func TestSetupCodeThatExpiresBeforeTheCallbackIsRefused(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.setupCode()
	e.now = e.now.Add(9 * time.Minute)
	f := e.begin(code)
	e.now = e.now.Add(2 * time.Minute)
	res := e.complete(f, 4242, "octocat")
	if res.Code != http.StatusUnauthorized || res.cookie() != nil || !strings.Contains(res.Body.String(), "unknown, used or expired") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if has, _ := e.srv.DB.HasAdmin(t.Context()); has {
		t.Fatal("an expired code made an admin")
	}
}

func TestSetupIsRefusedOnceAnAdminExists(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.setupCode()
	first, second := e.begin(code), e.begin(code)
	if res := e.complete(first, 1, "first"); res.Code != http.StatusSeeOther {
		t.Fatalf("%d", res.Code)
	}
	res := e.complete(second, 2, "second")
	if res.Code != http.StatusConflict || res.cookie() != nil || !strings.Contains(res.Body.String(), "already set up") {
		t.Fatalf("a second setup answered %d %s", res.Code, res.Body)
	}
	if e.isAdmin(2, "second") {
		t.Fatal("a second admin was stored")
	}
	if res := e.post("/admin/github/start", url.Values{"code": {code}}, nil); res.Code != http.StatusConflict || res.named(oauthCookieName) != nil {
		t.Fatalf("a setup code was accepted with an admin present: %d", res.Code)
	}
	if _, err := adminui.IssueSetupCode(t.Context(), e.srv.DB); !errors.Is(err, store.ErrAdminExists) {
		t.Fatalf("a setup code was issued with an admin present: %v", err)
	}
}

func TestOnlyStoredGitHubIdsGetASession(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	for name, who := range map[string]struct {
		id    int64
		login string
	}{"another user": {2000, "mallory"}, "the admin's login on another id": {7, adminLogin}} {
		res := e.complete(e.begin(""), who.id, who.login)
		if res.Code != http.StatusForbidden || res.cookie() != nil || !strings.Contains(res.Body.String(), "not an admin") {
			t.Errorf("%s answered %d", name, res.Code)
		}
	}
	res := e.complete(e.begin(""), adminGitHubID, "renamed")
	if res.Code != http.StatusSeeOther || res.cookie() == nil {
		t.Fatalf("the admin must get in after a rename: %d", res.Code)
	}
	if page := e.get("/admin/invites", res.cookie()); !strings.Contains(page.Body.String(), "<span>renamed ·</span>") {
		t.Fatalf("the session shows %s", page.Body)
	}
	if entries, _ := e.srv.DB.Audit(t.Context(), 1); len(entries) != 1 || entries[0].Admin != "github:1000" || entries[0].Target != "renamed" {
		t.Fatalf("the audit names the admin by id and shows the login as a label: %+v", entries)
	}
}

func TestSignInStateMustBelongToTheBrowserThatStartedIt(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	f, other := e.begin(""), e.begin("")
	callback := e.authorize(f, adminGitHubID, adminLogin)
	for name, cookie := range map[string]*http.Cookie{
		"no cookie":                  nil,
		"a wrong cookie":             {Name: oauthCookieName, Value: ids.Token()},
		"another flow's cookie":      other.cookie,
		"a cookie of the wrong name": {Name: "ostia_admin", Value: f.state},
	} {
		res := e.land(callback, cookie)
		if res.Code != http.StatusBadRequest || res.cookie() != nil || !strings.Contains(res.Body.String(), "did not start in this browser") {
			t.Errorf("%s: %d", name, res.Code)
		}
	}
	if res := e.get("/admin/github/finish?code=x", f.cookie); res.Code != http.StatusBadRequest {
		t.Errorf("a missing state answered %d", res.Code)
	}
	if res := e.land(callback, f.cookie); res.Code != http.StatusSeeOther || res.cookie() == nil {
		t.Fatalf("a refused attempt must not spend the real flow: %d", res.Code)
	}
}

func TestReplayedOrExpiredStateIsRefused(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	f := e.begin("")
	if res := e.complete(f, adminGitHubID, adminLogin); res.Code != http.StatusSeeOther {
		t.Fatalf("%d", res.Code)
	}
	replay := e.authorize(f, adminGitHubID, adminLogin)
	if res := e.land(replay, f.cookie); res.Code != http.StatusBadRequest || res.cookie() != nil || !strings.Contains(res.Body.String(), "already used or has expired") {
		t.Fatalf("a replayed state answered %d", res.Code)
	}

	late := e.begin("")
	cb := e.authorize(late, adminGitHubID, adminLogin)
	e.now = e.now.Add(10*time.Minute + time.Second)
	if res := e.land(cb, late.cookie); res.Code != http.StatusBadRequest || res.cookie() != nil {
		t.Fatalf("an expired state answered %d", res.Code)
	}
}

func TestGitHubDenialAndFailuresGiveNoSession(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	f := e.begin("")
	res := e.land("/admin/github/callback?error=access_denied&state="+f.state, f.cookie)
	if res.Code != http.StatusForbidden || res.cookie() != nil {
		t.Fatalf("a denial answered %d", res.Code)
	}
	f = e.begin("")
	res = e.land("/admin/github/callback?code=not-a-github-code&state="+f.state, f.cookie)
	if res.Code != http.StatusBadGateway || res.cookie() != nil || !strings.Contains(res.Body.String(), "Try again") {
		t.Fatalf("a code GitHub refuses answered %d %s", res.Code, res.Body)
	}
	f = e.begin("")
	cb := e.authorize(f, adminGitHubID, adminLogin)
	e.gh.Server.Close()
	if res := e.land(cb, f.cookie); res.Code != http.StatusBadGateway || res.cookie() != nil {
		t.Fatalf("GitHub being down answered %d", res.Code)
	}
}

func TestCallbackOnlyHandsTheReturnOnToTheFinishRoute(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	f := e.begin("")
	cb := e.authorize(f, adminGitHubID, adminLogin)
	res := e.get(cb+"&evil=1", nil)
	next := res.next()
	if res.Code != http.StatusOK || len(res.Result().Cookies()) != 0 || !strings.HasPrefix(next, "/admin/github/finish?") || strings.Contains(next, "evil") ||
		!strings.Contains(res.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("%d %q %s", res.Code, next, res.Body)
	}
	if res := e.get(next, f.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("the callback must not have spent the flow: %d", res.Code)
	}
	if res := e.get("/admin/github/callback?code="+strings.Repeat("a", 600)+"&state=x", nil); res.Code != http.StatusBadRequest {
		t.Fatalf("an oversized code answered %d", res.Code)
	}
	if res := e.get("/admin/github/callback?state="+strings.Repeat("a", 200), nil); res.Code != http.StatusBadRequest {
		t.Fatalf("an oversized state answered %d", res.Code)
	}
	if res := e.post("/admin/github/callback", url.Values{}, nil); res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST callback answered %d", res.Code)
	}
	if res := e.get("/admin/github/start", nil); res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET start answered %d", res.Code)
	}
}

func TestSetupCodeIsHashedAtRestAndANewOneReplacesTheOld(t *testing.T) {
	d, err := store.Open(t.TempDir()+"/db.sqlite", config.Default().Storage.SQLiteJournal, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	old, err := adminui.IssueSetupCode(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	code, err := adminui.IssueSetupCode(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetupCodeValid(t.Context(), ids.Hash(auth.NormalizeCode(old))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an older code survived: %v", err)
	}
	if _, err := d.ClaimFirstAdmin(t.Context(), []byte(code), 1, "a", ids.Hash("tok"), time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the plain code must not be what is stored: %v", err)
	}
	hint, err := d.ClaimFirstAdmin(t.Context(), ids.Hash(auth.NormalizeCode(code)), 1, "a", ids.Hash("tok"), time.Hour)
	if err != nil || hint != strings.ToUpper(auth.NormalizeCode(code)[:4]) {
		t.Fatalf("%q %v", hint, err)
	}
}

func TestSignInRoutesAreRateLimitedPerAddress(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	for name, do := range map[string]func(ip string) reply{
		"start":    func(ip string) reply { return e.from(ip, "POST", "/admin/github/start", url.Values{}) },
		"callback": func(ip string) reply { return e.from(ip, "GET", "/admin/github/callback?code=x&state=y", nil) },
		"finish":   func(ip string) reply { return e.from(ip, "GET", "/admin/github/finish?code=x&state=y", nil) },
	} {
		limited := false
		for range 40 {
			if res := do("198.51.100.7"); res.Code == http.StatusTooManyRequests {
				limited = res.Header().Get("Retry-After") != ""
				break
			}
		}
		if !limited {
			t.Errorf("%s: repeated requests from one address were never limited", name)
		}
		if res := do("198.51.100.8"); res.Code == http.StatusTooManyRequests {
			t.Errorf("%s: another address must not be affected", name)
		}
	}
}

func TestWrongSetupCodesAreLimitedOverallButAValidCodeGetsIn(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	code := e.setupCode()
	refused := 0
	for i := range 200 {
		if res := e.from(fmt.Sprintf("203.0.113.%d", i+1), "POST", "/admin/github/start", url.Values{"code": {"WRONG"}}); res.Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("a spread-out guessing run was never limited overall")
	}
	res := e.from("203.0.113.250", "POST", "/admin/github/start", url.Values{"code": {"WRONG"}})
	if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After must match the refill of the overall limit: %d %q", res.Code, res.Header().Get("Retry-After"))
	}
	if res := e.from("203.0.113.251", "POST", "/admin/github/start", url.Values{"code": {code}}); res.Code != http.StatusOK || res.named(oauthCookieName) == nil {
		t.Fatalf("a valid code must get in while the overall limit is exhausted: %d", res.Code)
	}
}

func TestRefusedSignInsAreLoggedWithoutSecrets(t *testing.T) {
	var log strings.Builder
	restore := captureLog(&log)
	defer restore()
	e := newAdminEnv(t, nil, Options{})
	e.post("/admin/github/start", url.Values{"code": {"SECRET-GUESS-VALUE-XYZ"}}, nil)
	e.get("/admin/github/finish?code=SECRETGITHUBCODE&state=SECRETSTATE", nil)
	f := e.begin(e.setupCode())
	e.complete(f, 4242, "octocat")
	out := strings.ToLower(log.String())
	if strings.Count(out, "admin sign-in refused") != 2 {
		t.Fatalf("each refusal must be logged: %q", out)
	}
	for _, secret := range []string{"secret-guess", "secretgithubcode", "secretstate", strings.ToLower(f.state), strings.ToLower(testkit.WebClientSecret), "gho_web"} {
		if strings.Contains(out, secret) {
			t.Fatalf("the log contains %q: %s", secret, out)
		}
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
	code := e.setupCode()
	hint := strings.ToUpper(auth.NormalizeCode(code)[:4])
	res := e.complete(e.begin(code), 4242, "octocat")
	page := e.get("/admin/invites", res.cookie())
	s := signedIn{cookie: res.cookie(), csrf: csrfField.FindStringSubmatch(page.Body.String())[1]}
	e.act(s, "/admin/invites", url.Values{"ttl": {"1h"}})
	open, _, _ := e.srv.DB.AdminInvites(t.Context())
	e.act(s, "/admin/invites/revoke", url.Values{"id": {open[0].ID}})
	e.act(s, "/admin/accounts/"+a.ID+"/delete", url.Values{})
	e.act(s, "/admin/logout", url.Values{})
	e.complete(e.begin(""), 4242, "octocat")

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
	who := "github:4242"
	want := []string{
		"cli setup-code " + hint,
		who + " setup octocat",
		who + " invite.create " + open[0].Hint,
		who + " invite.revoke " + open[0].Hint,
		who + " account.delete " + a.ID,
		who + " logout ",
		who + " login octocat",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit\n got %q\nwant %q", got, want)
	}
}

func TestEverySetupRefusalAndTheResetAreAudited(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	e.post("/admin/github/start", url.Values{"code": {"WRONG"}}, nil)
	code := e.setupCode()
	hint := strings.ToUpper(auth.NormalizeCode(code)[:4])
	second := e.begin(code)
	e.complete(e.begin(code), 4242, "octocat")
	e.complete(second, 99, "late")
	e.post("/admin/github/start", url.Values{"code": {code}}, nil)
	e.complete(e.begin(""), 99, "mallory")
	e.land(e.authorize(e.begin(""), 4242, "octocat"), nil)
	e.get("/admin/github/finish?code=x&state=y", nil)
	f := e.begin("")
	e.land("/admin/github/callback?error=access_denied&state="+f.state, f.cookie)
	f = e.begin("")
	e.land("/admin/github/callback?code=bogus&state="+f.state, f.cookie)
	admin, err := OpenAdmin(e.srv.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = admin.ResetAdmins(t.Context())
	_ = admin.Close()
	if err != nil {
		t.Fatal(err)
	}

	entries, _ := e.srv.DB.Audit(t.Context(), 50)
	var got []string
	for i := len(entries) - 1; i >= 0; i-- {
		line := entries[i].Admin + " " + entries[i].Action + " " + entries[i].Target
		if entries[i].Count > 1 {
			line += fmt.Sprintf(" x%d", entries[i].Count)
		}
		got = append(got, line)
	}
	want := []string{
		"anonymous refused setup-code",
		"cli setup-code " + hint,
		"github:4242 setup octocat",
		"anonymous refused admin-exists 99",
		"anonymous refused admin-exists",
		"anonymous refused not-admin 99",
		"anonymous refused state-mismatch x2",
		"anonymous refused github-denied",
		"anonymous refused github-unavailable",
		"cli reset 1 admins, 1 sessions",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit\n got %q\nwant %q", got, want)
	}
}

func TestResetReturnsTheServerToSetup(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	pending := e.begin("")
	admin, err := OpenAdmin(e.srv.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetupCode(t.Context()); err == nil || !strings.Contains(err.Error(), "admin reset") {
		t.Fatalf("setup must refuse while an admin exists and name the way out: %v", err)
	}
	admins, sessions, err := admin.ResetAdmins(t.Context())
	if err != nil || admins != 1 || sessions != 1 {
		t.Fatalf("%d %d %v", admins, sessions, err)
	}
	code, err := admin.SetupCode(t.Context())
	_ = admin.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("a session survived the reset: %d", res.Code)
	}
	if page := e.get("/admin/", nil).Body.String(); !strings.Contains(page, "Set up admin") {
		t.Fatalf("after a reset the page offers setup: %s", page)
	}
	if res := e.complete(pending, adminGitHubID, adminLogin); res.Code == http.StatusSeeOther {
		t.Fatalf("a sign-in started before the reset finished after it: %d", res.Code)
	}
	if res := e.post("/admin/github/start", url.Values{}, nil); res.Code != http.StatusUnauthorized || res.named(oauthCookieName) != nil {
		t.Fatalf("after a reset sign-in needs a setup code: %d", res.Code)
	}
	if res := e.complete(e.begin(code), 5000, "newcomer"); res.Code != http.StatusSeeOther {
		t.Fatalf("setup after a reset: %d", res.Code)
	}
	if e.isAdmin(adminGitHubID, adminLogin) {
		t.Fatal("the old admin id is back")
	}
}

func TestSetupCommandNeedsTheAdminUIOn(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	cfg := e.srv.Cfg
	cfg.Admin.Enabled = false
	admin, err := OpenAdmin(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.SetupCode(t.Context()); err == nil || !strings.Contains(err.Error(), "admin.enabled") {
		t.Fatalf("%v", err)
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

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read, write time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error  { d.read = t; return nil }
func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.write = t; return nil }

func TestAdminRequestsGetTheJSONDeadlines(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	for _, path := range []string{"/admin/", "/admin/assets/admin.css"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "api.test"
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		before := time.Now()
		e.handler.ServeHTTP(w, req)
		for name, got := range map[string]time.Time{"read": w.read, "write": w.write} {
			if got.Before(before.Add(httpx.JSONWait)) || got.After(time.Now().Add(httpx.JSONWait)) {
				t.Errorf("%s: %s deadline %v is not now plus httpx.JSONWait", path, name, got)
			}
		}
	}
}

func TestCheapRefusalsAreCountedNotWrittenOneRowEach(t *testing.T) {
	var log strings.Builder
	restore := captureLog(&log)
	defer restore()
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	for i := range 30 {
		e.from(fmt.Sprintf("198.51.100.%d", i+1), "GET", "/admin/github/finish?code=x&state=unknown"+fmt.Sprint(i), nil)
	}
	f := e.begin("")
	for i := range 10 {
		e.land(e.authorize(f, adminGitHubID, adminLogin), &http.Cookie{Name: oauthCookieName, Value: fmt.Sprint("wrong", i)})
	}
	if strings.Count(log.String(), "reason=state-mismatch") != 40 {
		t.Fatal("every refusal must still be logged")
	}
	entries, _ := e.srv.DB.Audit(t.Context(), 50)
	rows := map[string]int{}
	for _, entry := range entries {
		if entry.Action == "refused" {
			rows[entry.Target] += entry.Count
			if entry.Count < 2 {
				t.Errorf("a counted refusal has its own row: %+v", entry)
			}
		}
	}
	if len(rows) != 1 || rows["state-mismatch"] != 40 {
		t.Fatalf("%v", rows)
	}
	e.now = e.now.Add(2 * time.Minute)
	e.get("/admin/github/finish?code=x&state=again", nil)
	if entries, _ = e.srv.DB.Audit(t.Context(), 50); entries[0].Count != 1 || entries[0].Target != "state-mismatch" {
		t.Fatalf("a later minute starts a new row: %+v", entries[0])
	}
}

func TestTheGitHubTokenIsRevokedEvenWhenTheSignInIsRefusedAndRevokeFailuresDoNotBlock(t *testing.T) {
	var log strings.Builder
	restore := captureLog(&log)
	defer restore()
	e := newAdminEnv(t, nil, Options{})
	e.signIn()
	before := len(e.gh.Revoked)
	if res := e.complete(e.begin(""), 2000, "mallory"); res.Code != http.StatusForbidden {
		t.Fatalf("%d", res.Code)
	}
	if len(e.gh.Revoked) != before+1 {
		t.Fatalf("a refused sign-in left its token alive: %v", e.gh.Revoked)
	}
	e.gh.RevokeStatus = http.StatusInternalServerError
	res := e.complete(e.begin(""), adminGitHubID, adminLogin)
	if res.Code != http.StatusSeeOther || res.cookie() == nil {
		t.Fatalf("a failing revoke must not block the admin: %d", res.Code)
	}
	if !strings.Contains(log.String(), "could not revoke") || strings.Contains(log.String(), "gho_web") {
		t.Fatalf("the failure must be logged without the token: %s", log.String())
	}
}

func TestSessionsDieWithTheirAdminAndNameHimByNumericID(t *testing.T) {
	e := newAdminEnv(t, nil, Options{})
	s := e.signIn()
	admin, err := OpenAdmin(e.srv.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = admin.ResetAdmins(t.Context())
	_ = admin.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res := e.get("/admin/invites", s.cookie); res.Code != http.StatusSeeOther {
		t.Fatalf("a session outlived its admin: %d", res.Code)
	}
	var left int
	for _, entry := range mustAudit(t, e) {
		if strings.HasPrefix(entry.Admin, "github:") && entry.Admin != fmt.Sprintf("github:%d", adminGitHubID) {
			left++
		}
	}
	if left != 0 {
		t.Fatal("the audit must name the admin by numeric id")
	}
}

func mustAudit(t *testing.T, e *adminEnv) []store.AuditEntry {
	t.Helper()
	entries, err := e.srv.DB.Audit(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
