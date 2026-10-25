package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

const artifactHTML = "<!doctype html><title>report</title><p>quarterly numbers: 42</p><script>document.title='ok'</script>"

func ptr[T any](v T) *T { return &v }

func viewsOf(t *testing.T, api *testkit.API, id string) int {
	t.Helper()
	var list struct {
		Shares []struct {
			ID    string `json:"id"`
			Views int    `json:"views"`
		} `json:"shares"`
	}
	api.Must(t, http.StatusOK, "GET", "/v1/shares", nil).JSON(t, &list)
	for _, s := range list.Shares {
		if s.ID == id {
			return s.Views
		}
	}
	t.Fatalf("share %s not listed", id)
	return 0
}

func TestLinkShareIsEncryptedAndOpensWithTheFragmentKey(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})

	if !strings.HasPrefix(sh.URL, "https://"+apiHost+"/s/"+sh.ID) {
		t.Fatalf("each share gets its own subdomain on the share domain: %s", sh.URL)
	}
	blob := e.net.ShareGet(t, sh.ID, "/blob")
	if blob.Status != http.StatusOK || strings.Contains(string(blob.Body), "quarterly numbers") || strings.Contains(string(blob.Body), "<p>") {
		t.Fatalf("the server must only hold ciphertext: %d", blob.Status)
	}
	html, err := e.net.OpenShare(t, sh)
	if err != nil || html != artifactHTML {
		t.Fatalf("open: %q %v", html, err)
	}
	wrongKey := sh
	wrongKey.Key = testkit.RandomBytes(32)
	if _, err := e.net.OpenShare(t, wrongKey); err == nil {
		t.Fatal("a different fragment key decrypted the share")
	}
}

func TestPasswordShareNeedsThePassword(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "password", Password: "correct horse", HTML: artifactHTML})
	meta := e.net.ShareGet(t, sh.ID, "/meta").Map(t)
	if meta["mode"] != "password" || meta["salt"] == "" {
		t.Fatalf("meta: %v", meta)
	}
	if html, err := e.net.OpenShare(t, sh); err != nil || html != artifactHTML {
		t.Fatalf("right password: %q %v", html, err)
	}
	wrong := sh
	wrong.Password = "battery staple"
	if _, err := e.net.OpenShare(t, wrong); err == nil {
		t.Fatal("wrong password opened the share")
	}
	both := owner.PublishHTML(t, testkit.ShareOptions{Mode: "password", Password: "pw", HTML: artifactHTML, WithFragmentKey: true})
	if html, err := e.net.OpenShare(t, both); err != nil || html != artifactHTML {
		t.Fatalf("password plus link key: %q %v", html, err)
	}
	noFragment := both
	noFragment.Key = nil
	if _, err := e.net.OpenShare(t, noFragment); err == nil {
		t.Fatal("the password alone opened a share that also needs the link key")
	}
}

func TestPublicShareIsExplicitAndSandboxed(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "public", HTML: artifactHTML})
	res := e.net.ShareGet(t, sh.ID, "/")
	if res.Status != http.StatusOK || strings.Contains(string(res.Body), artifactHTML) || !strings.Contains(string(res.Body), "/shell.js") {
		t.Fatalf("a public share must be the shell, never the artifact: %s", res)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "allow-same-origin") {
		t.Fatalf("shell CSP %q", csp)
	}
	blob := e.net.ShareGet(t, sh.ID, "/blob")
	if blob.Status != http.StatusOK || string(blob.Body) != artifactHTML {
		t.Fatalf("/blob of a public share: %s", blob)
	}
	if ct := blob.Header.Get("Content-Type"); ct != "application/octet-stream" || !strings.Contains(blob.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("public bytes must not be a document: %q", ct)
	}
	if views := viewsOf(t, owner, sh.ID); views != 0 {
		t.Fatalf("fetching the bytes is not a view: %d", views)
	}
	if res := e.net.SharePost(t, sh.ID, "/view", nil); res.Status != http.StatusNoContent {
		t.Fatalf("/view: %s", res)
	}
	if views := viewsOf(t, owner, sh.ID); views != 1 {
		t.Fatalf("views %d", views)
	}
}

func TestPublicSharesCanBeDisabledByTheOperator(t *testing.T) {
	e := newEnv(t, "[publish]\nallow_public = false\n")
	owner := e.user(t, "desktop")
	res := owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "public", "size": 10})
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "public-disabled" {
		t.Fatalf("%s", res)
	}
	if res := owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "link", "size": 10}); res.Status != http.StatusCreated {
		t.Fatalf("encrypted shares must still work: %s", res)
	}
}

func TestShareHostSendsStrictHeadersAndNoCookies(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	for _, path := range []string{"/", "/meta", "/blob", "/s/-/shell.js", "/s/-/crypto.js", "/s/-/shell.css"} {
		res := e.net.ShareGet(t, sh.ID, path)
		if strings.HasPrefix(path, "/s/-") {
			res = e.net.ShareGet(t, "-", strings.TrimPrefix(path, "/s/-"))
		}
		if res.Status != http.StatusOK {
			t.Fatalf("%s: %s", path, res)
		}
		want := map[string]string{
			"X-Content-Type-Options":     "nosniff",
			"Referrer-Policy":            "no-referrer",
			"Cross-Origin-Opener-Policy": "same-origin",
			"X-Robots-Tag":               "noindex",
		}
		for header, value := range want {
			if got := res.Header.Get(header); got != value {
				t.Errorf("%s %s = %q, want %q", path, header, got, value)
			}
		}
		if res.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s has no Content-Security-Policy", path)
		}
		if res.Header.Get("Set-Cookie") != "" {
			t.Errorf("%s sets a cookie", path)
		}
	}
	shell := e.net.ShareGet(t, sh.ID, "/")
	csp := shell.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "connect-src https://" + apiHost + "/s/;", "script-src https://" + apiHost + "/s/ ", "frame-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("shell CSP lacks %q: %s", directive, csp)
		}
	}
	if strings.Contains(string(shell.Body), "http://") || strings.Contains(string(shell.Body), "https://") {
		t.Error("the shell page references an external resource")
	}
}

func TestViewsAreCountedWithoutLoggingWho(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	e.net.ShareGet(t, sh.ID, "/meta")
	if views := viewsOf(t, owner, sh.ID); views != 0 {
		t.Fatalf("meta is not a view: %d", views)
	}
	for range 3 {
		e.net.ShareGet(t, sh.ID, "/blob")
	}
	if views := viewsOf(t, owner, sh.ID); views != 0 {
		t.Fatalf("blob fetches are not views: %d", views)
	}
	for range 3 {
		e.net.SharePost(t, sh.ID, "/view", nil)
	}
	if views := viewsOf(t, owner, sh.ID); views != 3 {
		t.Fatalf("views %d", views)
	}
	logged := e.proc.Log()
	if strings.Contains(logged, "127.0.0.1:") && strings.Contains(logged, sh.ID) {
		t.Fatalf("share access appears in the server log:\n%s", logged)
	}
}

func TestSharesExpireAndAreSwept(t *testing.T) {
	e := newEnv(t, "[publish]\nmin_expiry = \"1s\"\nsweep_interval = \"300ms\"\n")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML, ExpiresInSeconds: ptr(int64(2))})
	if _, err := e.net.OpenShare(t, sh); err != nil {
		t.Fatalf("share must open before it expires: %v", err)
	}
	time.Sleep(2300 * time.Millisecond)
	if meta := e.net.ShareGet(t, sh.ID, "/meta"); meta.Status != http.StatusGone && meta.Status != http.StatusNotFound {
		t.Fatalf("expired share still served: %s", meta)
	}
	if blob := e.net.ShareGet(t, sh.ID, "/blob"); blob.Status == http.StatusOK {
		t.Fatal("expired share content still served")
	}
	waitUntil(t, "the sweeper removes the share", func() bool {
		var list struct {
			Shares []any `json:"shares"`
		}
		owner.Must(t, http.StatusOK, "GET", "/v1/shares", nil).JSON(t, &list)
		return len(list.Shares) == 0
	})
	if meta := e.net.ShareGet(t, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("swept share: %s", meta)
	}
}

func TestExpiryRulesAreEnforced(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	cases := map[string]struct {
		expires *int64
		want    int
	}{
		"default":   {nil, http.StatusCreated},
		"one day":   {ptr(int64(86400)), http.StatusCreated},
		"never":     {ptr(int64(0)), http.StatusBadRequest},
		"too long":  {ptr(int64(366 * 86400)), http.StatusBadRequest},
		"too short": {ptr(int64(5)), http.StatusBadRequest},
		"negative":  {ptr(int64(-5)), http.StatusBadRequest},
	}
	for name, c := range cases {
		body := map[string]any{"mode": "link", "size": 10}
		if c.expires != nil {
			body["expiresInSeconds"] = *c.expires
		}
		if res := owner.Do(t, "POST", "/v1/shares", body); res.Status != c.want {
			t.Errorf("%s: %s", name, res)
		}
	}
	selfHosted := newEnv(t, "[publish]\nallow_never = true\n")
	user := selfHosted.user(t, "desktop")
	res := user.Must(t, http.StatusCreated, "POST", "/v1/shares", map[string]any{"mode": "link", "size": 10, "expiresInSeconds": 0})
	if res.Map(t)["expiresAt"].(float64) != 0 {
		t.Fatalf("never-expiring share: %s", res)
	}
}

func TestDeleteWithTheTokenTheOwnerOrNotAtAll(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	stranger := e.user(t, "stranger")
	anon := e.anonymous()

	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if res := anon.Do(t, "DELETE", "/v1/shares/"+sh.ID, nil); res.Status != http.StatusNotFound {
		t.Fatalf("anonymous delete: %s", res)
	}
	if res := anon.Do(t, "DELETE", "/v1/shares/"+sh.ID, nil, "X-Delete-Token", "wrong"); res.Status != http.StatusNotFound {
		t.Fatalf("wrong token: %s", res)
	}
	if res := stranger.Do(t, "DELETE", "/v1/shares/"+sh.ID, nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's delete: %s", res)
	}
	if _, err := e.net.OpenShare(t, sh); err != nil {
		t.Fatalf("share lost to refused deletes: %v", err)
	}
	anon.Must(t, http.StatusNoContent, "DELETE", "/v1/shares/"+sh.ID, nil, "X-Delete-Token", sh.DeleteToken)
	if meta := e.net.ShareGet(t, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("deleted share: %s", meta)
	}
	if blob := e.net.ShareGet(t, sh.ID, "/blob"); blob.Status != http.StatusNotFound {
		t.Fatalf("deleted share content: %s", blob)
	}

	second := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	owner.Must(t, http.StatusNoContent, "DELETE", "/v1/shares/"+second.ID, nil)
}

func TestReportPathAndTakedown(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	anon := e.anonymous()

	if res := e.net.SharePost(t, sh.ID, "/report", map[string]string{"reason": "bogus"}); res.Status != http.StatusBadRequest {
		t.Fatalf("unknown reason: %s", res)
	}
	if res := e.net.SharePost(t, sh.ID, "/report", map[string]string{"reason": "malware"}); res.Status != http.StatusNoContent {
		t.Fatalf("report from the shell page: %s", res)
	}
	anon.Must(t, http.StatusNoContent, "POST", "/v1/report/"+sh.ID, map[string]string{"reason": "abuse"})
	if res := anon.Do(t, "POST", "/v1/report/"+strings.Repeat("a", 26), map[string]string{"reason": "abuse"}); res.Status != http.StatusNotFound {
		t.Fatalf("report of an unknown share: %s", res)
	}

	reports := e.proc.Admin(t, "reports")
	if !strings.Contains(reports, sh.ID) || !strings.Contains(reports, "reports=2") {
		t.Fatalf("admin reports:\n%s", reports)
	}
	e.proc.Admin(t, "takedown", sh.ID)
	if meta := e.net.ShareGet(t, sh.ID, "/meta"); meta.Status != http.StatusGone {
		t.Fatalf("taken down share meta: %s", meta)
	}
	if blob := e.net.ShareGet(t, sh.ID, "/blob"); blob.Status != http.StatusGone {
		t.Fatalf("taken down share content: %s", blob)
	}
	if res := anon.Do(t, "POST", "/v1/report/"+sh.ID, map[string]string{"reason": "abuse"}); res.Status != http.StatusNotFound {
		t.Fatalf("report of a removed share: %s", res)
	}
	var list struct {
		Shares []any `json:"shares"`
	}
	owner.Must(t, http.StatusOK, "GET", "/v1/shares", nil).JSON(t, &list)
	if len(list.Shares) != 0 {
		t.Fatalf("taken down share still listed for the owner: %v", list.Shares)
	}
}

func TestRepeatAbuseDisablesPublishing(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	accounts := e.proc.Admin(t, "accounts")
	accountID, _, _ := strings.Cut(accounts, "\t")
	e.proc.Admin(t, "disable-publish", accountID)
	res := owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "link", "size": 10})
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "publish-disabled" {
		t.Fatalf("%s", res)
	}
	e.proc.Admin(t, "enable-publish", accountID)
	owner.Must(t, http.StatusCreated, "POST", "/v1/shares", map[string]any{"mode": "link", "size": 10})
}

func TestShareLimitsAndUploadRules(t *testing.T) {
	e := newEnv(t, "[publish]\nmax_shares_per_account = 2\nmax_file_bytes = 1000\nmax_bytes_per_account = 1500\n")
	owner := e.user(t, "desktop")
	create := func(size int64) testkit.Response {
		return owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "link", "size": size})
	}
	if res := create(0); res.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("zero size: %s", res)
	}
	if res := create(1001); res.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the file limit: %s", res)
	}
	first := create(900)
	if first.Status != http.StatusCreated {
		t.Fatalf("%s", first)
	}
	if res := create(900); res.Status != http.StatusInsufficientStorage {
		t.Fatalf("over the byte quota: %s", res)
	}
	second := create(100)
	if second.Status != http.StatusCreated {
		t.Fatalf("%s", second)
	}
	if res := create(1); res.Status != http.StatusInsufficientStorage {
		t.Fatalf("over the share count: %s", res)
	}

	id := first.Map(t)["id"].(string)
	if res := owner.UploadShare(t, id, make([]byte, 899)); res.Status != http.StatusBadRequest {
		t.Fatalf("short body: %s", res)
	}
	if res := owner.UploadShare(t, id, make([]byte, 901)); res.Status != http.StatusBadRequest {
		t.Fatalf("long body: %s", res)
	}
	if res := owner.UploadShare(t, id, make([]byte, 900)); res.Status != http.StatusNoContent {
		t.Fatalf("exact body: %s", res)
	}
	if res := owner.UploadShare(t, id, make([]byte, 900)); res.Status != http.StatusConflict {
		t.Fatalf("second upload: %s", res)
	}
	stranger := e.user(t, "stranger")
	other := second.Map(t)["id"].(string)
	if res := stranger.UploadShare(t, other, make([]byte, 100)); res.Status != http.StatusNotFound {
		t.Fatalf("another account's upload: %s", res)
	}
	if meta := e.net.ShareGet(t, other, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("a share that was never uploaded must not be served: %s", meta)
	}
}

func TestShareRoutesAreStrictAndUnknownIDsRefused(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	a := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	b := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if a.ID == b.ID || a.URL == b.URL || strings.Split(a.URL, "/")[2] != apiHost || strings.Split(b.URL, "/")[2] != apiHost {
		t.Fatalf("shares are paths of the API host: %s %s", a.URL, b.URL)
	}
	if res := e.net.ShareGet(t, strings.Repeat("a", 26), "/"); res.Status != http.StatusOK {
		t.Fatalf("an unknown share still gets the shell, which reports it missing: %s", res)
	}
	if meta := e.net.ShareGet(t, strings.Repeat("a", 26), "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("unknown share meta: %s", meta)
	}
	if res := e.net.ShareGet(t, "not-a-share-id", "/"); res.Status != http.StatusNotFound {
		t.Fatalf("a path that is not a share id: %s", res)
	}
	if res := e.net.ShareGet(t, a.ID, "/v1/shares"); res.Status != http.StatusNotFound {
		t.Fatalf("the API must not be reachable under a share: %s", res)
	}
	if res := e.net.ShareGet(t, a.ID, "/../../etc/passwd"); res.Status != http.StatusNotFound && res.Status != http.StatusMovedPermanently {
		t.Fatalf("traversal: %s", res)
	}
	api := e.anonymous()
	res, err := api.Raw("GET", "/v1/info", map[string]string{"Host": "evil.example"}, nil)
	if err != nil || res.Status != http.StatusNotFound {
		t.Fatalf("unknown host header: %v %s", err, res)
	}
}

func TestPublishModuleCanBeSwitchedOff(t *testing.T) {
	e := newEnvModules(t, "relay = true\npublish = false\nsync = true\npush = false\n", "")
	owner := e.user(t, "desktop")
	if res := owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "link", "size": 10}); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("publish route exists with the module off: %s", res)
	}
}

func TestDeleteAccountRemovesItsShares(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	e.proc.Admin(t, "delete-account", owner.ID.AccountID)
	if meta := e.net.ShareGet(t, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("share of a deleted account: %s", meta)
	}
	if res := owner.Do(t, "GET", "/v1/shares", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("session of a deleted account: %s", res)
	}
}

func TestPublishRoutesRequireASession(t *testing.T) {
	e := newEnv(t, "")
	anon := e.anonymous()
	for _, route := range [][2]string{{"POST", "/v1/shares"}, {"GET", "/v1/shares"}, {"PUT", "/v1/shares/abc/blob"}} {
		if res := anon.Do(t, route[0], route[1], nil); res.Status != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %s", route[0], route[1], res)
		}
	}
}

func TestSharesOnTheAPIOriginStillSandboxEveryArtifact(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	n := e.net

	hostile := "<script>document.cookie='__Host-ostia_admin=x'; fetch('/admin/')</script>"
	public := owner.PublishHTML(t, testkit.ShareOptions{Mode: "public", HTML: hostile})
	if public.URL != "https://"+apiHost+"/s/"+public.ID {
		t.Fatalf("share url %s", public.URL)
	}
	for _, method := range []string{"GET", "HEAD"} {
		req, err := http.NewRequest(method, n.URL("/s/"+public.ID), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", "__Host-ostia_admin=a-session")
		res, err := n.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		csp := res.Header.Get("Content-Security-Policy")
		if res.StatusCode != http.StatusOK || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-eval") {
			t.Fatalf("%s public share: %d CSP %q", method, res.StatusCode, csp)
		}
		if res.Header.Get("Cross-Origin-Opener-Policy") != "same-origin" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: COOP %q nosniff %q", method, res.Header.Get("Cross-Origin-Opener-Policy"), res.Header.Get("X-Content-Type-Options"))
		}
		if len(res.Cookies()) != 0 {
			t.Fatalf("%s: a share route set a cookie", method)
		}
	}
	withCookie := n.ShareGet(t, public.ID, "/meta", "Cookie", "__Host-ostia_admin=a-session")
	without := n.ShareGet(t, public.ID, "/meta")
	if fmt.Sprint(withCookie.Map(t)) != fmt.Sprint(without.Map(t)) || withCookie.Header.Get("Set-Cookie") != "" {
		t.Fatal("a share route must not read or set the admin cookie")
	}

	encrypted := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: hostile})
	responses := map[string]testkit.Response{}
	for _, path := range []string{"/", "/meta", "/blob"} {
		responses[path] = n.ShareGet(t, encrypted.ID, path)
	}
	for _, path := range []string{"/shell.js", "/crypto.js", "/shell.css"} {
		responses["/s/-"+path] = n.ShareGet(t, "-", path)
	}
	for path, res := range responses {
		csp := res.Header.Get("Content-Security-Policy")
		if res.Status != http.StatusOK || csp == "" || res.Header.Get("Set-Cookie") != "" || strings.Contains(csp, "allow-same-origin") {
			t.Fatalf("%s: %d CSP %q Set-Cookie %q", path, res.Status, csp, res.Header.Get("Set-Cookie"))
		}
	}
	shell := n.ShareGet(t, "-", "/shell.js")
	if !strings.Contains(string(shell.Body), "sandbox: 'allow-scripts'") || strings.Contains(string(shell.Body), "allow-same-origin") {
		t.Fatal("the shell must frame the artifact with sandbox=allow-scripts and no allow-same-origin")
	}
	if blob := n.ShareGet(t, encrypted.ID, "/blob"); strings.Contains(string(blob.Body), "document.cookie") {
		t.Fatal("an encrypted share must not be served as readable bytes")
	}
	if res := n.ShareGet(t, public.ID, "/blob"); res.Status != http.StatusOK || res.Header.Get("Content-Type") != "application/octet-stream" || res.Header.Get("Content-Disposition") != "attachment" {
		t.Fatalf("a public share's bytes are data, not a document: %s", res)
	}
	if res := n.ShareGet(t, "not-a-share-id", "/"); res.Status != http.StatusNotFound || res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("an invalid label must still get the common headers: %s", res)
	}
	for _, path := range []string{"/admin/", "/admin/invites", "/v1/shares"} {
		if res := n.ShareGet(t, public.ID, path); res.Status != http.StatusNotFound {
			t.Fatalf("%s under a share must not exist: %s", path, res)
		}
	}
}

func TestShareWarningIsAServerSettingThatNoShareCanChange(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  bool
	}{{"", true}, {"[publish]\nshare_warning = true\n", true}, {"[publish]\nshare_warning = false\n", false}} {
		e := newEnv(t, tc.extra)
		owner := e.user(t, "desktop")
		if res := owner.Do(t, "POST", "/v1/shares", map[string]any{"mode": "public", "size": 10, "warning": false, "showWarning": false}); res.Status != http.StatusCreated {
			t.Fatalf("an uploader's warning field must be ignored, not break the request: %s", res)
		}
		sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "public", HTML: artifactHTML})
		for _, path := range []string{"/meta", "/meta?warning=false"} {
			res := e.net.ShareGet(t, sh.ID, path, "X-Warning", "off", "Cookie", "warning=off")
			if got, ok := res.Map(t)["warning"].(bool); res.Status != http.StatusOK || !ok || got != tc.want {
				t.Fatalf("share_warning %v, %s: %s", tc.want, path, res)
			}
		}
		if pp := e.net.ShareGet(t, sh.ID, "/").Header.Get("Permissions-Policy"); !strings.Contains(pp, "fullscreen=()") {
			t.Fatalf("Permissions-Policy %q", pp)
		}
		shell := e.net.ShareGet(t, sh.ID, "/")
		if !strings.Contains(shell.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || strings.Contains(string(shell.Body), artifactHTML) {
			t.Fatalf("the shell stays whatever the setting: %s", shell)
		}
	}
}

func TestShareHostNeverRedirectsToACallerSuppliedURL(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "public", HTML: artifactHTML})
	for _, path := range []string{"//evil.example/", "/%2f%2fevil.example/", "/../evil.example", "/?next=https://evil.example", "/blob?url=https://evil.example", "/meta?redirect=//evil.example", "/report?to=https://evil.example"} {
		res := e.net.ShareGet(t, sh.ID, path)
		if loc := res.Header.Get("Location"); loc != "" || res.Status >= 300 && res.Status < 400 {
			t.Fatalf("%s: status %d Location %q", path, res.Status, loc)
		}
	}
}

func TestTopLevelNavigationToShareDataIsRefused(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	for _, mode := range []string{"public", "link"} {
		sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: mode, HTML: artifactHTML})
		for _, path := range []string{"/blob", "/meta"} {
			for _, headers := range [][]string{{"Sec-Fetch-Mode", "navigate"}, {"Sec-Fetch-Dest", "document"}} {
				res := e.net.ShareGet(t, sh.ID, path, headers...)
				if res.Status != http.StatusNotFound || strings.Contains(string(res.Body), "Quarterly") || strings.Contains(string(res.Body), artifactHTML) {
					t.Fatalf("%s %s %v: %s", mode, path, headers, res)
				}
			}
			if res := e.net.ShareGet(t, sh.ID, path, "Sec-Fetch-Mode", "same-origin", "Sec-Fetch-Dest", "empty"); res.Status != http.StatusOK {
				t.Fatalf("%s %s from the shell: %s", mode, path, res)
			}
		}
		if res := e.net.SharePost(t, sh.ID, "/view", nil); res.Status != http.StatusNoContent {
			t.Fatalf("/view: %s", res)
		}
	}
	if res := e.net.SharePost(t, "nosuchshare", "/view", nil); res.Status != http.StatusNotFound {
		t.Fatalf("/view of an unknown share: %s", res)
	}
}
