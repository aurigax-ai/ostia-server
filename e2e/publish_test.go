package e2e

import (
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

	if !strings.HasPrefix(sh.URL, "https://"+sh.ID+"."+shareHost+"/") {
		t.Fatalf("each share gets its own subdomain on the share domain: %s", sh.URL)
	}
	blob := e.net.ShareGet(t, shareHost, sh.ID, "/blob")
	if blob.Status != http.StatusOK || strings.Contains(string(blob.Body), "quarterly numbers") || strings.Contains(string(blob.Body), "<p>") {
		t.Fatalf("the server must only hold ciphertext: %d", blob.Status)
	}
	html, err := e.net.OpenShare(t, shareHost, sh)
	if err != nil || html != artifactHTML {
		t.Fatalf("open: %q %v", html, err)
	}
	wrongKey := sh
	wrongKey.Key = testkit.RandomBytes(32)
	if _, err := e.net.OpenShare(t, shareHost, wrongKey); err == nil {
		t.Fatal("a different fragment key decrypted the share")
	}
}

func TestPasswordShareNeedsThePassword(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "password", Password: "correct horse", HTML: artifactHTML})
	meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta").Map(t)
	if meta["mode"] != "password" || meta["salt"] == "" {
		t.Fatalf("meta: %v", meta)
	}
	if html, err := e.net.OpenShare(t, shareHost, sh); err != nil || html != artifactHTML {
		t.Fatalf("right password: %q %v", html, err)
	}
	wrong := sh
	wrong.Password = "battery staple"
	if _, err := e.net.OpenShare(t, shareHost, wrong); err == nil {
		t.Fatal("wrong password opened the share")
	}
	both := owner.PublishHTML(t, testkit.ShareOptions{Mode: "password", Password: "pw", HTML: artifactHTML, WithFragmentKey: true})
	if html, err := e.net.OpenShare(t, shareHost, both); err != nil || html != artifactHTML {
		t.Fatalf("password plus link key: %q %v", html, err)
	}
	noFragment := both
	noFragment.Key = nil
	if _, err := e.net.OpenShare(t, shareHost, noFragment); err == nil {
		t.Fatal("the password alone opened a share that also needs the link key")
	}
}

func TestPublicShareIsExplicitAndSandboxed(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "public", HTML: artifactHTML})
	res := e.net.ShareGet(t, shareHost, sh.ID, "/")
	if res.Status != http.StatusOK || string(res.Body) != artifactHTML {
		t.Fatalf("public share: %s", res)
	}
	if csp := res.Header.Get("Content-Security-Policy"); csp != "sandbox allow-scripts" {
		t.Fatalf("public documents must run in an opaque origin, got CSP %q", csp)
	}
	if res := e.net.ShareGet(t, shareHost, sh.ID, "/blob"); res.Status != http.StatusNotFound {
		t.Fatalf("/blob of a public share: %s", res)
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
	for _, path := range []string{"/", "/meta", "/blob", "/shell.js", "/crypto.js", "/shell.css"} {
		res := e.net.ShareGet(t, shareHost, sh.ID, path)
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
	shell := e.net.ShareGet(t, shareHost, sh.ID, "/")
	csp := shell.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "connect-src 'self'", "frame-src blob:", "frame-ancestors 'none'", "base-uri 'none'"} {
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
	e.net.ShareGet(t, shareHost, sh.ID, "/meta")
	if views := viewsOf(t, owner, sh.ID); views != 0 {
		t.Fatalf("meta is not a view: %d", views)
	}
	for range 3 {
		e.net.ShareGet(t, shareHost, sh.ID, "/blob")
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
	if _, err := e.net.OpenShare(t, shareHost, sh); err != nil {
		t.Fatalf("share must open before it expires: %v", err)
	}
	time.Sleep(2300 * time.Millisecond)
	if meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta"); meta.Status != http.StatusGone && meta.Status != http.StatusNotFound {
		t.Fatalf("expired share still served: %s", meta)
	}
	if blob := e.net.ShareGet(t, shareHost, sh.ID, "/blob"); blob.Status == http.StatusOK {
		t.Fatal("expired share content still served")
	}
	waitUntil(t, "the sweeper removes the share", func() bool {
		var list struct {
			Shares []any `json:"shares"`
		}
		owner.Must(t, http.StatusOK, "GET", "/v1/shares", nil).JSON(t, &list)
		return len(list.Shares) == 0
	})
	if meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
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
	if _, err := e.net.OpenShare(t, shareHost, sh); err != nil {
		t.Fatalf("share lost to refused deletes: %v", err)
	}
	anon.Must(t, http.StatusNoContent, "DELETE", "/v1/shares/"+sh.ID, nil, "X-Delete-Token", sh.DeleteToken)
	if meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("deleted share: %s", meta)
	}
	if blob := e.net.ShareGet(t, shareHost, sh.ID, "/blob"); blob.Status != http.StatusNotFound {
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

	if res := e.net.SharePost(t, shareHost, sh.ID, "/report", map[string]string{"reason": "bogus"}); res.Status != http.StatusBadRequest {
		t.Fatalf("unknown reason: %s", res)
	}
	if res := e.net.SharePost(t, shareHost, sh.ID, "/report", map[string]string{"reason": "malware"}); res.Status != http.StatusNoContent {
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
	if meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta"); meta.Status != http.StatusGone {
		t.Fatalf("taken down share meta: %s", meta)
	}
	if blob := e.net.ShareGet(t, shareHost, sh.ID, "/blob"); blob.Status != http.StatusGone {
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
	if meta := e.net.ShareGet(t, shareHost, other, "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("a share that was never uploaded must not be served: %s", meta)
	}
}

func TestShareHostsAreIsolatedAndUnknownHostsRefused(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "desktop")
	a := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	b := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if a.ID == b.ID || strings.Split(a.URL, "/")[2] == strings.Split(b.URL, "/")[2] {
		t.Fatal("shares must not share an origin")
	}
	if res := e.net.ShareGet(t, shareHost, strings.Repeat("a", 26), "/"); res.Status != http.StatusOK {
		t.Fatalf("an unknown share still gets the shell, which reports it missing: %s", res)
	}
	if meta := e.net.ShareGet(t, shareHost, strings.Repeat("a", 26), "/meta"); meta.Status != http.StatusNotFound {
		t.Fatalf("unknown share meta: %s", meta)
	}
	if res := e.net.ShareGet(t, shareHost, "not-a-share-id", "/"); res.Status != http.StatusNotFound {
		t.Fatalf("host that is not a share id: %s", res)
	}
	if res := e.net.ShareGet(t, shareHost, a.ID, "/v1/shares"); res.Status != http.StatusNotFound {
		t.Fatalf("the API must not be reachable on a share host: %s", res)
	}
	if res := e.net.ShareGet(t, shareHost, a.ID, "/../../etc/passwd"); res.Status != http.StatusNotFound && res.Status != http.StatusMovedPermanently {
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
	owner.Must(t, http.StatusNoContent, "DELETE", "/v1/account", nil)
	if meta := e.net.ShareGet(t, shareHost, sh.ID, "/meta"); meta.Status != http.StatusNotFound {
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
