package e2e

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/store"
	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func signedHeaders(id *testkit.Identity, message func(deviceID string, ms int64) []byte, ms int64) map[string]string {
	return map[string]string{
		"X-Device-Timestamp": fmt.Sprint(ms),
		"X-Device-Signature": httpx.EncodeB64(ed25519.Sign(id.Sign, message(id.DeviceID, ms))),
	}
}

func wrapReadFor(slot string) func(string, int64) []byte {
	return func(deviceID string, ms int64) []byte { return auth.WrapReadMessage(deviceID, ms, slot) }
}

func manifestPutFor(ifMatch int64, body []byte) func(string, int64) []byte {
	return func(deviceID string, ms int64) []byte { return auth.ManifestPutMessage(deviceID, ms, ifMatch, body) }
}

func rotateFor(ifMatch int64, body []byte) func(string, int64) []byte {
	return func(deviceID string, ms int64) []byte { return auth.SyncRotateMessage(deviceID, ms, ifMatch, body) }
}

func stolenCopy(e *env, owner *testkit.API) *testkit.API {
	stolen := testkit.NewAPI(e.net, &testkit.Identity{Name: "copy of the owner", DeviceID: owner.ID.DeviceID, AccountID: owner.ID.AccountID})
	stolen.Token = owner.Token
	stolen.Unsigned = true
	return stolen
}

func requireSignature(t *testing.T, api *testkit.API, what, method, path string, body any, headers ...string) {
	t.Helper()
	res := api.Do(t, method, path, body, headers...)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "device-signature-required" {
		t.Errorf("%s without the device key was not refused: %s", what, res)
	}
}

func TestStolenTokenCannotReadWrapsPushManifestsOrReplaceTheKey(t *testing.T) {
	f := newSyncFixture(t, "")
	stolen := stolenCopy(f.env, f.a.API)
	owner := f.a.API

	for _, slot := range []string{"passphrase", "recovery"} {
		requireSignature(t, stolen, "reading the "+slot+" wrap", "GET", "/v1/sync/wraps/"+slot, nil)
		owner.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/"+slot, nil)
	}
	junk := testkit.EncodeB64([]byte("junk"))
	requireSignature(t, stolen, "pushing a manifest", "PUT", "/v1/sync/manifest", map[string]string{"blob": junk}, "If-Match", "1")
	requireSignature(t, stolen, "replacing the key", "POST", "/v1/sync/rotate", map[string]string{"manifest": junk, "passphrase": junk, "recovery": junk}, "If-Match", "1")
	view := owner.Must(t, http.StatusOK, "GET", "/v1/sync/manifest", nil).Map(t)
	if view["version"] != float64(1) || view["keyVersion"] != float64(1) {
		t.Fatalf("a refused request changed the account: %v", view)
	}
}

func TestSignedReadsRejectWrongContextStaleAndReplayedSignatures(t *testing.T) {
	f := newSyncFixture(t, "")
	owner := f.a.API
	stolen := stolenCopy(f.env, owner)
	now := time.Now().UnixMilli()

	read := func(headers map[string]string) testkit.Response {
		t.Helper()
		res, err := stolen.Raw("GET", "/v1/sync/wraps/passphrase", headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	expect := func(what string, res testkit.Response, status int, code string) {
		t.Helper()
		if res.Status != status || (code != "" && res.Map(t)["error"] != code) {
			t.Errorf("%s: want %d %s, got %s", what, status, code, res)
		}
	}

	expect("a signature made for replacing the key", read(signedHeaders(owner.ID, rotateFor(1, []byte("{}")), now)), http.StatusForbidden, "bad-signature")
	expect("a signature made for pushing a manifest", read(signedHeaders(owner.ID, manifestPutFor(0, []byte("{}")), now+1)), http.StatusForbidden, "bad-signature")
	expect("a timestamp ten minutes old", read(signedHeaders(owner.ID, wrapReadFor("passphrase"), now-10*60*1000)), http.StatusForbidden, "stale-signature")
	expect("a timestamp ten minutes ahead", read(signedHeaders(owner.ID, wrapReadFor("passphrase"), now+10*60*1000)), http.StatusForbidden, "stale-signature")

	good := signedHeaders(owner.ID, wrapReadFor("passphrase"), now+2)
	expect("a fresh signature", read(good), http.StatusOK, "")
	expect("the same request replayed", read(good), http.StatusForbidden, "stale-signature")
	older := signedHeaders(owner.ID, wrapReadFor("passphrase"), now+1)
	expect("an older timestamp than the last accepted one", read(older), http.StatusForbidden, "stale-signature")

	other := f.env.device(t, owner, "phone")
	foreign := signedHeaders(other.ID, wrapReadFor("passphrase"), now+3)
	expect("another device's signature on the owner's token", read(foreign), http.StatusForbidden, "bad-signature")
}

func TestManifestPushWithSignatureStillHonoursIfMatch(t *testing.T) {
	f := newSyncFixture(t, "")
	owner := f.a.API
	body := map[string]string{"blob": testkit.EncodeB64([]byte("sealed"))}
	owner.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", body, "If-Match", "1")
	res := owner.Do(t, "PUT", "/v1/sync/manifest", body, "If-Match", "1")
	if res.Status != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match: %s", res)
	}
	res = owner.Do(t, "PUT", "/v1/sync/manifest", body)
	if res.Status != http.StatusPreconditionRequired {
		t.Fatalf("a missing If-Match: %s", res)
	}
}

func TestForgedLeftHandForwardedEntriesDoNotFreshenTheRateLimit(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ClientIPHeader: "X-Forwarded-For", TrustedProxies: []string{"127.0.0.0/8"},
	})
	anon := testkit.NewAPI(testkit.Net{HTTPSAddr: proc.HTTPAddr, APIHost: apiHost, Plain: true}, testkit.NewIdentity("anon"))
	body := anon.ID.Registration()
	body["code"] = "nope"
	limited := 0
	for i := range 30 {
		forged := fmt.Sprintf("10.9.%d.1, 127.0.0.77", i)
		if anon.Do(t, "POST", "/v1/auth/invite", body, "X-Forwarded-For", forged).Status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("entries a client prepends let it pick its own rate limit key")
	}
}

func adminOutput(t *testing.T, e *env, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(serverBinary, append([]string{"admin", "-config", e.proc.ConfigPath}, args...)...).CombinedOutput()
	return string(out), err
}

func TestEverythingTheServerWritesIsOwnerOnly(t *testing.T) {
	f := newSyncFixture(t, "")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	files := 0
	err := filepath.WalkDir(f.env.proc.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %o, group and others must have no access", path, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ostia.sqlite", "ostia.sqlite-wal", "server.key"} {
		if _, err := os.Stat(filepath.Join(f.env.proc.DataDir, name)); err != nil {
			t.Errorf("expected %s in the data directory: %v", name, err)
		}
	}
	if files < 6 {
		t.Fatalf("walked only %d entries", files)
	}
}

func TestAdminInviteRefusesTTLsThatNeverEndOrExceedTheMaximum(t *testing.T) {
	e := newEnv(t, "[auth]\ninvite_ttl = \"48h\"\n")
	for _, ttl := range []string{"0", "0s", "-1h", "49h", "8760h"} {
		if out, err := adminOutput(t, e, "invite", "-ttl", ttl); err == nil {
			t.Errorf("-ttl %s was accepted: %s", ttl, out)
		}
	}
	if out, err := adminOutput(t, e, "invite", "-ttl", "48h"); err != nil {
		t.Fatalf("the maximum itself: %v %s", err, out)
	}
	if out, err := adminOutput(t, e, "invite"); err != nil || !strings.Contains(out, "expires ") {
		t.Fatalf("the default: %v %s", err, out)
	}
}

func TestAdminBackupWritesAnEncryptedRestorableCopyOfTheLiveDatabase(t *testing.T) {
	f := newSyncFixture(t, "")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "ostia.sqlite.age")
	if res, err := adminOutput(t, f.env, "backup", "-recipient", identity.Recipient().String(), "-out", out); err != nil {
		t.Fatalf("backup: %v %s", err, res)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	encrypted, _ := os.ReadFile(out)
	if bytes.HasPrefix(encrypted, []byte("SQLite format 3")) {
		t.Fatal("the backup is plain SQLite")
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(reader)
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	if err := os.WriteFile(restored, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(restored, store.JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts, err := db.Accounts(t.Context())
	if err != nil || len(accounts) != 1 || accounts[0].ID != f.a.API.ID.AccountID {
		t.Fatalf("restored accounts: %+v %v", accounts, err)
	}
	if _, err := db.CurrentManifest(t.Context(), accounts[0].ID); err != nil {
		t.Fatalf("the synced manifest is not in the backup: %v", err)
	}
}

func TestAdminBackupNeedsARecipientAndAFreshOutputPath(t *testing.T) {
	e := newEnv(t, "")
	identity, _ := age.GenerateX25519Identity()
	taken := filepath.Join(t.TempDir(), "taken")
	if err := os.WriteFile(taken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no flags":        {"backup"},
		"no output":       {"backup", "-recipient", identity.Recipient().String()},
		"no recipient":    {"backup", "-out", filepath.Join(t.TempDir(), "b")},
		"bad recipient":   {"backup", "-recipient", "hunter2", "-out", filepath.Join(t.TempDir(), "b")},
		"existing output": {"backup", "-recipient", identity.Recipient().String(), "-out", taken},
	} {
		if out, err := adminOutput(t, e, args...); err == nil {
			t.Errorf("%s was accepted: %s", name, out)
		}
	}
	if kept, _ := os.ReadFile(taken); string(kept) != "x" {
		t.Fatalf("an existing file was overwritten: %q", kept)
	}
}

func TestDeleteJournalModeRunsWithoutAWALFile(t *testing.T) {
	f := newSyncFixture(t, "[storage]\nsqlite_journal = \"delete\"\n")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ostia.sqlite-wal", "ostia.sqlite-shm"} {
		if _, err := os.Stat(filepath.Join(f.env.proc.DataDir, name)); err == nil {
			t.Errorf("%s exists in delete mode", name)
		}
	}
	if out := f.env.proc.Admin(t, "accounts"); !strings.Contains(out, f.a.API.ID.AccountID) {
		t.Fatalf("admin cannot read the database while the server runs: %s", out)
	}
	got, err := f.a.Pull(t)
	if err != nil || !testkit.Equal(got, settings("theme", "dark")) {
		t.Fatalf("pull: %v %v", got, err)
	}
}

func TestSignaturesBindTheSlotTheVersionAndTheBody(t *testing.T) {
	f := newSyncFixture(t, "")
	owner := f.a.API
	stolen := stolenCopy(f.env, owner)
	now := time.Now().UnixMilli()

	read := func(slot string, headers map[string]string) testkit.Response {
		t.Helper()
		res, err := stolen.Raw("GET", "/v1/sync/wraps/"+slot, headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := read("recovery", signedHeaders(owner.ID, wrapReadFor("passphrase"), now)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
		t.Fatalf("a passphrase read signature redirected to the recovery slot: %s", res)
	}
	if res := read("recovery", signedHeaders(owner.ID, wrapReadFor("recovery"), now+1)); res.Status != http.StatusOK {
		t.Fatalf("a signature for the recovery slot: %s", res)
	}

	body := []byte(`{"blob":"` + testkit.EncodeB64([]byte("sealed")) + `"}`)
	put := func(ifMatch string, sent []byte, headers map[string]string) testkit.Response {
		t.Helper()
		headers["If-Match"] = ifMatch
		headers["Content-Type"] = "application/json"
		res, err := stolen.Raw("PUT", "/v1/sync/manifest", headers, bytes.NewReader(sent))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	forged := []byte(`{"blob":"` + testkit.EncodeB64([]byte("junk!!")) + `"}`)
	if res := put("1", forged, signedHeaders(owner.ID, manifestPutFor(1, body), now+2)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
		t.Fatalf("a captured signature carried another body: %s", res)
	}
	if res := put("2", body, signedHeaders(owner.ID, manifestPutFor(1, body), now+3)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
		t.Fatalf("a captured signature carried another If-Match: %s", res)
	}
	if res := put("1", body, signedHeaders(owner.ID, rotateFor(1, body), now+4)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
		t.Fatalf("a key replacement signature pushed a manifest: %s", res)
	}
	if res := put("1", body, signedHeaders(owner.ID, manifestPutFor(1, body), now+5)); res.Status != http.StatusOK {
		t.Fatalf("the exact request the signature covers: %s", res)
	}
}

func TestAdminBackupStreamsToStandardOutputForKubectlExec(t *testing.T) {
	f := newSyncFixture(t, "")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(serverBinary, "admin", "-config", f.env.proc.ConfigPath, "backup", "-recipient", identity.Recipient().String(), "-out", "-")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("backup to stdout: %v\n%s", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("anything on stderr is noise for a pipeline: %q", stderr.String())
	}
	if bytes.HasPrefix(stdout.Bytes(), []byte("SQLite format 3")) {
		t.Fatal("standard output carries plain SQLite")
	}
	reader, err := age.Decrypt(&stdout, identity)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(reader)
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	if err := os.WriteFile(restored, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(restored, store.JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if accounts, err := db.Accounts(t.Context()); err != nil || len(accounts) != 1 {
		t.Fatalf("restored accounts: %+v %v", accounts, err)
	}
	if left, _ := filepath.Glob(filepath.Join(f.env.proc.DataDir, ".backup-scratch-*")); len(left) != 0 {
		t.Fatalf("plaintext scratch left in the data directory: %v", left)
	}
}

func TestManifestPushRefusesMissingOrStaleTimestampsWithoutReadingTheBody(t *testing.T) {
	f := newSyncFixture(t, "")
	owner := f.a.API
	for name, stamp := range map[string]string{
		"no timestamp":     "",
		"stale timestamp":  fmt.Sprint(time.Now().Add(-10 * time.Minute).UnixMilli()),
		"future timestamp": fmt.Sprint(time.Now().Add(10 * time.Minute).UnixMilli()),
	} {
		conn, err := tls.Dial("tcp", f.env.net.HTTPSAddr, &tls.Config{RootCAs: f.env.net.Roots, ServerName: apiHost})
		if err != nil {
			t.Fatal(err)
		}
		request := "PUT /v1/sync/manifest HTTP/1.1\r\nHost: " + apiHost + "\r\nAuthorization: Bearer " + owner.Token +
			"\r\nIf-Match: 1\r\nContent-Type: application/json\r\nContent-Length: 4000000\r\n"
		if stamp != "" {
			request += "X-Device-Timestamp: " + stamp + "\r\nX-Device-Signature: AAAA\r\n"
		}
		_, _ = conn.Write([]byte(request + "\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Errorf("%s: the server waited for a body that never comes: %v", name, err)
			_ = conn.Close()
			continue
		}
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&body)
		want := "stale-signature"
		if stamp == "" {
			want = "device-signature-required"
		}
		if res.StatusCode != http.StatusForbidden || body.Error != want {
			t.Errorf("%s: %d %s, want 403 %s", name, res.StatusCode, body.Error, want)
		}
		_ = conn.Close()
	}
}
